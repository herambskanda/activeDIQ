package read

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	maxRoots = 64
	// batchEntries and batchBytes bound one SearchBatch well under any frame limit.
	batchEntries = 200
	batchBytes   = 256 << 10
)

// SearchSender is the sending side of the ScopedSearch stream.
type SearchSender interface {
	Send(*connectorv1.ScopedSearchResponse) error
}

func invalidSearch(field string) error {
	r := write.NewRefusal(connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "invalid request")
	r.Err.Details = &connectorv1.ConnectorError_RejectedInput{RejectedInput: &connectorv1.RejectedInputDetails{RuleId: "InvalidScopedSearchRequest", Field: field}}
	return r
}

// ScopedSearch implements the ScopedSearch RPC: one search per delegation root on the bound DC,
// streamed in bounded batches, never buffered. The stream is complete only if it ends with
// SearchCompleted. parent_guid is set on every entry that has a parent (connector-contract §5.1): the
// connector resolves parents after each page, outside the session lock, with one read per distinct
// parent DN, and the value equals Read's. A naming-context head has none.
func (h *Handler) ScopedSearch(ctx context.Context, req *connectorv1.ScopedSearchRequest, out SearchSender) error {
	srch, ok := h.src.(Searcher)
	if !ok {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "search not supported")
	}
	if req.GetConnection().GetConnectionId() == "" || req.GetConnection().GetDirectoryIdentity() == nil {
		return invalidSearch("connection")
	}
	if !proto.Equal(req.GetConnection().GetDirectoryIdentity(), h.src.Identity()) {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "directory identity mismatch")
	}
	if n := len(req.GetRoots()); n == 0 || n > maxRoots {
		return invalidSearch("roots")
	}
	roots := make([]dn.ObjectRef, 0, len(req.GetRoots()))
	for _, r := range req.GetRoots() {
		g, err := write.GUIDFromWire(r.GetGuid())
		if err != nil {
			return invalidSearch("roots.guid")
		}
		roots = append(roots, dn.GUIDRef(g))
	}
	var depth ad.Scope
	switch req.GetDepth() {
	case connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE:
		depth = ad.ScopeSubtree
	case connectorv1.SearchDepth_SEARCH_DEPTH_ONE_LEVEL:
		depth = ad.ScopeOneLevel
	default:
		return invalidSearch("depth")
	}
	if req.GetFilter() == nil {
		return invalidSearch("filter")
	}
	attrs := req.GetAttributes()
	if len(attrs) == 0 || len(attrs) > maxAttributes {
		return invalidSearch("attributes")
	}
	canon := make([]string, 0, len(attrs))
	for _, a := range attrs {
		c, err := h.src.CanonicalAttr(a)
		if err != nil {
			return mapAD(err, nil)
		}
		if strings.EqualFold(c, "nTSecurityDescriptor") { // held for T-0118
			return refuse(connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "attribute not allowed")
		}
		canon = append(canon, c)
	}
	var pin *connectorv1.Guid
	if sel := req.GetDc(); sel != nil && sel.PinnedDsaGuid != nil {
		pin = sel.PinnedDsaGuid
		if _, err := write.GUIDFromWire(pin); err != nil {
			return invalidSearch("dc.pinned_dsa_guid")
		}
	}
	flt, err := srch.ParseFilter(req.GetFilter())
	if err != nil {
		r := write.NewRefusal(connectorv1.ErrorCode_ERROR_CODE_FILTER_REJECTED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "filter rejected")
		r.Err.Details = &connectorv1.ConnectorError_RejectedInput{RejectedInput: &connectorv1.RejectedInputDetails{RuleId: ldapfilter.Code(err), Field: "filter"}}
		return r
	}
	before, err := h.bound(ctx, pin)
	if err != nil {
		return err
	}
	obs := func() *connectorv1.Observation {
		return &connectorv1.Observation{Dc: before, ReceivedAt: timestamppb.New(h.now())}
	}

	var batch []*connectorv1.DirectoryEntry
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		m := &connectorv1.ScopedSearchResponse{Event: &connectorv1.ScopedSearchResponse_Batch{
			Batch: &connectorv1.SearchBatch{Entries: batch, Observed: obs()}}}
		batch, size = nil, 0
		return out.Send(m)
	}
	res, err := srch.ScopedSearch(ctx, ad.ScopedRequest{Roots: roots, Depth: depth, Filter: flt, Attributes: canon,
		PageSize: req.GetPageSize(), ResolveParents: true}, func(e *ad.Entry) error {
		id, err := e.GUID()
		if err != nil {
			return err
		}
		// A search never follows ranges: the tails build returns are dropped, the head says complete = false.
		pg, has, resolved := e.Parent()
		if !resolved { // "no parent" is an authoritative claim: an unresolved entry is a failure
			return errUndecodable
		}
		var parent *connectorv1.Guid
		if has {
			parent = write.GUIDToWire(pg)
		}
		entry, _, err := h.build(e, id, parent, canon)
		if err != nil {
			return errUndecodable
		}
		batch = append(batch, entry)
		size += proto.Size(entry)
		if len(batch) >= batchEntries || size >= batchBytes {
			return flush()
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errUndecodable) {
			return refuse(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "attribute could not be decoded")
		}
		if ad.CodeOf(err) == ad.CodeDelegationRootGone {
			return refuse(connectorv1.ErrorCode_ERROR_CODE_DELEGATION_ROOT_GONE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "delegation root no longer exists")
		}
		if ctx.Err() != nil {
			return err
		}
		return mapAD(err, before)
	}
	if err := flush(); err != nil {
		return err
	}
	if res.Unreadable > 0 {
		// The completed event cannot carry the count (no proto field yet): the connector logs it, so a
		// pass that withheld entries is never silent. Count only, no directory value.
		h.log.Warn("connector: scoped search withheld unreadable entries", "withheld", res.Unreadable, "returned", res.Returned)
	}
	after, err := h.bound(ctx, pin)
	if err != nil {
		return err
	}
	if !proto.Equal(before.GetDsaGuid(), after.GetDsaGuid()) {
		return pinRefusal()
	}
	return out.Send(&connectorv1.ScopedSearchResponse{Event: &connectorv1.ScopedSearchResponse_Completed{
		Completed: &connectorv1.SearchCompleted{Observed: obs()}}})
}

var errUndecodable = errors.New("read: undecodable attribute")
