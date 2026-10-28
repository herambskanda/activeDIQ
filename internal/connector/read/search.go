package read

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	maxSearchRoots = 64
	searchBatch    = 100
)

// SearchSource is what ScopedSearch needs on top of Source. ADSource implements it; a Source that
// does not makes ScopedSearch fail with a refusal rather than panic.
type SearchSource interface {
	Source
	// FilterSchema is the allowlist every wire filter is validated against.
	FilterSchema() *ldapfilter.Schema
	// ScopedSearch is ad.Session.ScopedSearch: paged, de-duplicated, never leaves the roots.
	ScopedSearch(ctx context.Context, req ad.ScopedRequest, fn func(*ad.Entry) error) (ad.ScopedResult, error)
}

// SearchSender is the sending side of the ScopedSearch stream.
type SearchSender interface {
	Send(*connectorv1.ScopedSearchResponse) error
}

// ScopedSearch implements the ScopedSearch RPC. The filter arrives as a typed tree and is validated
// against the schema here (a compromised server is in the threat model, TM-TB6-T4); the text sent
// to the DC is rendered by ldapfilter, never assembled from request strings. The stream ends with
// SearchCompleted only when every root was searched; any other end is an incomplete result.
func (h *Handler) ScopedSearch(ctx context.Context, req *connectorv1.ScopedSearchRequest, out SearchSender) error {
	ss, ok := h.src.(SearchSource)
	if !ok {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "search not supported by this source")
	}
	if req.GetConnection().GetConnectionId() == "" || req.GetConnection().GetDirectoryIdentity() == nil {
		return invalid("connection")
	}
	if !proto.Equal(req.GetConnection().GetDirectoryIdentity(), h.src.Identity()) {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "directory identity mismatch")
	}
	roots := req.GetRoots()
	if len(roots) == 0 || len(roots) > maxSearchRoots {
		return invalid("roots")
	}
	refs := make([]dn.ObjectRef, 0, len(roots))
	for _, r := range roots {
		g, err := write.GUIDFromWire(r.GetGuid())
		if err != nil {
			return invalid("roots")
		}
		refs = append(refs, dn.GUIDRef(g))
	}
	var depth ad.Scope
	switch req.GetDepth() {
	case connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE:
		depth = ad.ScopeSubtree
	case connectorv1.SearchDepth_SEARCH_DEPTH_ONE_LEVEL:
		depth = ad.ScopeOneLevel
	default:
		return invalid("depth")
	}
	attrs := req.GetAttributes()
	if len(attrs) == 0 || len(attrs) > maxAttributes {
		return invalid("attributes")
	}
	canon := make([]string, 0, len(attrs))
	for _, a := range attrs {
		c, err := h.src.CanonicalAttr(a)
		if err != nil {
			return mapAD(err, nil)
		}
		if strings.EqualFold(c, "nTSecurityDescriptor") {
			return refuse(connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "attribute not allowed")
		}
		canon = append(canon, c)
	}
	// nil Caller: a filter naming a DN is refused (the search by name never needs one).
	flt, err := ldapfilter.ParseFilterAST(req.GetFilter(), ss.FilterSchema(), nil, ldapfilter.Limits{})
	if err != nil {
		return invalid("filter")
	}
	var pin *connectorv1.Guid
	if sel := req.GetDc(); sel != nil && sel.PinnedDsaGuid != nil {
		pin = sel.PinnedDsaGuid
		if _, err := write.GUIDFromWire(pin); err != nil {
			return invalid("dc.pinned_dsa_guid")
		}
	}
	before, err := h.bound(ctx, pin)
	if err != nil {
		return err
	}

	var batch []*connectorv1.DirectoryEntry
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		m := &connectorv1.ScopedSearchResponse{Event: &connectorv1.ScopedSearchResponse_Batch{
			Batch: &connectorv1.SearchBatch{Entries: batch, Observed: &connectorv1.Observation{Dc: before, ReceivedAt: timestamppb.New(h.now())}}}}
		batch = nil
		return out.Send(m)
	}
	_, err = ss.ScopedSearch(ctx, ad.ScopedRequest{Roots: refs, Depth: depth, Filter: flt, Attributes: canon, PageSize: req.GetPageSize()},
		func(e *ad.Entry) error {
			id, err := e.GUID()
			if err != nil {
				return err
			}
			entry, _, err := h.build(e, id, nil, canon)
			if err != nil {
				return err
			}
			batch = append(batch, entry)
			if len(batch) >= searchBatch {
				return flush()
			}
			return nil
		})
	if err != nil {
		var rf *write.Refusal
		if errors.As(err, &rf) {
			return err
		}
		if ad.CodeOf(err) == ad.CodeDelegationRootGone {
			return refuse(connectorv1.ErrorCode_ERROR_CODE_DELEGATION_ROOT_GONE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "search root no longer exists")
		}
		return mapAD(err, before)
	}
	// The DC that answered the last page must be the DC that answered the first.
	after, err := h.bound(ctx, pin)
	if err != nil {
		return err
	}
	if !proto.Equal(before.GetDsaGuid(), after.GetDsaGuid()) {
		return pinRefusal()
	}
	if err := flush(); err != nil {
		return err
	}
	return out.Send(&connectorv1.ScopedSearchResponse{Event: &connectorv1.ScopedSearchResponse_Completed{
		Completed: &connectorv1.SearchCompleted{Observed: &connectorv1.Observation{Dc: after, ReceivedAt: timestamppb.New(h.now())}}}})
}

// ScopedSearch implements connectorv1.ConnectorServer.
func (s *Server) ScopedSearch(req *connectorv1.ScopedSearchRequest, st grpc.ServerStreamingServer[connectorv1.ScopedSearchResponse]) error {
	return s.h.ScopedSearch(st.Context(), req, st)
}
