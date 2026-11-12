package read

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/wirevalue"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	// rangeWindow is the size of one ValueChunk, the Windows default MaxValRange.
	rangeWindow = 1500
	// maxAttributes bounds one request (the contract asks for explicit names; this is a sanity cap).
	maxAttributes = 64
)

// Source is what the handler needs from one AD directory binding. Every method works on the one
// session, hence one DC.
type Source interface {
	Identity() *connectorv1.DirectoryIdentity
	// BoundDC reads the identity of the DC the session is bound to, live.
	BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error)
	// Read reads the object with every range followed (ad.Session.Read semantics).
	Read(ctx context.Context, id guid.GUID, attrs []string, maxValues int) (*ad.Entry, error)
	// Parent returns the objectGUID of the entry's parent; ok is false only for a naming-context head.
	// A parent that cannot be read or decoded is an error: "no parent" is an authoritative claim.
	// The entry carries instanceType (the handler asks for it).
	Parent(ctx context.Context, e *ad.Entry) (g guid.GUID, ok bool, err error)
	// Syntax is the value syntax of an attribute.
	Syntax(name string) (ldapfilter.Syntax, bool)
	// CanonicalAttr resolves a requested name (ldapDisplayName in any case, or the schema's numeric
	// OID). An OID returns the ldapDisplayName; a descr returns in the case typed, so compare
	// case-insensitively. An attribute outside the schema is an error.
	CanonicalAttr(name string) (string, error)
	// Classify is the connector classifier's verdict on the same session.
	Classify(ctx context.Context, id guid.GUID) (write.Verdict, error)
}

// Handler serves Read.
type Handler struct {
	src Source
	now func() time.Time
}

// New returns the handler for one source.
func New(src Source) (*Handler, error) {
	if src == nil {
		return nil, errors.New("read: a source is required")
	}
	return &Handler{src: src, now: time.Now}, nil
}

// Sender is the sending side of the Read stream (grpc.ServerStreamingServer satisfies it).
type Sender interface {
	Send(*connectorv1.ReadResponse) error
}

// Read implements the Read RPC. Messages are sent only after the read and, when asked for, the
// verdict have succeeded on the pinned DC, so a failed call never leaves a partial stream that
// looks like an object.
func (h *Handler) Read(ctx context.Context, req *connectorv1.ReadRequest, out Sender) error {
	if req.GetConnection().GetConnectionId() == "" || req.GetConnection().GetDirectoryIdentity() == nil {
		return invalid("connection")
	}
	if !proto.Equal(req.GetConnection().GetDirectoryIdentity(), h.src.Identity()) {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "directory identity mismatch")
	}
	id, err := write.GUIDFromWire(req.GetGuid())
	if err != nil {
		return invalid("guid")
	}
	attrs := req.GetAttributes()
	if len(attrs) == 0 || len(attrs) > maxAttributes {
		return invalid("attributes")
	}
	// Canonicalise once: the SD hold, the DC request and the answer filter all work on the schema
	// names, so an OID spelling can neither pass the hold nor be dropped from the answer.
	canon := make([]string, 0, len(attrs))
	for _, a := range attrs {
		c, err := h.src.CanonicalAttr(a)
		if err != nil {
			return mapAD(err, nil)
		}
		canon = append(canon, c)
	}
	attrs = canon
	for _, a := range attrs {
		if strings.EqualFold(a, "nTSecurityDescriptor") { // held for T-0118 (typed SD + SD-flags control)
			return refuse(connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "attribute not allowed")
		}
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
	e, err := h.src.Read(ctx, id, withInstanceType(attrs), int(req.GetMaxValuesPerAttribute()))
	if err != nil {
		return mapAD(err, before)
	}
	got, err := e.GUID()
	if err != nil || got != id {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "directory returned another object")
	}
	var parent *connectorv1.Guid
	if pg, ok, err := h.src.Parent(ctx, e); err != nil {
		if ad.CodeOf(err) == ad.CodeObjectNotFound {
			err = errors.New("parent not found") // not OBJECT_NOT_FOUND: the requested object exists
		}
		return mapAD(err, before)
	} else if ok {
		parent = write.GUIDToWire(pg)
	}
	var verdict *connectorv1.Tier0Verdict
	if req.GetIncludeTier0() {
		v, err := h.src.Classify(ctx, id)
		if err != nil {
			// An undecidable classification is an error, never tier0 = false.
			return refuse(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "tier0 classification failed")
		}
		verdict = &connectorv1.Tier0Verdict{Tier0: v.Tier0, Basis: sortedBasis(v.Bases)}
		if !v.Tier0 {
			verdict.Basis = nil
		}
	}
	// The DC after the read and the classification must be the DC before them (and the pin).
	after, err := h.bound(ctx, pin)
	if err != nil {
		return err
	}
	if !proto.Equal(before.GetDsaGuid(), after.GetDsaGuid()) {
		return pinRefusal()
	}

	entry, tails, err := h.build(e, id, parent, attrs)
	if err != nil {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "attribute could not be decoded")
	}
	obs := &connectorv1.Observation{Dc: after, ReceivedAt: timestamppb.New(h.now())}
	if err := out.Send(&connectorv1.ReadResponse{Event: &connectorv1.ReadResponse_Header{
		Header: &connectorv1.ReadHeader{Entry: entry, Observed: obs, Tier0: verdict}}}); err != nil {
		return err
	}
	for _, c := range tails {
		if err := out.Send(&connectorv1.ReadResponse{Event: &connectorv1.ReadResponse_Chunk{Chunk: c}}); err != nil {
			return err
		}
	}
	return out.Send(&connectorv1.ReadResponse{Event: &connectorv1.ReadResponse_Completed{
		Completed: &connectorv1.ReadCompleted{TruncatedAttributes: truncated(e)}}})
}

// bound returns the bound DC and, when a pin is given, fails unless it is that DC.
func (h *Handler) bound(ctx context.Context, pin *connectorv1.Guid) (*connectorv1.DcIdentity, error) {
	dc, err := h.src.BoundDC(ctx)
	if err != nil || dc == nil {
		return nil, refuse(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "domain controller identity unavailable")
	}
	if pin != nil && !proto.Equal(dc.GetDsaGuid(), pin) {
		return nil, pinRefusal()
	}
	return dc, nil
}

// withInstanceType adds instanceType to the requested names: the parent decision needs it, and
// build drops it again unless the caller asked for it.
func withInstanceType(attrs []string) []string {
	out := append([]string(nil), attrs...)
	for _, a := range out {
		if strings.EqualFold(a, "instanceType") {
			return out
		}
	}
	return append(out, "instanceType")
}

func sortedBasis(in []connectorv1.Tier0Basis) []connectorv1.Tier0Basis {
	seen := map[connectorv1.Tier0Basis]bool{}
	var out []connectorv1.Tier0Basis
	for _, b := range in {
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func truncated(e *ad.Entry) []string {
	out := append([]string(nil), e.Truncated...)
	sort.Strings(out)
	return out
}

// build turns the entry into the header entry plus the chunks that follow it. An attribute with
// more than rangeWindow values carries its first range in the header (complete = false) and the
// rest as in-order chunks, the last marked terminal.
func (h *Handler) build(e *ad.Entry, id guid.GUID, parent *connectorv1.Guid, asked []string) (*connectorv1.DirectoryEntry, []*connectorv1.ValueChunk, error) {
	out := &connectorv1.DirectoryEntry{ObjectGuid: write.GUIDToWire(id), ParentGuid: parent,
		Dn: &connectorv1.DnValue{DisplayDn: e.DN}}
	var tails []*connectorv1.ValueChunk
	want := map[string]bool{}
	for _, a := range asked {
		want[strings.ToLower(a)] = true
	}
	for _, name := range e.Names() {
		if name == "objectguid" || !want[name] {
			continue
		}
		raw := e.Raw(name)
		vals := make([]*connectorv1.AttributeValue, 0, len(raw))
		for _, r := range raw {
			v, err := h.value(name, r)
			if err != nil {
				return nil, nil, err
			}
			vals = append(vals, v)
		}
		at := &connectorv1.Attribute{Name: name, Complete: true}
		if len(vals) > rangeWindow {
			at.Values, at.Complete = vals[:rangeWindow], false
			at.Range = &connectorv1.ValueRange{Start: 0, End: rangeWindow - 1}
			for start := rangeWindow; start < len(vals); start += rangeWindow {
				end := min(start+rangeWindow, len(vals))
				tails = append(tails, &connectorv1.ValueChunk{Attribute: name, Values: vals[start:end],
					Range: &connectorv1.ValueRange{Start: uint32(start), End: uint32(end - 1), Terminal: end == len(vals)}})
			}
		} else {
			at.Values = vals
		}
		out.Attributes = append(out.Attributes, at)
	}
	return out, tails, nil
}

// value decodes one raw value by the attribute's schema syntax (wirevalue.Of).
func (h *Handler) value(name string, raw []byte) (*connectorv1.AttributeValue, error) {
	syn, _ := h.src.Syntax(name)
	return wirevalue.Of(name, syn, raw)
}
