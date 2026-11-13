package replstatus

import (
	"context"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/ad/replxml"
	"github.com/skenzeriq/activediq/internal/connector/write"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// MaxDCs is the most DCs one call reads (rule 5 [PROPOSED], spec §7.3.6). More is LIMIT_EXCEEDED
// before any directory call.
const MaxDCs = 100

// DefaultConcurrency is the DC-level fan-out when the request asks for none; the request can lower
// it, never raise it past MaxConcurrency. Each DC has one read in flight (rule 5).
const (
	DefaultConcurrency = 4
	MaxConcurrency     = 8
)

// DC is one domain controller in scope, as Describe lists it.
type DC struct {
	Identity *connectorv1.DcIdentity
	// ReadOnly marks an RODC; the WRITABLE scope leaves it out.
	ReadOnly bool
}

// DCLister returns every DC of the directory, reachable or not (Describe's domain_controllers).
type DCLister interface {
	DCs(ctx context.Context) ([]DC, error)
}

// DCReader reads the replication attributes of one DC. ad.Session satisfies it.
type DCReader interface {
	ReadReplication(ctx context.Context, attrs []ad.ReplAttr) (ad.ReplRead, error)
}

// Opener gives a reader for one DC and a function that releases it. A DC that cannot be reached is
// an error here, which becomes that DC's error result (rule 1).
type Opener interface {
	Open(ctx context.Context, dc DC) (DCReader, func(), error)
}

// Source is what the handler needs.
type Source interface {
	DCLister
	Opener
	Identity() *connectorv1.DirectoryIdentity
}

// Sender is the stream's Send.
type Sender interface {
	Send(*connectorv1.ReadReplicationStatusResponse) error
}

// Handler serves ReadReplicationStatus.
type Handler struct {
	src Source
	now func() time.Time
}

// New returns a handler over one source.
func New(src Source) (*Handler, error) {
	if src == nil {
		return nil, write.NewRefusal(connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "no source")
	}
	return &Handler{src: src, now: time.Now}, nil
}

func refuse(code connectorv1.ErrorCode, retry connectorv1.RetryAdvice, msg string) error {
	return write.NewRefusal(code, retry, msg)
}

func invalid(field string) error {
	r := write.NewRefusal(connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "invalid request")
	r.Err.Details = &connectorv1.ConnectorError_RejectedInput{RejectedInput: &connectorv1.RejectedInputDetails{RuleId: "InvalidReplicationRequest", Field: field}}
	return r
}

// request is the validated form of the call.
type request struct {
	scope      connectorv1.PerDcScope
	attrs      []ad.ReplAttr
	partitions [][]byte
	conc       int
}

var attrOf = map[connectorv1.ReplicationAttribute]ad.ReplAttr{
	connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_INBOUND_NEIGHBORS:   ad.ReplInboundNeighbors,
	connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_PENDING_OPS:         ad.ReplPendingOps,
	connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_CONNECTION_FAILURES: ad.ReplConnectionFailures,
	connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_LINK_FAILURES:       ad.ReplLinkFailures,
}

var protoAttr = map[ad.ReplAttr]connectorv1.ReplicationAttribute{
	ad.ReplInboundNeighbors:   connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_INBOUND_NEIGHBORS,
	ad.ReplPendingOps:         connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_PENDING_OPS,
	ad.ReplConnectionFailures: connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_CONNECTION_FAILURES,
	ad.ReplLinkFailures:       connectorv1.ReplicationAttribute_REPLICATION_ATTRIBUTE_LINK_FAILURES,
}

func validate(req *connectorv1.ReadReplicationStatusRequest) (request, error) {
	var r request
	switch req.GetScope() {
	case connectorv1.PerDcScope_PER_DC_SCOPE_WRITABLE, connectorv1.PerDcScope_PER_DC_SCOPE_ALL:
		r.scope = req.GetScope()
	default:
		return r, invalid("scope")
	}
	seen := map[ad.ReplAttr]bool{}
	for _, a := range req.GetAttributes() {
		m, ok := attrOf[a]
		if !ok {
			return r, invalid("attributes")
		}
		if !seen[m] {
			seen[m] = true
		}
	}
	for _, a := range ad.AllReplAttrs { // enum order, deduplicated; empty request means all four
		if len(seen) == 0 || seen[a] {
			r.attrs = append(r.attrs, a)
		}
	}
	for _, p := range req.GetPartitions() {
		if len(p.GetValue()) != 16 {
			return r, invalid("partitions")
		}
		r.partitions = append(r.partitions, p.GetValue())
	}
	r.conc = DefaultConcurrency
	if c := int(req.GetMaxConcurrency()); c > 0 && c < r.conc {
		r.conc = c
	}
	return r, nil
}

// ReadReplicationStatus runs the call: one ReplicationDcResult per DC in scope as it completes,
// then the summary.
func (h *Handler) ReadReplicationStatus(ctx context.Context, req *connectorv1.ReadReplicationStatusRequest, out Sender) error {
	if req.GetConnection().GetConnectionId() == "" || req.GetConnection().GetDirectoryIdentity() == nil {
		return invalid("connection")
	}
	if !proto.Equal(req.GetConnection().GetDirectoryIdentity(), h.src.Identity()) {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "directory identity mismatch")
	}
	r, err := validate(req)
	if err != nil {
		return err
	}
	all, err := h.src.DCs(ctx)
	if err != nil {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "domain controllers not listed")
	}
	var dcs []DC
	for _, d := range all {
		if r.scope == connectorv1.PerDcScope_PER_DC_SCOPE_WRITABLE && d.ReadOnly {
			continue
		}
		dcs = append(dcs, d)
	}
	if len(dcs) > MaxDCs {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "too many domain controllers in scope")
	}
	if len(dcs) == 0 {
		// "Complete over zero DCs" would read as healthy.
		return refuse(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "no domain controller in scope")
	}

	results := make(chan *connectorv1.ReplicationDcResult)
	sem := make(chan struct{}, r.conc)
	var wg sync.WaitGroup
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, d := range dcs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-cctx.Done():
				return
			}
			defer func() { <-sem }()
			res := h.readDC(cctx, d, r)
			select {
			case results <- res:
			case <-cctx.Done():
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()

	answered := 0
	for res := range results {
		if res.GetState() != nil {
			answered++
		}
		if err := out.Send(&connectorv1.ReadReplicationStatusResponse{Event: &connectorv1.ReadReplicationStatusResponse_Result{Result: res}}); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, "canceled")
	}
	cov := connectorv1.Coverage_COVERAGE_PARTIAL
	if answered == len(dcs) {
		cov = connectorv1.Coverage_COVERAGE_COMPLETE
	}
	return out.Send(&connectorv1.ReadReplicationStatusResponse{Event: &connectorv1.ReadReplicationStatusResponse_Summary{Summary: &connectorv1.ReplicationSummary{
		DcsInScope: uint32(len(dcs)), DcsAnswered: uint32(answered), Coverage: cov,
	}}})
}

// readDC reads one DC. Its failure is that DC's error result, never a dropped DC.
func (h *Handler) readDC(ctx context.Context, d DC, r request) *connectorv1.ReplicationDcResult {
	res := &connectorv1.ReplicationDcResult{Dc: d.Identity}
	fail := func(code connectorv1.ErrorCode, msg string) *connectorv1.ReplicationDcResult {
		e := write.NewRefusal(code, connectorv1.RetryAdvice_RETRY_ADVICE_AFTER_REPLAN, msg)
		e.Err.Dc = proto.Clone(d.Identity).(*connectorv1.DcIdentity)
		res.Outcome = &connectorv1.ReplicationDcResult_Error{Error: e.Err}
		return res
	}
	rd, release, err := h.src.Open(ctx, d)
	if err != nil {
		return fail(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, "domain controller unreachable")
	}
	defer release()
	read, err := rd.ReadReplication(ctx, r.attrs)
	received := h.now()
	if err != nil {
		switch ad.CodeOf(err) {
		case ad.CodeBindFailed:
			return fail(connectorv1.ErrorCode_ERROR_CODE_BIND_FAILED, "bind failed")
		case ad.CodeInvalidArgument:
			return fail(connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "invalid request")
		}
		return fail(connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, "domain controller unreachable")
	}
	res.Observed = &connectorv1.Observation{Dc: d.Identity, ReceivedAt: timestamppb.New(received)}
	res.Outcome = &connectorv1.ReplicationDcResult_State{State: stateOf(read, r)}
	return res
}

// stateOf decodes every value through replxml and builds the state. One attribute's failure never
// affects another's.
func stateOf(read ad.ReplRead, r request) *connectorv1.ReplicationState {
	st := &connectorv1.ReplicationState{}
	var budget replxml.Budget // X2: 8 MiB per DC per call, across all four attributes
	for _, a := range r.attrs {
		v, ok := read[a]
		o := &connectorv1.AttributeOutcome{Attribute: protoAttr[a]}
		switch {
		case ok && v.Denied:
			o.Kind = connectorv1.OutcomeKind_PERMISSION_DENIED
		case !ok || !v.Present || len(v.Values) == 0:
			o.Kind = connectorv1.OutcomeKind_NOT_RETURNED
		case v.RangeIncomplete:
			o.Kind, o.DetailCode = connectorv1.OutcomeKind_DECODE_FAILED, "RANGE_INCOMPLETE"
		default:
			if code := decodeAttr(st, a, v.Values, &budget, r.partitions); code != "" {
				o.Kind, o.DetailCode = connectorv1.OutcomeKind_DECODE_FAILED, string(code)
			} else {
				o.Kind = connectorv1.OutcomeKind_RETURNED
			}
		}
		st.Attributes = append(st.Attributes, o)
	}
	return st
}
