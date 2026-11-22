package read

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/wirevalue"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	// maxPerDCDomainControllers bounds one call (connector-contract §5.5 / §5.6 rule 5): more is
	// LIMIT_EXCEEDED before any read, never a silent truncation.
	maxPerDCDomainControllers = 100
	// DefaultPerDCOps is the number of reads in flight against one DC: one (§5.6 rule 5).
	DefaultPerDCOps = 1
	// DefaultPerDomainOps is the number of reads in flight across one domain's DCs.
	DefaultPerDomainOps = 8
	// perDCReadTimeout bounds one DC's read (open, bind, identity and read) so a hung DC is a
	// result with an error and the call still ends in a summary.
	perDCReadTimeout = 30 * time.Second
)

// DC is one domain controller of the domain asked about.
type DC struct {
	Host    string
	Site    string
	DSAGUID guid.GUID
	// RODC is meaningful only when RODCKnown. An unknown DC is in scope for both scopes: dropping it
	// would hide a DC from the coverage.
	RODC, RODCKnown bool
}

// PerDCSource is the optional per-DC half of a Source. A Source without it answers ReadPerDC with
// CAPABILITY_UNSUPPORTED.
type PerDCSource interface {
	// DomainDCs lists the DCs that serve the domain whose naming-context head has this objectGUID,
	// reachable or not.
	DomainDCs(ctx context.Context, nc guid.GUID) ([]DC, error)
	// ReadOnDC reads attrs of the object on that DC and on no other. The returned identity is the
	// DC that answered; it is nil if the DC could not be reached.
	ReadOnDC(ctx context.Context, dc DC, id guid.GUID, attrs []string) (*ad.Entry, *connectorv1.DcIdentity, error)
}

// PerDCSender is the sending side of the ReadPerDC stream.
type PerDCSender interface {
	Send(*connectorv1.ReadPerDCResponse) error
}

// perDCName is the LDAP name of each closed-enum attribute. Time reports whether the value is a
// FILETIME.
var perDCName = map[connectorv1.PerDcAttribute]struct {
	name string
	time bool
}{
	connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON:        {"lastLogon", true},
	connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LOGON_COUNT:       {"logonCount", false},
	connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_BAD_PWD_COUNT:     {"badPwdCount", false},
	connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_BAD_PASSWORD_TIME: {"badPasswordTime", true},
	connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LOCKOUT_TIME:      {"lockoutTime", true},
}

// sem is a counting semaphore; acquire gives up with the context.
type sem chan struct{}

func (s sem) acquire(ctx context.Context) error {
	select {
	case s <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release frees a slot this caller took; it is only called after a successful acquire.
func (s sem) release() { <-s }

// limiter hands out one semaphore per key, shared by every call of the handler, so the caps hold
// across concurrent calls and not just within one.
type limiter struct {
	mu   sync.Mutex
	size int
	m    map[string]sem
}

func (l *limiter) get(key string) sem {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]sem{}
	}
	s, ok := l.m[key]
	if !ok {
		s = make(sem, l.size)
		l.m[key] = s
	}
	return s
}

// WithPerDCLimits sets the reads in flight against one DC and across one domain. Values below one
// keep the defaults. It is called before the handler serves.
func (h *Handler) WithPerDCLimits(perDC, perDomain int) *Handler {
	if perDC > 0 {
		h.perDC = &limiter{size: perDC}
	}
	if perDomain > 0 {
		h.perDomain = &limiter{size: perDomain}
	}
	return h
}

func invalidPerDC(field string) error {
	r := write.NewRefusal(connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "invalid request")
	r.Err.Details = &connectorv1.ConnectorError_RejectedInput{RejectedInput: &connectorv1.RejectedInputDetails{RuleId: "InvalidReadPerDCRequest", Field: field}}
	return r
}

// ReadPerDC implements the ReadPerDC RPC (connector-contract §5.5): the object's per-DC attributes
// from every DC of its domain that the scope includes, one PerDcResult per DC as it completes
// (values, or the typed error that kept the DC from answering), then one PerDcSummary. A DC is never
// dropped: COMPLETE means every DC in scope answered. Reads run under the per-DC and per-domain
// caps, which max_concurrency can only lower.
func (h *Handler) ReadPerDC(ctx context.Context, req *connectorv1.ReadPerDCRequest, out PerDCSender) error {
	psrc, ok := h.src.(PerDCSource)
	if !ok {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "per-DC read not supported")
	}
	if req.GetConnection().GetConnectionId() == "" || req.GetConnection().GetDirectoryIdentity() == nil {
		return invalidPerDC("connection")
	}
	if !proto.Equal(req.GetConnection().GetDirectoryIdentity(), h.src.Identity()) {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "directory identity mismatch")
	}
	id, err := write.GUIDFromWire(req.GetGuid())
	if err != nil {
		return invalidPerDC("guid")
	}
	nc, err := write.GUIDFromWire(req.GetNcGuid())
	if err != nil {
		return invalidPerDC("nc_guid")
	}
	var attrs []connectorv1.PerDcAttribute
	seen := map[connectorv1.PerDcAttribute]bool{}
	for _, a := range req.GetAttributes() {
		if _, ok := perDCName[a]; !ok {
			return invalidPerDC("attributes")
		}
		if !seen[a] {
			seen[a] = true
			attrs = append(attrs, a)
		}
	}
	if len(attrs) == 0 {
		return invalidPerDC("attributes")
	}
	switch req.GetScope() {
	case connectorv1.PerDcScope_PER_DC_SCOPE_WRITABLE, connectorv1.PerDcScope_PER_DC_SCOPE_ALL:
	default:
		return invalidPerDC("scope")
	}

	all, err := psrc.DomainDCs(ctx, nc)
	if err != nil {
		return mapAD(err, nil)
	}
	var dcs []DC
	for _, dc := range all {
		if req.GetScope() == connectorv1.PerDcScope_PER_DC_SCOPE_WRITABLE && dc.RODCKnown && dc.RODC {
			continue
		}
		dcs = append(dcs, dc)
	}
	if len(all) == 0 {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "domain not found")
	}
	if len(dcs) > maxPerDCDomainControllers {
		return refuse(connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED, connectorv1.RetryAdvice_RETRY_ADVICE_NEVER, "too many domain controllers in scope")
	}

	// Workers: the domain cap, lowered by the request and by the number of DCs. The per-DC cap is
	// the semaphore each worker takes for the DC it reads.
	domSem := h.perDomain.get(string(nc[:]))
	workers := cap(domSem)
	if m := int(req.GetMaxConcurrency()); m > 0 && m < workers {
		workers = m
	}
	workers = min(workers, len(dcs))

	jobs := make(chan DC)
	results := make(chan *connectorv1.PerDcResult)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dc := range jobs {
				r := h.readDC(cctx, psrc, domSem, dc, id, attrs)
				select {
				case results <- r:
				case <-cctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, dc := range dcs {
			select {
			case jobs <- dc:
			case <-cctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	answered := 0
	for r := range results {
		if r.GetValues() != nil {
			answered++
		}
		if err := out.Send(&connectorv1.ReadPerDCResponse{Event: &connectorv1.ReadPerDCResponse_Result{Result: r}}); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return mapAD(&ad.Error{Code: ad.CodeCanceled}, nil) // a cancelled call has no summary: it must not look finished
	}
	cov := connectorv1.Coverage_COVERAGE_PARTIAL
	if answered == len(dcs) {
		cov = connectorv1.Coverage_COVERAGE_COMPLETE
	}
	return out.Send(&connectorv1.ReadPerDCResponse{Event: &connectorv1.ReadPerDCResponse_Summary{
		Summary: &connectorv1.PerDcSummary{DcsInScope: uint32(len(dcs)), DcsAnswered: uint32(answered), Coverage: cov}}})
}

// readDC reads one DC under its cap and turns every outcome into a result.
func (h *Handler) readDC(ctx context.Context, psrc PerDCSource, dom sem, dc DC, id guid.GUID, attrs []connectorv1.PerDcAttribute) *connectorv1.PerDcResult {
	listed := &connectorv1.DcIdentity{DsaGuid: write.GUIDToWire(dc.DSAGUID), DnsHostname: dc.Host, Site: dc.Site}
	fail := func(err error, who *connectorv1.DcIdentity) *connectorv1.PerDcResult {
		if who == nil || !proto.Equal(who.GetDsaGuid(), listed.GetDsaGuid()) {
			who = listed // an error result always names the DC that was listed, never an impostor
		}
		var ref *write.Refusal
		if !errors.As(mapAD(err, who), &ref) {
			panic("read: mapAD returns a refusal")
		}
		return &connectorv1.PerDcResult{Dc: who, Observed: h.observed(who), Outcome: &connectorv1.PerDcResult_Error{Error: ref.Err}}
	}
	if dc.Host == "" {
		return fail(&ad.Error{Code: ad.CodeUnreachable}, nil) // a server object without a name cannot be dialled
	}
	dcSem := h.perDC.get(string(dc.DSAGUID[:]))
	if err := dcSem.acquire(ctx); err != nil {
		return fail(&ad.Error{Code: ad.CodeCanceled}, nil)
	}
	defer dcSem.release()
	if err := dom.acquire(ctx); err != nil {
		return fail(&ad.Error{Code: ad.CodeCanceled}, nil)
	}
	defer dom.release()

	rctx, cancel := context.WithTimeout(ctx, perDCReadTimeout)
	defer cancel()
	names := make([]string, len(attrs))
	for i, a := range attrs {
		names[i] = perDCName[a].name
	}
	e, who, err := psrc.ReadOnDC(rctx, dc, id, names)
	if err != nil {
		return fail(err, who)
	}
	// The DC that answered must be the DC listed: a host re-pointed or rebuilt since the listing is
	// another DC's answer under this DC's name.
	if who == nil || !proto.Equal(who.GetDsaGuid(), listed.GetDsaGuid()) {
		return fail(&ad.Error{Code: ad.CodeUnreachable}, nil)
	}
	if got, gerr := e.GUID(); gerr != nil || got != id {
		return fail(&ad.Error{Code: ad.CodeProtocol}, who)
	}
	vals := &connectorv1.PerDcValues{}
	for _, a := range attrs {
		v, derr := perDCValue(e, a)
		if derr != nil {
			return fail(derr, who) // a value that does not decode is not a value
		}
		vals.Values = append(vals.Values, v)
	}
	return &connectorv1.PerDcResult{Dc: who, Observed: h.observed(who), Outcome: &connectorv1.PerDcResult_Values{Values: vals}}
}

func (h *Handler) observed(dc *connectorv1.DcIdentity) *connectorv1.Observation {
	return &connectorv1.Observation{Dc: dc, ReceivedAt: timestamppb.New(h.now())}
}

// perDCValue decodes one attribute. A DC omits an attribute that holds nothing (a never-logged-on
// account has no lastLogon), which is the value 0: ZERO for a time, 0 for a count. That is the
// documented meaning of absence; an attribute the account cannot read looks the same, a limit the
// caller already carries through the connection's required rights.
func perDCValue(e *ad.Entry, a connectorv1.PerDcAttribute) (*connectorv1.PerDcValue, error) {
	info := perDCName[a]
	raw := e.Raw(info.name)
	var n int64
	switch len(raw) {
	case 0:
	case 1:
		var err error
		if n, err = codec.ParseInteger(string(raw[0]), 64); err != nil {
			return nil, &ad.Error{Code: ad.CodeProtocol}
		}
	default:
		return nil, &ad.Error{Code: ad.CodeProtocol}
	}
	if info.time {
		return &connectorv1.PerDcValue{Attribute: a, Value: &connectorv1.PerDcValue_Time{Time: wirevalue.TimeOf(n)}}, nil
	}
	return &connectorv1.PerDcValue{Attribute: a, Value: &connectorv1.PerDcValue_Integer{Integer: n}}, nil
}
