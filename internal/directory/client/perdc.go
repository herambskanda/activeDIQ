package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Errors of the per-DC read. None carries an object identifier, a DC list or a connector message.
var (
	ErrNoPerDCTransport = errors.New("client: no per-DC read transport wired")
	ErrPerDCAttr        = fmt.Errorf("%w: per-DC attribute", ErrInvalidOp)
	ErrPerDCScope       = fmt.Errorf("%w: per-DC scope", ErrInvalidOp)
	ErrPerDCRead        = errors.New("client: connector per-DC read failed") // no typed connector error behind it
	ErrPerDCObjects     = fmt.Errorf("%w: per-DC read needs at least one object", ErrInvalidOp)
)

// Bounds on the per-DC read. The connector lowers the DC fan-out further under its own per-DC and
// per-domain caps (connector contract §5.5); these bound what this side ever asks.
const (
	// DefaultPerDCInFlight is the reads in flight per tenant when none is configured.
	DefaultPerDCInFlight = 8
	// MaxPerDCInFlight is the largest bound a configuration may ask for.
	MaxPerDCInFlight = 64
	// DefaultPerDCFanOut is the DCs the connector is asked to read at once for one object.
	DefaultPerDCFanOut = 4
	// MaxPerDCFanOut is the largest fan-out a configuration may ask for.
	MaxPerDCFanOut = 16

	maxDCNameLen = 255
	// maxPerDCResults bounds how many DC answers one object's stream may carry; a forest has far fewer
	// DCs, so more is a broken or hostile stream, not a big domain.
	maxPerDCResults = 4096
)

// PerDCStream is the receiving side of the ReadPerDC RPC. The generated
// grpc.ServerStreamingClient satisfies it.
type PerDCStream interface {
	Recv() (*connectorv1.ReadPerDCResponse, error)
}

// PerDCTransport opens the ReadPerDC stream of the connector serving req.Connection. The gRPC
// transport implements it; the generated client is referenced there and nowhere else.
type PerDCTransport interface {
	ReadPerDC(ctx context.Context, req *connectorv1.ReadPerDCRequest) (PerDCStream, error)
}

// PerDCConfig bounds the reader. The zero value takes the defaults; a value above its maximum is an
// error, never silently clamped.
type PerDCConfig struct {
	// InFlight is the most ReadPerDC calls running at once for one tenant, across every Read.
	InFlight int
	// FanOut is the max_concurrency asked of the connector for one call (it may lower it).
	FanOut int
}

// ConnectorPerDC reads attributes that are not replicated from every DC of an object's domain, over
// the connector's ReadPerDC RPC. It implements report.PerDCReader.
type ConnectorPerDC struct {
	conns  ConnectionSource
	tr     PerDCTransport
	flight int
	fanOut uint32

	reads atomic.Uint64
	mu    sync.Mutex
	sems  map[tenant.ID]chan struct{}
}

var _ report.PerDCReader = (*ConnectorPerDC)(nil)

// NewConnectorPerDC returns the reader. Every port is required.
func NewConnectorPerDC(conns ConnectionSource, tr PerDCTransport, cfg PerDCConfig) (*ConnectorPerDC, error) {
	switch {
	case conns == nil:
		return nil, errors.New("client: per-DC reads need a connection source")
	case tr == nil:
		return nil, ErrNoPerDCTransport
	}
	if cfg.InFlight == 0 {
		cfg.InFlight = DefaultPerDCInFlight
	}
	if cfg.FanOut == 0 {
		cfg.FanOut = DefaultPerDCFanOut
	}
	if cfg.InFlight < 0 || cfg.InFlight > MaxPerDCInFlight || cfg.FanOut < 0 || cfg.FanOut > MaxPerDCFanOut {
		return nil, errors.New("client: per-DC read bounds out of range")
	}
	return &ConnectorPerDC{conns: conns, tr: tr, flight: cfg.InFlight, fanOut: uint32(cfg.FanOut), sems: map[tenant.ID]chan struct{}{}}, nil
}

// Reads is the number of ReadPerDC calls made to the connector since the reader was built. The run
// path compares it with the read cap it checked before reading (reports.md §6.5).
func (p *ConnectorPerDC) Reads() uint64 { return p.reads.Load() }

// Read implements report.PerDCReader: one ReadPerDC per object, at most the configured number in
// flight for the tenant of ctx. It returns each object's per-DC answers in the order of objs and one
// summary for the batch: DCsInScope is the largest any object saw, DCsAnswered the smallest, and
// coverage is COMPLETE only when every object's was. A failure of any call fails the batch; nothing
// partial is returned with an error. Attributes and scope are validated before any RPC.
func (p *ConnectorPerDC) Read(ctx context.Context, conn, nc authz.ObjectID, objs []authz.ObjectID,
	attrs []report.PerDCAttr, scope report.PerDCScope) ([]report.PerDCObject, report.PerDCSummary, error) {
	none := report.PerDCSummary{}
	wireAttrs, err := wireAttrsOf(attrs)
	if err != nil {
		return nil, none, err
	}
	wireScope, err := wireScopeOf(scope)
	if err != nil {
		return nil, none, err
	}
	if len(objs) == 0 {
		return nil, none, ErrPerDCObjects
	}
	for _, o := range objs {
		if o.IsZero() {
			return nil, none, fmt.Errorf("%w: object GUID", ErrInvalidOp)
		}
	}
	if conn.IsZero() || nc.IsZero() {
		return nil, none, fmt.Errorf("%w: connection or naming context", ErrInvalidOp)
	}
	tid, err := readTenant(ctx)
	if err != nil {
		return nil, none, err
	}
	connID := formatUUID(wireGUID(conn).Value)
	c, err := p.conns.Get(ctx, tid, connection.ID(connID))
	if err != nil || string(c.ID) != connID || c.RetiredAt != nil || c.Kind != connection.KindADForest {
		return nil, none, ErrReadConnection
	}
	ident := directoryOf(c)
	if ident == nil {
		return nil, none, ErrReadDirectory
	}
	base := connectorv1.ReadPerDCRequest{
		Connection:     &connectorv1.ConnectionRef{ConnectionId: connID, DirectoryIdentity: ident},
		NcGuid:         wireGUID(nc),
		Attributes:     wireAttrs,
		Scope:          wireScope,
		MaxConcurrency: p.fanOut,
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := p.semaphore(tid)
	type one struct {
		obj     report.PerDCObject
		summary report.PerDCSummary
	}
	got := make([]one, len(objs))
	var (
		wg       sync.WaitGroup
		failOnce sync.Once
		failure  error
	)
	fail := func(err error) { failOnce.Do(func() { failure = err; cancel() }) }
loop:
	for i, o := range objs {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break loop
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			req := &connectorv1.ReadPerDCRequest{
				Connection: base.Connection, NcGuid: base.NcGuid, Attributes: base.Attributes, Scope: base.Scope,
				MaxConcurrency: base.MaxConcurrency, Guid: wireGUID(o),
			}
			obj, sum, err := p.readOne(ctx, req, o, attrs)
			if err != nil {
				fail(err)
				return
			}
			got[i] = one{obj, sum}
		}()
	}
	wg.Wait()
	if failure != nil {
		return nil, none, failure
	}
	if err := ctx.Err(); err != nil {
		return nil, none, fmt.Errorf("client: per-DC read: %w", err)
	}

	out := make([]report.PerDCObject, len(objs))
	sum := report.PerDCSummary{DCsAnswered: ^uint32(0), Coverage: report.CoverageComplete}
	for i, g := range got {
		out[i] = g.obj
		sum.DCsInScope = max(sum.DCsInScope, g.summary.DCsInScope)
		sum.DCsAnswered = min(sum.DCsAnswered, g.summary.DCsAnswered)
		if g.summary.Coverage != report.CoverageComplete {
			sum.Coverage = report.CoveragePartial
		}
	}
	return out, sum, nil
}

// ReadPerDC reads attrs of one object from every DC in scope of the domain nc. See Read.
func (p *ConnectorPerDC) ReadPerDC(ctx context.Context, conn, nc, obj authz.ObjectID, attrs []report.PerDCAttr,
	scope report.PerDCScope) (report.PerDCObject, report.PerDCSummary, error) {
	objs, sum, err := p.Read(ctx, conn, nc, []authz.ObjectID{obj}, attrs, scope)
	if err != nil {
		return report.PerDCObject{}, report.PerDCSummary{}, err
	}
	return objs[0], sum, nil
}

func (p *ConnectorPerDC) semaphore(tid tenant.ID) chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sems[tid]
	if !ok {
		s = make(chan struct{}, p.flight)
		p.sems[tid] = s
	}
	return s
}

// readOne makes one ReadPerDC call and folds its stream: DC results, then exactly one summary, then
// the end. Anything else is a protocol error.
func (p *ConnectorPerDC) readOne(ctx context.Context, req *connectorv1.ReadPerDCRequest, obj authz.ObjectID,
	attrs []report.PerDCAttr) (report.PerDCObject, report.PerDCSummary, error) {
	p.reads.Add(1)
	st, err := p.tr.ReadPerDC(ctx, req)
	if err != nil {
		return notFoundPerDC(obj, err)
	}
	var (
		results  []report.PerDCResult
		seen     = map[string]bool{}
		claimed  *connectorv1.PerDcSummary
		needSet  = attrSet(attrs)
		answered uint32
	)
	for {
		m, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return notFoundPerDC(obj, err)
		}
		if claimed != nil {
			return report.PerDCObject{}, report.PerDCSummary{}, ErrReadProtocol // nothing follows the summary
		}
		switch ev := m.GetEvent().(type) {
		case *connectorv1.ReadPerDCResponse_Result:
			if len(results) >= maxPerDCResults {
				return report.PerDCObject{}, report.PerDCSummary{}, ErrReadProtocol
			}
			r, key, err := foldDC(ev.Result, needSet)
			if err != nil {
				return report.PerDCObject{}, report.PerDCSummary{}, err
			}
			if seen[key] {
				return report.PerDCObject{}, report.PerDCSummary{}, ErrReadProtocol // one answer per DC
			}
			seen[key] = true
			if r.Err == "" {
				answered++
			}
			results = append(results, r)
		case *connectorv1.ReadPerDCResponse_Summary:
			if ev.Summary == nil {
				return report.PerDCObject{}, report.PerDCSummary{}, ErrReadProtocol
			}
			claimed = ev.Summary
		default:
			return report.PerDCObject{}, report.PerDCSummary{}, ErrReadProtocol
		}
	}
	if claimed == nil {
		return report.PerDCObject{}, report.PerDCSummary{}, ErrReadProtocol // an early end is an incomplete read
	}
	// The connector reports every DC in scope, answered or not, so the count of results is its scope.
	if uint32(len(results)) != claimed.GetDcsInScope() || claimed.GetDcsAnswered() > claimed.GetDcsInScope() {
		return report.PerDCObject{}, report.PerDCSummary{}, ErrReadProtocol
	}
	switch claimed.GetCoverage() {
	case connectorv1.Coverage_COVERAGE_COMPLETE:
		if claimed.GetDcsAnswered() != claimed.GetDcsInScope() || claimed.GetDcsInScope() == 0 {
			return report.PerDCObject{}, report.PerDCSummary{}, ErrReadProtocol
		}
	case connectorv1.Coverage_COVERAGE_PARTIAL:
		if claimed.GetDcsAnswered() == claimed.GetDcsInScope() {
			return report.PerDCObject{}, report.PerDCSummary{}, ErrReadProtocol
		}
	default:
		return report.PerDCObject{}, report.PerDCSummary{}, ErrReadProtocol
	}
	// Coverage is derived from the answers we accepted, never taken on trust: a DC whose values we
	// had to refuse (foldDC marks it with an error) is not an answer, and a connector that says
	// COMPLETE cannot raise the count above it.
	slices.SortFunc(results, func(a, b report.PerDCResult) int { return strings.Compare(a.DC, b.DC) })
	sum := report.PerDCSummary{DCsInScope: uint32(len(results)), DCsAnswered: min(answered, claimed.GetDcsAnswered())}
	sum.Coverage = report.CoveragePartial
	if sum.DCsInScope > 0 && sum.DCsAnswered == sum.DCsInScope {
		sum.Coverage = report.CoverageComplete
	}
	return report.PerDCObject{Object: obj, Results: results}, sum, nil
}

// notFoundPerDC maps a failed call. A stream-level OBJECT_NOT_FOUND is an object with no answers and
// PARTIAL coverage (never a maximum anyone may call exact); every other failure is an error.
func notFoundPerDC(obj authz.ObjectID, err error) (report.PerDCObject, report.PerDCSummary, error) {
	var re *RemoteError
	if errors.As(FromStatus(err), &re) && re.Err.GetCode() == connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND {
		return report.PerDCObject{Object: obj}, report.PerDCSummary{Coverage: report.CoveragePartial}, nil
	}
	if errors.As(FromStatus(err), &re) {
		return report.PerDCObject{}, report.PerDCSummary{}, fmt.Errorf("client: connector per-DC read: %w", re)
	}
	// A status without a ConnectorError detail carries free text: never pass it on.
	if ctxErr := contextErr(err); ctxErr != nil {
		return report.PerDCObject{}, report.PerDCSummary{}, fmt.Errorf("client: connector per-DC read: %w", ctxErr)
	}
	return report.PerDCObject{}, report.PerDCSummary{}, ErrPerDCRead
}

func contextErr(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	}
	return nil
}

// foldDC turns one DC's PerDcResult into a report.PerDCResult. A DC that answered with values we can
// not accept is an errored result (code "invalid_value" or "incomplete_values"), never a guess and
// never a silent drop. The key identifies the DC for the one-answer-per-DC check.
func foldDC(r *connectorv1.PerDcResult, want map[connectorv1.PerDcAttribute]report.PerDCAttr) (report.PerDCResult, string, error) {
	if r == nil {
		return report.PerDCResult{}, "", ErrReadProtocol
	}
	id := r.GetDc()
	if id == nil {
		id = r.GetObserved().GetDc()
	}
	if id == nil {
		if e := r.GetError(); e != nil {
			id = e.GetDc()
		}
	}
	name := id.GetDnsHostname()
	dsa := id.GetDsaGuid().GetValue()
	if name == "" && len(dsa) == 16 && !allZero(dsa) {
		name = formatUUID(dsa)
	}
	if !plainDCName(name) {
		return report.PerDCResult{}, "", ErrReadProtocol
	}
	key := strings.ToLower(name)
	out := report.PerDCResult{DC: name}
	switch o := r.GetOutcome().(type) {
	case *connectorv1.PerDcResult_Error:
		out.Err = errCode(o.Error.GetCode())
	case *connectorv1.PerDcResult_Values:
		vals, code := foldValues(o.Values.GetValues(), want)
		if code != "" {
			out.Err = code
		} else {
			out.Values = vals
		}
	default:
		return report.PerDCResult{}, "", ErrReadProtocol
	}
	return out, key, nil
}

// foldValues maps the values of one DC. Every requested attribute must be present exactly once, with
// the value kind the attribute has: omission is never read as "not set" (CC-READ-08).
func foldValues(in []*connectorv1.PerDcValue, want map[connectorv1.PerDcAttribute]report.PerDCAttr) ([]report.PerDCValue, string) {
	out := make([]report.PerDCValue, 0, len(want))
	have := map[report.PerDCAttr]bool{}
	for _, v := range in {
		a, ok := want[v.GetAttribute()]
		if !ok || have[a] {
			return nil, "invalid_value" // an attribute we did not ask for, or twice
		}
		have[a] = true
		pv := report.PerDCValue{Attr: a}
		if isCountAttr(a) {
			if _, ok := v.GetValue().(*connectorv1.PerDcValue_Integer); !ok {
				return nil, "invalid_value"
			}
			pv.Int = v.GetInteger()
		} else {
			tv, ok := v.GetValue().(*connectorv1.PerDcValue_Time)
			if !ok {
				return nil, "invalid_value"
			}
			t, ok := timeOf(tv.Time)
			if !ok {
				return nil, "invalid_value"
			}
			pv.Time = t
		}
		out = append(out, pv)
	}
	if len(have) != len(want) {
		return nil, "incomplete_values"
	}
	slices.SortFunc(out, func(a, b report.PerDCValue) int { return int(a.Attr) - int(b.Attr) })
	return out, ""
}

// timeOf maps a TimeValue. FILETIME 0 (the "unset" form of lastLogon, lockoutTime, badPasswordTime) is
// the zero time.Time; MAX and ticks beyond year 9999 are not a value any of these attributes holds.
func timeOf(tv *connectorv1.TimeValue) (time.Time, bool) {
	switch k := tv.GetKind().(type) {
	case *connectorv1.TimeValue_At:
		if k.At == nil || k.At.CheckValid() != nil {
			return time.Time{}, false
		}
		t := k.At.AsTime()
		return t, !t.IsZero()
	case *connectorv1.TimeValue_Sentinel:
		return time.Time{}, k.Sentinel == connectorv1.TimeSentinel_TIME_SENTINEL_ZERO
	}
	return time.Time{}, false
}

func isCountAttr(a report.PerDCAttr) bool {
	return a == report.PerDCLogonCount || a == report.PerDCBadPwdCount
}

// errCode is the fixed, lowercase code of a connector error code ("unreachable_dc"): never the message.
func errCode(c connectorv1.ErrorCode) string {
	if c == connectorv1.ErrorCode_ERROR_CODE_UNSPECIFIED {
		return "unknown"
	}
	if _, ok := connectorv1.ErrorCode_name[int32(c)]; !ok {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(c.String(), "ERROR_CODE_"))
}

// plainDCName accepts a DNS host name or a GUID text and nothing that could be markup or a control.
func plainDCName(s string) bool {
	if s == "" || len(s) > maxDCNameLen {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII || (!unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '-' && r != '_') {
			return false
		}
	}
	return true
}

// wireAttrsOf maps the closed attribute set. An undefined value is refused here, before any RPC: there
// is no path from a string to an attribute name on the wire.
func wireAttrsOf(attrs []report.PerDCAttr) ([]connectorv1.PerDcAttribute, error) {
	if len(attrs) == 0 || len(attrs) > len(perDCWire) {
		return nil, ErrPerDCAttr
	}
	out := make([]connectorv1.PerDcAttribute, 0, len(attrs))
	seen := map[report.PerDCAttr]bool{}
	for _, a := range attrs {
		w, ok := perDCWire[a]
		if !a.Valid() || !ok || seen[a] {
			return nil, ErrPerDCAttr
		}
		seen[a] = true
		out = append(out, w)
	}
	return out, nil
}

var perDCWire = map[report.PerDCAttr]connectorv1.PerDcAttribute{
	report.PerDCLastLogon:       connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON,
	report.PerDCLogonCount:      connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LOGON_COUNT,
	report.PerDCBadPwdCount:     connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_BAD_PWD_COUNT,
	report.PerDCBadPasswordTime: connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_BAD_PASSWORD_TIME,
	report.PerDCLockoutTime:     connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LOCKOUT_TIME,
}

func attrSet(attrs []report.PerDCAttr) map[connectorv1.PerDcAttribute]report.PerDCAttr {
	m := make(map[connectorv1.PerDcAttribute]report.PerDCAttr, len(attrs))
	for _, a := range attrs {
		m[perDCWire[a]] = a
	}
	return m
}

func wireScopeOf(s report.PerDCScope) (connectorv1.PerDcScope, error) {
	switch s {
	case report.ScopeWritable:
		return connectorv1.PerDcScope_PER_DC_SCOPE_WRITABLE, nil
	case report.ScopeAll:
		return connectorv1.PerDcScope_PER_DC_SCOPE_ALL, nil
	}
	return 0, ErrPerDCScope
}
