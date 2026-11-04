package read_test

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const ncGUID = "bbbbbbbb-0000-0000-0000-000000000001"

func dsa(i int) guid.GUID { return g(fmt.Sprintf("cccccccc-0000-0000-0000-%012d", i)) }

// filetime of 2026-01-01T00:00:00Z.
const ft2026 = int64(134_116_992_000_000_000)

// pdSrc is a Source with the per-DC half; reads are scripted per DSA GUID.
type pdSrc struct {
	*src
	dcs     []read.DC
	listErr error
	// per DSA: the lastLogon text ("" = attribute absent) or an error.
	logon map[guid.GUID]string
	errs  map[guid.GUID]error
	other map[guid.GUID]guid.GUID // the DC that really answers at this host
	hold  time.Duration

	mu       sync.Mutex
	inflight map[guid.GUID]int
	peak     map[guid.GUID]int
	total    atomic.Int32
}

func (p *pdSrc) DomainDCs(context.Context, guid.GUID) ([]read.DC, error) { return p.dcs, p.listErr }

func (p *pdSrc) ReadOnDC(ctx context.Context, dc read.DC, id guid.GUID, attrs []string) (*ad.Entry, *connectorv1.DcIdentity, error) {
	p.mu.Lock()
	if p.inflight == nil {
		p.inflight, p.peak = map[guid.GUID]int{}, map[guid.GUID]int{}
	}
	p.inflight[dc.DSAGUID]++
	p.peak[dc.DSAGUID] = max(p.peak[dc.DSAGUID], p.inflight[dc.DSAGUID])
	p.mu.Unlock()
	p.total.Add(1)
	defer func() { p.mu.Lock(); p.inflight[dc.DSAGUID]--; p.mu.Unlock() }()
	if p.hold > 0 {
		select {
		case <-time.After(p.hold):
		case <-ctx.Done():
		}
	}
	answers := dc.DSAGUID
	if o, ok := p.other[dc.DSAGUID]; ok {
		answers = o
	}
	who := &connectorv1.DcIdentity{DsaGuid: write.GUIDToWire(answers), DnsHostname: dc.Host}
	if err := p.errs[dc.DSAGUID]; err != nil {
		if ad.CodeOf(err) == ad.CodeUnreachable {
			return nil, nil, err
		}
		return nil, who, err
	}
	a := map[string][][]byte{"objectGUID": {id.Bytes()}, "logonCount": {[]byte("7")}, "badPwdCount": {[]byte("2")}}
	if v := p.logon[dc.DSAGUID]; v != "" {
		a["lastLogon"] = [][]byte{[]byte(v)}
	}
	return ad.NewEntry("CN=u", a), who, nil
}

func newPD(n int) *pdSrc {
	p := &pdSrc{src: &src{dsa: dsaA}, logon: map[guid.GUID]string{}, errs: map[guid.GUID]error{}, other: map[guid.GUID]guid.GUID{}}
	for i := 1; i <= n; i++ {
		p.dcs = append(p.dcs, read.DC{Host: "dc" + strconv.Itoa(i) + ".lab.test", Site: "S", DSAGUID: dsa(i), RODCKnown: true})
	}
	return p
}

func pdReq(scope connectorv1.PerDcScope, attrs ...connectorv1.PerDcAttribute) *connectorv1.ReadPerDCRequest {
	if len(attrs) == 0 {
		attrs = []connectorv1.PerDcAttribute{connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON,
			connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LOGON_COUNT}
	}
	return &connectorv1.ReadPerDCRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: ident},
		Guid: write.GUIDToWire(g(objGUID)), NcGuid: write.GUIDToWire(g(ncGUID)), Attributes: attrs, Scope: scope}
}

func runPD(t *testing.T, p *pdSrc, r *connectorv1.ReadPerDCRequest) (map[guid.GUID]*connectorv1.PerDcResult, *connectorv1.PerDcSummary, error) {
	t.Helper()
	h, err := read.New(p)
	if err != nil {
		t.Fatal(err)
	}
	return runPDH(t, h, r)
}

type pdSink struct {
	mu sync.Mutex
	ms []*connectorv1.ReadPerDCResponse
}

func (s *pdSink) Send(m *connectorv1.ReadPerDCResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ms = append(s.ms, m)
	return nil
}

func runPDH(t *testing.T, h *read.Handler, r *connectorv1.ReadPerDCRequest) (map[guid.GUID]*connectorv1.PerDcResult, *connectorv1.PerDcSummary, error) {
	t.Helper()
	s := &pdSink{}
	err := h.ReadPerDC(context.Background(), r, s)
	res := map[guid.GUID]*connectorv1.PerDcResult{}
	var sum *connectorv1.PerDcSummary
	for i, m := range s.ms {
		if m.GetSummary() != nil {
			if i != len(s.ms)-1 {
				t.Fatal("summary is not last")
			}
			sum = m.GetSummary()
			continue
		}
		d, _ := write.GUIDFromWire(m.GetResult().GetDc().GetDsaGuid())
		if _, dup := res[d]; dup {
			t.Fatal("two results for one DC")
		}
		res[d] = m.GetResult()
	}
	return res, sum, err
}

func timeOfResult(t *testing.T, r *connectorv1.PerDcResult, a connectorv1.PerDcAttribute) *connectorv1.TimeValue {
	t.Helper()
	for _, v := range r.GetValues().GetValues() {
		if v.GetAttribute() == a {
			return v.GetTime()
		}
	}
	t.Fatalf("no %v in %v", a, r)
	return nil
}

// CC-PDC-04: one result per DC, COMPLETE, and the maximum over the answers is the latest logon.
func TestPerDCCompleteExactMaximum(t *testing.T) {
	p := newPD(2)
	p.logon[dsa(1)] = strconv.FormatInt(ft2026, 10)
	p.logon[dsa(2)] = strconv.FormatInt(ft2026+600_000_000_0, 10) // 10 minutes later
	res, sum, err := runPD(t, p, pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || sum.GetDcsInScope() != 2 || sum.GetDcsAnswered() != 2 || sum.GetCoverage() != connectorv1.Coverage_COVERAGE_COMPLETE {
		t.Fatalf("%d results, summary %v", len(res), sum)
	}
	a1 := timeOfResult(t, res[dsa(1)], connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON).GetAt().AsTime()
	a2 := timeOfResult(t, res[dsa(2)], connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON).GetAt().AsTime()
	if a2.Sub(a1) != 10*time.Minute || a1.Year() != 2026 {
		t.Fatalf("times %v %v", a1, a2)
	}
}

// CC-PDC-01/02: absent lastLogon is ZERO (never a missing value); counts are integers.
func TestPerDCTypedValuesAndZero(t *testing.T) {
	p := newPD(1)
	res, sum, err := runPD(t, p, pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL))
	if err != nil || sum.GetCoverage() != connectorv1.Coverage_COVERAGE_COMPLETE {
		t.Fatalf("%v %v", err, sum)
	}
	if tv := timeOfResult(t, res[dsa(1)], connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON); tv.GetSentinel() != connectorv1.TimeSentinel_TIME_SENTINEL_ZERO {
		t.Fatalf("lastLogon %v", tv)
	}
	r := pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL, connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_BAD_PWD_COUNT)
	res, _, err = runPD(t, p, r)
	if err != nil {
		t.Fatal(err)
	}
	if v := res[dsa(1)].GetValues().GetValues(); len(v) != 1 || v[0].GetInteger() != 2 {
		t.Fatalf("badPwdCount %v", v)
	}
}

// CC-PDC-03 / 05: a DC that cannot answer is a result with an error, the summary is PARTIAL.
func TestPerDCPartialKeepsErroredDCs(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code connectorv1.ErrorCode
	}{
		"down":           {ad.NewError(ad.CodeUnreachable), connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC},
		"not replicated": {notFound(), connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND},
		"rights":         {ad.NewError(ad.CodeInsufficientRights), connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS},
	} {
		t.Run(name, func(t *testing.T) {
			p := newPD(3)
			p.errs[dsa(2)] = tc.err
			res, sum, err := runPD(t, p, pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL))
			if err != nil {
				t.Fatal(err)
			}
			if len(res) != 3 || sum.GetDcsInScope() != 3 || sum.GetDcsAnswered() != 2 || sum.GetCoverage() != connectorv1.Coverage_COVERAGE_PARTIAL {
				t.Fatalf("%d results, summary %v", len(res), sum)
			}
			if e := res[dsa(2)].GetError(); e.GetCode() != tc.code || res[dsa(2)].GetValues() != nil {
				t.Fatalf("error result %v", res[dsa(2)])
			}
			if res[dsa(2)].GetDc().GetDnsHostname() != "dc2.lab.test" {
				t.Fatalf("errored result does not name its DC: %v", res[dsa(2)].GetDc())
			}
		})
	}
}

// A host that now answers as another DC, or a server object with no name, is an error result.
func TestPerDCWrongOrNamelessDC(t *testing.T) {
	p := newPD(3)
	p.other[dsa(1)] = dsa(9)
	p.dcs[2].Host = ""
	res, sum, err := runPD(t, p, pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL))
	if err != nil {
		t.Fatal(err)
	}
	if sum.GetCoverage() != connectorv1.Coverage_COVERAGE_PARTIAL || sum.GetDcsAnswered() != 1 || len(res) != 3 {
		t.Fatalf("%d results, summary %v", len(res), sum)
	}
	for _, i := range []int{1, 3} {
		if res[dsa(i)].GetError().GetCode() != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC {
			t.Fatalf("dc%d: %v", i, res[dsa(i)])
		}
	}
	if string(res[dsa(1)].GetDc().GetDsaGuid().GetValue()) != string(write.GUIDToWire(dsa(1)).GetValue()) {
		t.Fatal("error result must name the listed DC, not the impostor")
	}
}

// CC-PDC-06 shape on fakes: WRITABLE leaves the RODC out of scope, ALL keeps it, an RODC of unknown
// state is never silently dropped.
func TestPerDCScope(t *testing.T) {
	p := newPD(3)
	p.dcs[1].RODC = true
	p.dcs[2].RODCKnown = false
	_, sum, err := runPD(t, p, pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_WRITABLE))
	if err != nil || sum.GetDcsInScope() != 2 {
		t.Fatalf("writable: %v %v", err, sum)
	}
	_, sum, err = runPD(t, p, pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL))
	if err != nil || sum.GetDcsInScope() != 3 {
		t.Fatalf("all: %v %v", err, sum)
	}
}

// CC-PDC-07: 20 DCs, several calls at once; one read per DC at a time, the domain cap holds, and
// max_concurrency can only lower it.
func TestPerDCConcurrencyCaps(t *testing.T) {
	p := newPD(20)
	p.hold = 10 * time.Millisecond
	h, err := read.New(p)
	if err != nil {
		t.Fatal(err)
	}
	h.WithPerDCLimits(1, 6)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, sum, err := runPDH(t, h, pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL))
			if err != nil || sum.GetCoverage() != connectorv1.Coverage_COVERAGE_COMPLETE {
				t.Errorf("%v %v", err, sum)
			}
		}()
	}
	wg.Wait()
	if n := p.total.Load(); n != 80 {
		t.Fatalf("%d reads", n)
	}
	for d, n := range p.peak {
		if n > 1 {
			t.Fatalf("%d reads in flight against one DC %v", n, d)
		}
	}

	// A request asks for 2: never more than 2 in flight in the call, however many DCs.
	q := newPD(20)
	q.hold = 10 * time.Millisecond
	h2, _ := read.New(q)
	r := pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL)
	r.MaxConcurrency = 2
	var inflight, peak atomic.Int32
	q.src = &src{dsa: dsaA}
	counting := &countSrc{pdSrc: q, in: &inflight, peak: &peak}
	h2, _ = read.New(counting)
	if _, sum, err := runPDH(t, h2, r); err != nil || sum.GetDcsAnswered() != 20 {
		t.Fatalf("%v %v", err, sum)
	}
	if peak.Load() != 2 {
		t.Fatalf("peak %d, want 2 (lowered by the request, not raised by the cap)", peak.Load())
	}
}

type countSrc struct {
	*pdSrc
	in, peak *atomic.Int32
}

func (c *countSrc) ReadOnDC(ctx context.Context, dc read.DC, id guid.GUID, attrs []string) (*ad.Entry, *connectorv1.DcIdentity, error) {
	n := c.in.Add(1)
	for {
		p := c.peak.Load()
		if n <= p || c.peak.CompareAndSwap(p, n) {
			break
		}
	}
	defer c.in.Add(-1)
	return c.pdSrc.ReadOnDC(ctx, dc, id, attrs)
}

func TestPerDCRefusals(t *testing.T) {
	code := func(err error) connectorv1.ErrorCode {
		var r *write.Refusal
		if err == nil {
			return connectorv1.ErrorCode_ERROR_CODE_UNSPECIFIED
		}
		if !asRefusal(err, &r) {
			t.Fatalf("not a refusal: %v", err)
		}
		return r.Err.GetCode()
	}
	base := func() *connectorv1.ReadPerDCRequest { return pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL) }
	for name, tc := range map[string]struct {
		mut  func(*connectorv1.ReadPerDCRequest)
		p    *pdSrc
		want connectorv1.ErrorCode
	}{
		"no attributes": {func(r *connectorv1.ReadPerDCRequest) { r.Attributes = nil }, newPD(1), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"unknown attr":  {func(r *connectorv1.ReadPerDCRequest) { r.Attributes = []connectorv1.PerDcAttribute{99} }, newPD(1), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"no scope":      {func(r *connectorv1.ReadPerDCRequest) { r.Scope = 0 }, newPD(1), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"bad guid":      {func(r *connectorv1.ReadPerDCRequest) { r.Guid = nil }, newPD(1), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"bad nc":        {func(r *connectorv1.ReadPerDCRequest) { r.NcGuid = nil }, newPD(1), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"no connection": {func(r *connectorv1.ReadPerDCRequest) { r.Connection = nil }, newPD(1), connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"other forest": {func(r *connectorv1.ReadPerDCRequest) {
			r.Connection.DirectoryIdentity = &connectorv1.DirectoryIdentity{}
		}, newPD(1), connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH},
		"no such domain": {func(*connectorv1.ReadPerDCRequest) {}, newPD(0), connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND},
		"101 DCs":        {func(*connectorv1.ReadPerDCRequest) {}, newPD(101), connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED},
		"list failed":    {func(*connectorv1.ReadPerDCRequest) {}, func() *pdSrc { p := newPD(1); p.listErr = ad.NewError(ad.CodeUnreachable); return p }(), connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC},
	} {
		t.Run(name, func(t *testing.T) {
			r := base()
			tc.mut(r)
			_, sum, err := runPD(t, tc.p, r)
			if got := code(err); got != tc.want || sum != nil {
				t.Fatalf("code %v summary %v, want %v", got, sum, tc.want)
			}
			if tc.p.total.Load() != 0 {
				t.Fatal("a refused call read a DC")
			}
		})
	}
}

// A Source without the per-DC half says so.
func TestPerDCUnsupported(t *testing.T) {
	h, _ := read.New(&src{dsa: dsaA})
	_, _, err := runPDH(t, h, pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL))
	if st, _ := status.FromError(err); st.Code() == codes.OK {
		t.Fatalf("served: %v", err)
	}
}

// Over the real gRPC hop the stream is results then one summary.
func TestPerDCOverGRPC(t *testing.T) {
	p := newPD(3)
	cl := start(t, p)
	st, err := cl.ReadPerDC(context.Background(), pdReq(connectorv1.PerDcScope_PER_DC_SCOPE_ALL))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	var sum *connectorv1.PerDcSummary
	for {
		m, err := st.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if m.GetSummary() != nil {
			sum = m.GetSummary()
		} else {
			n++
		}
	}
	if n != 3 || sum.GetCoverage() != connectorv1.Coverage_COVERAGE_COMPLETE {
		t.Fatalf("%d results, %v", n, sum)
	}
}
