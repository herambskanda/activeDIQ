package client_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	pdTenant  = "33333333-3333-4333-8333-333333333333"
	pdTenant2 = "44444444-4444-4444-8444-444444444444"
	pdUser    = "22222222-0000-4000-8000-00000000000a"
)

var pdAllAttrs = []report.PerDCAttr{report.PerDCLastLogon, report.PerDCLogonCount, report.PerDCBadPwdCount, report.PerDCBadPasswordTime, report.PerDCLockoutTime}

func pdCtx(tid string) context.Context { return authority.WithTenant(context.Background(), tid) }

func wireOf(t *testing.T, s string) []byte {
	t.Helper()
	// the dashed text is the wire (RFC 4122) order
	b := make([]byte, 0, 16)
	h := strings.ReplaceAll(s, "-", "")
	for i := 0; i < 32; i += 2 {
		var v byte
		for _, c := range []byte(h[i : i+2]) {
			v <<= 4
			if c >= 'a' {
				v |= c - 'a' + 10
			} else {
				v |= c - '0'
			}
		}
		b = append(b, v)
	}
	return b
}

func dcID(host string, n byte) *connectorv1.DcIdentity {
	dsa := make([]byte, 16)
	dsa[15] = n
	return &connectorv1.DcIdentity{DnsHostname: host, DsaGuid: &connectorv1.Guid{Value: dsa}}
}

func at(sec int64) *connectorv1.TimeValue {
	return &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_At{At: timestamppb.New(time.Unix(sec, 0))}}
}

func zeroT() *connectorv1.TimeValue {
	return &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_Sentinel{Sentinel: connectorv1.TimeSentinel_TIME_SENTINEL_ZERO}}
}

func timeVal(a connectorv1.PerDcAttribute, tv *connectorv1.TimeValue) *connectorv1.PerDcValue {
	return &connectorv1.PerDcValue{Attribute: a, Value: &connectorv1.PerDcValue_Time{Time: tv}}
}

func intVal(a connectorv1.PerDcAttribute, n int64) *connectorv1.PerDcValue {
	return &connectorv1.PerDcValue{Attribute: a, Value: &connectorv1.PerDcValue_Integer{Integer: n}}
}

// allVals is a complete answer for pdAllAttrs: lastLogon = sec.
func allVals(sec int64) []*connectorv1.PerDcValue {
	return []*connectorv1.PerDcValue{
		timeVal(connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON, at(sec)),
		intVal(connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LOGON_COUNT, sec),
		intVal(connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_BAD_PWD_COUNT, 1),
		timeVal(connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_BAD_PASSWORD_TIME, zeroT()),
		timeVal(connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LOCKOUT_TIME, zeroT()),
	}
}

func okResult(host string, n byte, vals []*connectorv1.PerDcValue) *connectorv1.ReadPerDCResponse {
	return &connectorv1.ReadPerDCResponse{Event: &connectorv1.ReadPerDCResponse_Result{Result: &connectorv1.PerDcResult{
		Dc: dcID(host, n), Outcome: &connectorv1.PerDcResult_Values{Values: &connectorv1.PerDcValues{Values: vals}},
	}}}
}

func errResult(host string, n byte, code connectorv1.ErrorCode, msg string) *connectorv1.ReadPerDCResponse {
	return &connectorv1.ReadPerDCResponse{Event: &connectorv1.ReadPerDCResponse_Result{Result: &connectorv1.PerDcResult{
		Dc: dcID(host, n), Outcome: &connectorv1.PerDcResult_Error{Error: &connectorv1.ConnectorError{Code: code, Message: msg}},
	}}}
}

func summary(scope, answered uint32, c connectorv1.Coverage) *connectorv1.ReadPerDCResponse {
	return &connectorv1.ReadPerDCResponse{Event: &connectorv1.ReadPerDCResponse_Summary{Summary: &connectorv1.PerDcSummary{
		DcsInScope: scope, DcsAnswered: answered, Coverage: c,
	}}}
}

var (
	complete = connectorv1.Coverage_COVERAGE_COMPLETE
	partial  = connectorv1.Coverage_COVERAGE_PARTIAL
)

// pdServer is a connector server whose ReadPerDC is scripted per call. It is reached over a real
// gRPC hop (marshalling, status errors with details, streaming).
type pdServer struct {
	connectorv1.UnimplementedConnectorServer
	script func(req *connectorv1.ReadPerDCRequest) ([]*connectorv1.ReadPerDCResponse, error)

	mu      sync.Mutex
	reqs    []*connectorv1.ReadPerDCRequest
	cur     atomic.Int32
	maxSeen atomic.Int32
	hold    time.Duration
}

func (s *pdServer) ReadPerDC(req *connectorv1.ReadPerDCRequest, st grpc.ServerStreamingServer[connectorv1.ReadPerDCResponse]) error {
	n := s.cur.Add(1)
	defer s.cur.Add(-1)
	for {
		m := s.maxSeen.Load()
		if n <= m || s.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	s.mu.Lock()
	s.reqs = append(s.reqs, req)
	s.mu.Unlock()
	if s.hold > 0 {
		time.Sleep(s.hold)
	}
	msgs, err := s.script(req)
	for _, m := range msgs {
		if e := st.Send(m); e != nil {
			return e
		}
	}
	return err
}

type pdSource struct{ c connectorv1.ConnectorClient }

func (s pdSource) Connector(context.Context, string) (connectorv1.ConnectorClient, error) {
	return s.c, nil
}

func serve(t *testing.T, srv *pdServer) client.GRPCPerDCTransport {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	connectorv1.RegisterConnectorServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	cc, err := grpc.NewClient("passthrough:///perdc", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close(); gs.Stop() })
	tr, err := client.NewGRPCPerDCTransport(pdSource{connectorv1.NewConnectorClient(cc)})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func reader(t *testing.T, tr client.PerDCTransport, cfg client.PerDCConfig) *client.ConnectorPerDC {
	t.Helper()
	r, err := client.NewConnectorPerDC(conns{}, tr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func three(sec int64) []*connectorv1.ReadPerDCResponse {
	return []*connectorv1.ReadPerDCResponse{
		okResult("dc1.corp.example", 1, allVals(sec)),
		okResult("dc2.corp.example", 2, allVals(sec+10)),
		okResult("dc3.corp.example", 3, allVals(sec+5)),
		summary(3, 3, complete),
	}
}

// AC-39: three DCs all answer: three values and COMPLETE. The request carries the wire (RFC 4122)
// GUID order, the connection's forest identity and only enum attributes.
func TestReadPerDCAllAnswer(t *testing.T) {
	srv := &pdServer{script: func(*connectorv1.ReadPerDCRequest) ([]*connectorv1.ReadPerDCResponse, error) { return three(1000), nil }}
	r := reader(t, serve(t, srv), client.PerDCConfig{})
	obj, sum, err := r.ReadPerDC(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), oid(t, pdUser), pdAllAttrs, report.ScopeWritable)
	if err != nil {
		t.Fatal(err)
	}
	if sum != (report.PerDCSummary{DCsInScope: 3, DCsAnswered: 3, Coverage: report.CoverageComplete}) {
		t.Fatalf("summary = %+v", sum)
	}
	if obj.Object != oid(t, pdUser) || len(obj.Results) != 3 {
		t.Fatalf("object = %+v", obj)
	}
	var latest time.Time
	for i, res := range obj.Results {
		if res.Err != "" || len(res.Values) != 5 {
			t.Fatalf("result %d = %+v", i, res)
		}
		if res.Values[0].Attr != report.PerDCLastLogon || res.Values[0].Time.IsZero() {
			t.Fatalf("values = %+v", res.Values)
		}
		if res.Values[0].Time.After(latest) {
			latest = res.Values[0].Time
		}
		if !res.Values[3].Time.IsZero() || res.Values[1].Int == 0 {
			t.Fatalf("sentinel/int mapping: %+v", res.Values)
		}
	}
	if !latest.Equal(time.Unix(1010, 0)) {
		t.Fatalf("latest = %v", latest)
	}
	if obj.Results[0].DC != "dc1.corp.example" || obj.Results[2].DC != "dc3.corp.example" {
		t.Fatalf("results not sorted by DC: %+v", obj.Results)
	}
	if r.Reads() != 1 {
		t.Fatalf("reads = %d", r.Reads())
	}

	req := srv.reqs[0]
	if string(req.GetGuid().GetValue()) != string(wireOf(t, pdUser)) || string(req.GetNcGuid().GetValue()) != string(wireOf(t, gH)) {
		t.Fatalf("guid order on the wire: %x / %x", req.GetGuid().GetValue(), req.GetNcGuid().GetValue())
	}
	if req.GetConnection().GetConnectionId() != connUUID || req.GetConnection().GetDirectoryIdentity().GetAdForest() == nil {
		t.Fatalf("connection ref = %+v", req.GetConnection())
	}
	if req.GetScope() != connectorv1.PerDcScope_PER_DC_SCOPE_WRITABLE || len(req.GetAttributes()) != 5 || req.GetMaxConcurrency() != client.DefaultPerDCFanOut {
		t.Fatalf("request = %+v", req)
	}
}

// AC-40: one DC unreachable: two values, 2 of 3, and the failed DC with a fixed code - never the
// connector's message.
func TestReadPerDCOneDCDown(t *testing.T) {
	srv := &pdServer{script: func(*connectorv1.ReadPerDCRequest) ([]*connectorv1.ReadPerDCResponse, error) {
		return []*connectorv1.ReadPerDCResponse{
			okResult("dc1.corp.example", 1, allVals(1000)),
			errResult("dc2.corp.example", 2, connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, "dial tcp 10.9.8.7:636: i/o timeout bind=svc-activediq"),
			okResult("dc3.corp.example", 3, allVals(2000)),
			summary(3, 2, partial),
		}, nil
	}}
	r := reader(t, serve(t, srv), client.PerDCConfig{})
	obj, sum, err := r.ReadPerDC(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), oid(t, pdUser), pdAllAttrs, report.ScopeAll)
	if err != nil {
		t.Fatal(err)
	}
	if sum != (report.PerDCSummary{DCsInScope: 3, DCsAnswered: 2, Coverage: report.CoveragePartial}) {
		t.Fatalf("summary = %+v", sum)
	}
	var answered int
	var failed []report.PerDCResult
	for _, res := range obj.Results {
		if res.Err == "" {
			answered++
		} else {
			failed = append(failed, res)
		}
	}
	if answered != 2 || len(failed) != 1 || failed[0].DC != "dc2.corp.example" || failed[0].Err != "unreachable_dc" || len(failed[0].Values) != 0 {
		t.Fatalf("results = %+v", obj.Results)
	}
	if strings.Contains(failed[0].Err, "10.9.8.7") || strings.Contains(failed[0].Err, "svc-activediq") {
		t.Fatal("connector message leaked into the per-DC error")
	}
}

// A call that fails as a whole (the connector is down) is an error and carries no partial answer; a
// typed connector error keeps its code, a bare status keeps none of its text.
func TestReadPerDCCallFailure(t *testing.T) {
	typed, _ := status.New(codes.Unavailable, "dc01.corp unreachable").WithDetails(&connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC})
	for name, e := range map[string]error{"typed": typed.Err(), "bare": status.Error(codes.Internal, "secret-host-17 exploded")} {
		srv := &pdServer{script: func(*connectorv1.ReadPerDCRequest) ([]*connectorv1.ReadPerDCResponse, error) { return nil, e }}
		r := reader(t, serve(t, srv), client.PerDCConfig{})
		objs, sum, err := r.Read(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), []authz.ObjectID{oid(t, pdUser)}, pdAllAttrs, report.ScopeAll)
		if err == nil || objs != nil || sum != (report.PerDCSummary{}) {
			t.Fatalf("%s: got (%v, %+v, %v)", name, objs, sum, err)
		}
		if strings.Contains(err.Error(), "secret-host") || strings.Contains(err.Error(), "dc01") {
			t.Fatalf("%s: error leaks connector text: %v", name, err)
		}
		if name == "typed" && !strings.Contains(err.Error(), "UNREACHABLE_DC") {
			t.Fatalf("typed code lost: %v", err)
		}
	}
}

// AC (bound): with a bound of N no more than N reads are in flight for the tenant, even across
// concurrent Read calls, and every object is read once.
func TestReadPerDCBoundedInFlight(t *testing.T) {
	const n, objects = 3, 40
	srv := &pdServer{hold: 5 * time.Millisecond, script: func(*connectorv1.ReadPerDCRequest) ([]*connectorv1.ReadPerDCResponse, error) { return three(1000), nil }}
	r := reader(t, serve(t, srv), client.PerDCConfig{InFlight: n})
	ids := make([]authz.ObjectID, objects)
	for i := range ids {
		ids[i] = authz.ObjectID{byte(i + 1), 7}
	}
	var wg sync.WaitGroup
	for half := 0; half < 2; half++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			objs, sum, err := r.Read(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), ids[half*20:half*20+20], pdAllAttrs, report.ScopeWritable)
			if err != nil || len(objs) != 20 || sum.Coverage != report.CoverageComplete {
				t.Errorf("read: %v %d %+v", err, len(objs), sum)
			}
			for i, o := range objs {
				if o.Object != ids[half*20+i] {
					t.Errorf("order lost at %d", i)
				}
			}
		}()
	}
	wg.Wait()
	if got := srv.maxSeen.Load(); got > n || got < 2 {
		t.Fatalf("max in flight = %d, want 2..%d", got, n)
	}
	if r.Reads() != objects {
		t.Fatalf("reads = %d", r.Reads())
	}
}

// The bound is per tenant: a tenant at its limit does not starve another.
func TestReadPerDCBoundIsPerTenant(t *testing.T) {
	release := make(chan struct{})
	var started atomic.Int32
	srv := &pdServer{script: func(*connectorv1.ReadPerDCRequest) ([]*connectorv1.ReadPerDCResponse, error) {
		started.Add(1)
		<-release
		return three(1000), nil
	}}
	r := reader(t, serve(t, srv), client.PerDCConfig{InFlight: 1})
	ctxA, cancelA := context.WithCancel(pdCtx(pdTenant))
	defer cancelA()
	doneA := make(chan struct{})
	go func() {
		defer close(doneA)
		_, _, _ = r.ReadPerDC(ctxA, oid(t, connUUID), oid(t, gH), oid(t, pdUser), pdAllAttrs, report.ScopeAll)
	}()
	for started.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	doneB := make(chan error, 1)
	go func() {
		_, _, err := r.ReadPerDC(pdCtx(pdTenant2), oid(t, connUUID), oid(t, gH), oid(t, pdUser), pdAllAttrs, report.ScopeAll)
		doneB <- err
	}()
	for started.Load() < 2 {
		time.Sleep(time.Millisecond) // tenant 2 got its own slot while tenant 1 holds its only one
	}
	close(release)
	if err := <-doneB; err != nil {
		t.Fatal(err)
	}
	<-doneA
}

// A cancelled context stops the fan-out and returns an error, with no read left in flight.
func TestReadPerDCCancel(t *testing.T) {
	srv := &pdServer{hold: 200 * time.Millisecond, script: func(*connectorv1.ReadPerDCRequest) ([]*connectorv1.ReadPerDCResponse, error) { return three(1), nil }}
	r := reader(t, serve(t, srv), client.PerDCConfig{InFlight: 2})
	ctx, cancel := context.WithTimeout(pdCtx(pdTenant), 50*time.Millisecond)
	defer cancel()
	ids := make([]authz.ObjectID, 30)
	for i := range ids {
		ids[i] = authz.ObjectID{byte(i + 1), 9}
	}
	_, _, err := r.Read(ctx, oid(t, connUUID), oid(t, gH), ids, pdAllAttrs, report.ScopeAll)
	if err == nil {
		t.Fatal("cancelled read succeeded")
	}
	if r.Reads() >= 30 {
		t.Fatalf("fan-out did not stop: %d reads", r.Reads())
	}
}

type countingTransport struct {
	calls atomic.Int32
	resp  []*connectorv1.ReadPerDCResponse
	err   error
}

type sliceStream struct {
	m   []*connectorv1.ReadPerDCResponse
	err error
}

func (s *sliceStream) Recv() (*connectorv1.ReadPerDCResponse, error) {
	if len(s.m) == 0 {
		if s.err != nil {
			return nil, s.err
		}
		return nil, io.EOF
	}
	m := s.m[0]
	s.m = s.m[1:]
	return m, nil
}

func (c *countingTransport) ReadPerDC(context.Context, *connectorv1.ReadPerDCRequest) (client.PerDCStream, error) {
	c.calls.Add(1)
	return &sliceStream{m: append([]*connectorv1.ReadPerDCResponse(nil), c.resp...), err: c.err}, nil
}

// AC: a hostile attribute is refused before anything is sent. There is no string path: an attribute
// is the closed report.PerDCAttr, and anything outside it - an undefined number, the zero value,
// a duplicate, none, too many - is an error.
func TestReadPerDCRefusesHostileAttributes(t *testing.T) {
	tr := &countingTransport{resp: three(1)}
	r := reader(t, tr, client.PerDCConfig{})
	cases := map[string][]report.PerDCAttr{
		"zero":      {0},
		"undefined": {report.PerDCAttr(6)},
		"large":     {report.PerDCAttr(255)},
		"valid+bad": {report.PerDCLastLogon, report.PerDCAttr(200)},
		"duplicate": {report.PerDCLastLogon, report.PerDCLastLogon},
		"none":      nil,
		"too many":  {1, 2, 3, 4, 5, 1},
	}
	for name, attrs := range cases {
		_, _, err := r.Read(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), []authz.ObjectID{oid(t, pdUser)}, attrs, report.ScopeAll)
		if !errors.Is(err, client.ErrInvalidOp) || !errors.Is(err, client.ErrPerDCAttr) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for _, sc := range []report.PerDCScope{0, 3, 255} {
		_, _, err := r.Read(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), []authz.ObjectID{oid(t, pdUser)}, pdAllAttrs, sc)
		if !errors.Is(err, client.ErrPerDCScope) {
			t.Errorf("scope %d: err = %v", sc, err)
		}
	}
	if tr.calls.Load() != 0 || r.Reads() != 0 {
		t.Fatalf("a refused request reached the connector: %d calls", tr.calls.Load())
	}
}

func TestReadPerDCRefusesBadInputs(t *testing.T) {
	tr := &countingTransport{resp: three(1)}
	r := reader(t, tr, client.PerDCConfig{})
	one := []authz.ObjectID{oid(t, pdUser)}
	if _, _, err := r.Read(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), nil, pdAllAttrs, report.ScopeAll); !errors.Is(err, client.ErrPerDCObjects) {
		t.Errorf("no objects: %v", err)
	}
	if _, _, err := r.Read(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), []authz.ObjectID{{}}, pdAllAttrs, report.ScopeAll); !errors.Is(err, client.ErrInvalidOp) {
		t.Errorf("zero object: %v", err)
	}
	if _, _, err := r.Read(pdCtx(pdTenant), authz.ObjectID{}, oid(t, gH), one, pdAllAttrs, report.ScopeAll); !errors.Is(err, client.ErrInvalidOp) {
		t.Errorf("zero connection: %v", err)
	}
	if _, _, err := r.Read(context.Background(), oid(t, connUUID), oid(t, gH), one, pdAllAttrs, report.ScopeAll); !errors.Is(err, client.ErrReadTenant) {
		t.Errorf("no tenant: %v", err)
	}
	if tr.calls.Load() != 0 {
		t.Fatal("reached the connector")
	}
}

type pdConns struct {
	c   connection.Connection
	err error
}

func (f pdConns) Get(context.Context, tenant.ID, connection.ID) (connection.Connection, error) {
	return f.c, f.err
}

func TestReadPerDCConnectionGate(t *testing.T) {
	now := time.Now()
	good := connection.Connection{ID: connUUID, Kind: connection.KindADForest, State: connection.StateActive, DirectoryIdentity: gH}
	cases := map[string]struct {
		c    pdConns
		want error
	}{
		"unknown":    {pdConns{err: errors.New("not found")}, client.ErrReadConnection},
		"other id":   {pdConns{c: connection.Connection{ID: "c0c0c0c0-0000-4000-8000-0000000000ff", Kind: connection.KindADForest, DirectoryIdentity: gH}}, client.ErrReadConnection},
		"retired":    {pdConns{c: func() connection.Connection { c := good; c.RetiredAt = &now; return c }()}, client.ErrReadConnection},
		"entra":      {pdConns{c: connection.Connection{ID: connUUID, Kind: connection.KindEntraTenant, DirectoryIdentity: "t"}}, client.ErrReadConnection},
		"unverified": {pdConns{c: connection.Connection{ID: connUUID, Kind: connection.KindADForest}}, client.ErrReadDirectory},
	}
	for name, tc := range cases {
		tr := &countingTransport{resp: three(1)}
		r, err := client.NewConnectorPerDC(tc.c, tr, client.PerDCConfig{})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = r.ReadPerDC(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), oid(t, pdUser), pdAllAttrs, report.ScopeAll)
		if !errors.Is(err, tc.want) || tr.calls.Load() != 0 {
			t.Errorf("%s: err = %v, calls = %d", name, err, tr.calls.Load())
		}
	}
}

func TestNewConnectorPerDCRequiresPorts(t *testing.T) {
	tr := &countingTransport{}
	if _, err := client.NewConnectorPerDC(nil, tr, client.PerDCConfig{}); err == nil {
		t.Error("nil connections accepted")
	}
	if _, err := client.NewConnectorPerDC(conns{}, nil, client.PerDCConfig{}); !errors.Is(err, client.ErrNoPerDCTransport) {
		t.Errorf("nil transport: %v", err)
	}
	for _, cfg := range []client.PerDCConfig{{InFlight: client.MaxPerDCInFlight + 1}, {FanOut: client.MaxPerDCFanOut + 1}, {InFlight: -1}, {FanOut: -1}} {
		if _, err := client.NewConnectorPerDC(conns{}, tr, cfg); err == nil {
			t.Errorf("config %+v accepted", cfg)
		}
	}
	if _, err := client.NewGRPCPerDCTransport(nil); err == nil {
		t.Error("nil connector source accepted")
	}
}

// The stream is checked, not trusted: every deviation from "results, one summary, end" is a protocol
// error or a demoted DC, and coverage is never higher than the answers accepted.
func TestReadPerDCStreamContract(t *testing.T) {
	short := allVals(1)[:3]
	badKind := append([]*connectorv1.PerDcValue{intVal(connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON, 5)}, allVals(1)[1:]...)
	maxT := append([]*connectorv1.PerDcValue{timeVal(connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON,
		&connectorv1.TimeValue{Kind: &connectorv1.TimeValue_Sentinel{Sentinel: connectorv1.TimeSentinel_TIME_SENTINEL_MAX}})}, allVals(1)[1:]...)
	twice := append(allVals(1), timeVal(connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON, at(3)))
	type tc struct {
		name     string
		resp     []*connectorv1.ReadPerDCResponse
		streamEr error
		proto    bool
		answered uint32
		errCode  string // expected code of dc2
	}
	cases := []tc{
		{name: "no summary", resp: three(1)[:3], proto: true},
		{name: "empty stream", proto: true},
		{name: "result after summary", resp: append(three(1), okResult("dc4", 4, allVals(1))), proto: true},
		{name: "two summaries", resp: append(three(1), summary(3, 3, complete)), proto: true},
		{name: "scope count differs from results", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), summary(2, 1, partial)}, proto: true},
		{name: "complete but not all answered", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), errResult("dc2", 2, connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, ""), summary(2, 1, complete)}, proto: true},
		{name: "partial but all answered", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), summary(1, 1, partial)}, proto: true},
		{name: "unspecified coverage", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), summary(1, 1, 0)}, proto: true},
		{name: "answered above scope", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), summary(1, 2, partial)}, proto: true},
		{name: "zero DCs complete", resp: []*connectorv1.ReadPerDCResponse{summary(0, 0, complete)}, proto: true},
		{name: "same DC twice", resp: []*connectorv1.ReadPerDCResponse{okResult("DC1.corp", 1, allVals(1)), okResult("dc1.CORP", 1, allVals(1)), summary(2, 2, complete)}, proto: true},
		{name: "DC without identity", resp: []*connectorv1.ReadPerDCResponse{{Event: &connectorv1.ReadPerDCResponse_Result{Result: &connectorv1.PerDcResult{
			Outcome: &connectorv1.PerDcResult_Values{Values: &connectorv1.PerDcValues{Values: allVals(1)}}}}}, summary(1, 1, complete)}, proto: true},
		{name: "markup in DC name", resp: []*connectorv1.ReadPerDCResponse{okResult("<script>alert(1)</script>", 1, allVals(1)), summary(1, 1, complete)}, proto: true},
		{name: "control in DC name", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1\n.corp", 1, allVals(1)), summary(1, 1, complete)}, proto: true},
		{name: "empty event", resp: []*connectorv1.ReadPerDCResponse{{}}, proto: true},
		{name: "outcome missing", resp: []*connectorv1.ReadPerDCResponse{{Event: &connectorv1.ReadPerDCResponse_Result{Result: &connectorv1.PerDcResult{Dc: dcID("dc1", 1)}}}, summary(1, 0, partial)}, proto: true},

		// Value problems demote the DC to an error and the batch to PARTIAL, even if the connector said COMPLETE.
		{name: "omitted attribute is not 'not set'", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), okResult("dc2", 2, short), summary(2, 2, complete)}, answered: 1, errCode: "incomplete_values"},
		{name: "wrong value kind", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), okResult("dc2", 2, badKind), summary(2, 2, complete)}, answered: 1, errCode: "invalid_value"},
		{name: "MAX is not a last logon", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), okResult("dc2", 2, maxT), summary(2, 2, complete)}, answered: 1, errCode: "invalid_value"},
		{name: "attribute twice", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), okResult("dc2", 2, twice), summary(2, 2, complete)}, answered: 1, errCode: "invalid_value"},
		{name: "attribute not asked", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), okResult("dc2", 2, append(allVals(1), intVal(0, 1))), summary(2, 2, complete)}, answered: 1, errCode: "invalid_value"},
		{name: "unknown error code", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), errResult("dc2", 2, 9999, "x"), summary(2, 1, partial)}, answered: 1, errCode: "unknown"},
		{name: "not yet replicated", resp: []*connectorv1.ReadPerDCResponse{okResult("dc1", 1, allVals(1)), errResult("dc2", 2, connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND, ""), summary(2, 1, partial)}, answered: 1, errCode: "object_not_found"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := reader(t, &countingTransport{resp: c.resp, err: c.streamEr}, client.PerDCConfig{})
			obj, sum, err := r.ReadPerDC(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), oid(t, pdUser), pdAllAttrs, report.ScopeAll)
			if c.proto {
				if !errors.Is(err, client.ErrReadProtocol) {
					t.Fatalf("err = %v, obj = %+v", err, obj)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if sum.Coverage != report.CoveragePartial || sum.DCsAnswered != c.answered || sum.DCsInScope != 2 {
				t.Fatalf("summary = %+v", sum)
			}
			if obj.Results[1].DC != "dc2" || obj.Results[1].Err != c.errCode || len(obj.Results[1].Values) != 0 {
				t.Fatalf("dc2 = %+v", obj.Results[1])
			}
		})
	}
}

// An object the connector reports as gone is an answer with no DCs and PARTIAL coverage, never a
// COMPLETE zero; the rest of the batch is unaffected.
func TestReadPerDCObjectGone(t *testing.T) {
	gone := oid(t, "22222222-0000-4000-8000-0000000000ff")
	nf, _ := status.New(codes.NotFound, "x").WithDetails(&connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND})
	srv := &pdServer{script: func(req *connectorv1.ReadPerDCRequest) ([]*connectorv1.ReadPerDCResponse, error) {
		if req.GetGuid().GetValue()[15] == 0xff {
			return nil, nf.Err()
		}
		return three(1000), nil
	}}
	r := reader(t, serve(t, srv), client.PerDCConfig{})
	objs, sum, err := r.Read(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH), []authz.ObjectID{oid(t, pdUser), gone}, pdAllAttrs, report.ScopeAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(objs[0].Results) != 3 || len(objs[1].Results) != 0 || objs[1].Object != gone {
		t.Fatalf("objects = %+v", objs)
	}
	if sum.Coverage != report.CoveragePartial || sum.DCsInScope != 3 || sum.DCsAnswered != 0 {
		t.Fatalf("summary = %+v", sum)
	}
}

// Across a batch the summary is the weakest object's: one object that saw a DC fewer makes the
// batch PARTIAL with the smallest answered count.
func TestReadPerDCBatchSummaryIsWeakest(t *testing.T) {
	srv := &pdServer{script: func(req *connectorv1.ReadPerDCRequest) ([]*connectorv1.ReadPerDCResponse, error) {
		if req.GetGuid().GetValue()[15] == 0x0b {
			return []*connectorv1.ReadPerDCResponse{okResult("dc1.corp.example", 1, allVals(1)), errResult("dc2.corp.example", 2, connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC, ""), okResult("dc3.corp.example", 3, allVals(1)), summary(3, 2, partial)}, nil
		}
		return three(1), nil
	}}
	r := reader(t, serve(t, srv), client.PerDCConfig{})
	objs, sum, err := r.Read(pdCtx(pdTenant), oid(t, connUUID), oid(t, gH),
		[]authz.ObjectID{oid(t, "22222222-0000-4000-8000-00000000000a"), oid(t, "22222222-0000-4000-8000-00000000000b")}, pdAllAttrs, report.ScopeAll)
	if err != nil || len(objs) != 2 {
		t.Fatal(err)
	}
	if sum != (report.PerDCSummary{DCsInScope: 3, DCsAnswered: 2, Coverage: report.CoveragePartial}) {
		t.Fatalf("summary = %+v", sum)
	}
}
