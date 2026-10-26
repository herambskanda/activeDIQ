package write

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

var t0time = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func mk(n byte) guid.GUID {
	b := make([]byte, 16)
	b[0], b[15] = n, 1
	g, err := guid.FromBytes(b)
	if err != nil {
		panic(err)
	}
	return g
}

func adIdentity() *connectorv1.DirectoryIdentity {
	return &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: toWire(mk(200))}}}
}

// fakeProv is a call-recording Provider. It has no write method at all: what it records is every
// read the guard asked for, so "no directory call" is len(calls)==0.
type fakeProv struct {
	mu       sync.Mutex
	kind     connectorv1.ProviderKind
	calls    []string
	tier0    map[guid.GUID][]Basis
	classErr map[guid.GUID]error
	anchors  map[guid.GUID]Anchors
	anchErr  error
	// afterErr makes Classify fail once the first Apply write has happened (step 9).
	failAfter *bool
	// members maps a designated group to its live members; Classify returns tier0 Designated for a
	// member of any designated group it is passed, and records what it was passed.
	members map[guid.GUID][]guid.GUID
	seenDes [][]guid.GUID
	// guard is what PropertyGuard returns; nil means the refuse-everything guard.
	guard    PropertyGuard
	guardErr error
	// bound is the DC identity BoundDC answers; boundErr makes it unreadable. dcReads counts the
	// reads (kept out of calls: it is not a read of an object).
	bound    *connectorv1.DcIdentity
	boundErr error
	dcReads  int
}

func newFake() *fakeProv {
	return &fakeProv{kind: connectorv1.ProviderKind_PROVIDER_KIND_AD, tier0: map[guid.GUID][]Basis{},
		classErr: map[guid.GUID]error{}, anchors: map[guid.GUID]Anchors{}, bound: testDC()}
}

// testDC is the DC every AD fixture is bound to and pins.
func testDC() *connectorv1.DcIdentity {
	return &connectorv1.DcIdentity{DsaGuid: toWire(mk(240)), InvocationId: toWire(mk(241)), DnsHostname: "dc1.corp.example", Site: "Default-First-Site-Name"}
}

func (f *fakeProv) BoundDC(context.Context) (*connectorv1.DcIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dcReads++
	return f.bound, f.boundErr
}

func (f *fakeProv) Kind() connectorv1.ProviderKind { return f.kind }
func (f *fakeProv) Identity() *connectorv1.DirectoryIdentity {
	return adIdentity()
}
func (f *fakeProv) Classify(_ context.Context, id guid.GUID, designated []guid.GUID) (Verdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "classify")
	f.seenDes = append(f.seenDes, designated)
	for _, d := range designated {
		for _, m := range f.members[d] {
			if m == id {
				return Verdict{Tier0: true, Bases: []Basis{tier0.Designated}}, nil
			}
		}
	}
	if f.failAfter != nil && *f.failAfter {
		return Verdict{Tier0: true}, errors.New("dc unreachable")
	}
	if err := f.classErr[id]; err != nil {
		return Verdict{Tier0: true}, err
	}
	if b, ok := f.tier0[id]; ok {
		return Verdict{Tier0: true, Bases: b}, nil
	}
	return Verdict{}, nil
}
func (f *fakeProv) Anchors(_ context.Context, id guid.GUID) (Anchors, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "anchors")
	return f.anchors[id], f.anchErr
}
func (f *fakeProv) PropertyGuard(context.Context) (PropertyGuard, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "propguard")
	if f.guardErr != nil {
		return nil, f.guardErr
	}
	if f.guard == nil {
		return (*tier0.Set)(nil), nil
	}
	return f.guard, nil
}
func (f *fakeProv) n() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

type memBaseline struct {
	mu   sync.Mutex
	fail bool
	got  []Mark
}

func (m *memBaseline) Append(_ string, marks []Mark) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("disk full")
	}
	m.got = append(m.got, marks...)
	return nil
}

type memRecorder struct {
	mu sync.Mutex
	ev []Event
}

func (r *memRecorder) Record(e Event) { r.mu.Lock(); r.ev = append(r.ev, e); r.mu.Unlock() }
func (r *memRecorder) last() Event    { r.mu.Lock(); defer r.mu.Unlock(); return r.ev[len(r.ev)-1] }

const connID = "conn-1"

type rig struct {
	h    *Handler
	prov *fakeProv
	gate *GateBook
	base *memBaseline
	rec  *memRecorder
	now  time.Time
}

func passRun(set map[string][]Basis) Run {
	return Run{VerificationID: toWire(mk(99)).Value, CompletedAt: t0time, Verdict: connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS,
		Checks: map[connectorv1.VerificationCheck]connectorv1.CheckOutcome{
			connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE:   connectorv1.CheckOutcome_CHECK_OUTCOME_PASS,
			connectorv1.VerificationCheck_VERIFICATION_CHECK_V8_READ_SUFFICIENCY: connectorv1.CheckOutcome_CHECK_OUTCOME_PASS},
		Set: set}
}

func newRig(t *testing.T, run *Run) *rig {
	t.Helper()
	r := &rig{prov: newFake(), base: &memBaseline{}, rec: &memRecorder{}, now: t0time}
	var err error
	r.gate, err = NewGateBook(r.base, func() time.Time { return r.now })
	if err != nil {
		t.Fatal(err)
	}
	if run != nil {
		r.gate.Complete(connID, *run)
	}
	r.h, err = New(r.prov, r.gate, WithRecorder(r.rec), WithClock(func() time.Time { return r.now }))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func noLink(id guid.GUID, at time.Time) *connectorv1.CorrelationStatement {
	return &connectorv1.CorrelationStatement{Object: toWire(id), ComputedAt: timestamppb.New(at),
		Correlation: &connectorv1.CorrelationStatement_NoHybridLink{NoHybridLink: &connectorv1.NoHybridLink{}}}
}

func peersStmt(id guid.GUID, at time.Time, ps ...*connectorv1.CorrelatedPeer) *connectorv1.CorrelationStatement {
	return &connectorv1.CorrelationStatement{Object: toWire(id), ComputedAt: timestamppb.New(at),
		Correlation: &connectorv1.CorrelationStatement_Peers{Peers: &connectorv1.CorrelatedPeers{Peers: ps}}}
}

func goodPeer(isT0 bool) *connectorv1.CorrelatedPeer {
	p := &connectorv1.CorrelatedPeer{PeerKind: connectorv1.ProviderKind_PROVIDER_KIND_ENTRA, State: connectorv1.CorrelationState_CORRELATION_STATE_MATCHED,
		Evidence: &connectorv1.CorrelationEvidence{Evidence: &connectorv1.CorrelationEvidence_SourceAnchor{SourceAnchor: []byte("anchor")}}}
	if isT0 {
		p.PeerTier0, p.PeerTier0Basis = true, []connectorv1.Tier0Basis{tier0.E1}
	}
	return p
}

func ctxFor(ids ...guid.GUID) *connectorv1.Tier0Context {
	c := &connectorv1.Tier0Context{Tier0Revision: 7}
	for _, id := range ids {
		c.Statements = append(c.Statements, noLink(id, t0time))
	}
	return c
}

func planReq(target guid.GUID, c *connectorv1.Tier0Context) *connectorv1.PlanRequest {
	return &connectorv1.PlanRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: connID, DirectoryIdentity: adIdentity()},
		Step:       &connectorv1.StepKey{OperationId: toWire(mk(50)), Item: 1, Step: 2},
		Target:     &connectorv1.WriteTarget{Object: toWire(target)}, Tier0: c,
		Dc:              &connectorv1.DcSelection{PinnedDsaGuid: testDC().GetDsaGuid()},
		ActingPrincipal: &connectorv1.ActingPrincipal{AccountId: toWire(mk(51))}}
}

func applyReq(target guid.GUID, c *connectorv1.Tier0Context) *connectorv1.ApplyRequest {
	return &connectorv1.ApplyRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: connID, DirectoryIdentity: adIdentity()},
		Step:       &connectorv1.StepKey{OperationId: toWire(mk(50)), Item: 1, Step: 2}, Attempt: 1,
		Target: &connectorv1.WriteTarget{Object: toWire(target)}, Tier0: c,
		Precondition: &connectorv1.TargetPrecondition{Dc: testDC(), StateDigest: []byte("d")}, PlanDigest: []byte("digest"),
		ActingPrincipal: &connectorv1.ActingPrincipal{AccountId: toWire(mk(51))}}
}

// transport is Plan and Apply as the server's client sees them.
type transport interface {
	Plan(context.Context, *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error)
	Apply(context.Context, *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error)
}

type grpcT struct{ c connectorv1.ConnectorClient }

func (g grpcT) Plan(ctx context.Context, r *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	return g.c.Plan(ctx, r)
}
func (g grpcT) Apply(ctx context.Context, r *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	return g.c.Apply(ctx, r)
}

// transports returns the in-process transport and a real gRPC one over an in-memory listener.
func transports(t *testing.T, h *Handler) map[string]transport {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	s := grpc.NewServer()
	Register(s, h)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	cc, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return map[string]transport{"in-process": h, "grpc": grpcT{connectorv1.NewConnectorClient(cc)}}
}

// connErr extracts the ConnectorError from an error of either transport, the way the client does.
func connErr(t *testing.T, err error) *connectorv1.ConnectorError {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got success")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("not a status error: %v", err)
	}
	for _, d := range st.Details() {
		if ce, ok := d.(*connectorv1.ConnectorError); ok {
			return ce
		}
	}
	t.Fatalf("status carries no ConnectorError: %v", err)
	return nil
}

func wantTier0(t *testing.T, err error, st connectorv1.Tier0RefusalStage) *connectorv1.Tier0RefusedDetails {
	t.Helper()
	ce := connErr(t, err)
	if ce.GetCode() != connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED || ce.GetTier0Refused().GetStage() != st {
		t.Fatalf("got %s stage %s, want TIER0_REFUSED %s", ce.GetCode(), ce.GetTier0Refused().GetStage(), st)
	}
	return ce.GetTier0Refused()
}

type guidT = guid.GUID

func ptr[T any](v T) *T { return &v }

func osStat(p string) (os.FileInfo, error) { return os.Stat(p) }
