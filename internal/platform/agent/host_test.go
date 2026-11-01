package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type tkey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   string
}

func newKey() tkey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return tkey{pub, priv, agentpolicy.KeyID(pub)}
}

func keysetDoc(t *testing.T, tid string, seq uint64, k tkey) *agentv1.SignedKeyset {
	t.Helper()
	ks := agentpolicy.Keyset{Tenant: tid, Seq: seq, IssuedAt: t0, SignerKeyID: k.id,
		Keys: []agentpolicy.KeysetKey{{KeyID: k.id, Public: k.pub, State: agentpolicy.KeyActive}}}
	sk, err := agentpolicy.SignKeyset(ks, k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.SignedKeyset{Document: sk.Marshal()}
}

func policyDoc(t *testing.T, tid string, seq uint64, k tkey, mut func(*agentpolicy.AddcPolicy)) *agentv1.SignedPolicy {
	t.Helper()
	p := agentpolicy.AddcPolicy{
		Password: agentpolicy.PasswordRules{MinLength: 12, MaxLength: 128, MinClasses: 3},
		Events: agentpolicy.EventRules{CollectionEnabled: true, Channels: []agentpolicy.Channel{agentpolicy.ChannelSecurity},
			EventIDs: []uint32{4624}, MaxEventsPerSecond: 10, BatchMaxBytes: 1024, OutboxMaxBytes: 4096},
	}
	if mut != nil {
		mut(&p)
	}
	body, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := agentpolicy.SignPolicy(agentpolicy.PolicyHeader{Tenant: tid, Kind: agentpolicy.KindADDC, Seq: seq, IssuedAt: t0, NotAfter: t0.Add(24 * time.Hour), KeyID: k.id}, body, k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.SignedPolicy{Document: sp.Marshal()}
}

type fakeModule struct {
	mu        sync.Mutex
	active    *agentpolicy.AddcPolicy
	validate  error
	activated int
	started   bool
}

func (m *fakeModule) Validate(agentpolicy.AddcPolicy) error { return m.validate }
func (m *fakeModule) Activate(p agentpolicy.AddcPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active, m.activated = &p, m.activated+1
	return nil
}
func (m *fakeModule) Start(context.Context, ModuleDeps) error { m.started = true; return nil }
func (m *fakeModule) Stop(context.Context) error              { return nil }
func (m *fakeModule) Collection() agentv1.CollectionState {
	return agentv1.CollectionState_COLLECTION_STATE_RUNNING
}
func (m *fakeModule) Register(grpc.ServiceRegistrar) {}

func ceil() Ceilings {
	return Ceilings{OutboxMaxBytes: 8 * DefaultSegmentBytes, BatchMaxBytes: 64 << 10, MaxEventsPerSecond: 50}
}

func openHost(t *testing.T, dir string, mod Module) *Host {
	t.Helper()
	h, err := Open(Config{Identity: idOf(tidA, compA), DataDir: dir, Version: "test", Module: mod, Ceilings: ceil(), Now: func() time.Time { return t0.Add(time.Hour) }, TokenCheckPassed: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.outbox.Close() })
	return h
}

// privDir is a data directory the host will accept (owner-only).
func privDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func code(err error) codes.Code { return status.Code(err) }

func TestHostPolicyBeforeAnchorRefused(t *testing.T) {
	h := openHost(t, privDir(t), &fakeModule{})
	k := newKey()
	_, err := h.ApplyPolicy(context.Background(), &agentv1.ApplyPolicyRequest{Signed: policyDoc(t, idOf(tidA, compA).Tenant.String(), 1, k, nil)})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v", err)
	}
}

func TestHostAnchorApplyReplayRestart(t *testing.T) {
	dir := privDir(t)
	mod := &fakeModule{}
	h := openHost(t, dir, mod)
	tid := idOf(tidA, compA).Tenant.String()
	k := newKey()
	ctx := context.Background()
	if r, err := h.ApplyKeyset(ctx, &agentv1.ApplyKeysetRequest{Signed: keysetDoc(t, tid, 1, k)}); err != nil || !r.AnchoredNow {
		t.Fatalf("anchor: %v %v", r, err)
	}
	if _, err := h.ApplyPolicy(ctx, &agentv1.ApplyPolicyRequest{Signed: policyDoc(t, tid, 5, k, nil)}); err != nil {
		t.Fatal(err)
	}
	if mod.activated != 1 {
		t.Fatalf("activated %d", mod.activated)
	}
	// P2: replay and rollback refused, nothing activated.
	for _, seq := range []uint64{5, 4} {
		_, err := h.ApplyPolicy(ctx, &agentv1.ApplyPolicyRequest{Signed: policyDoc(t, tid, seq, k, nil)})
		if code(err) != codes.FailedPrecondition {
			t.Fatalf("seq %d: %v", seq, err)
		}
	}
	if mod.activated != 1 {
		t.Fatal("refused policy was activated")
	}
	// Restart: floor survives, installed policy is reactivated by Run.
	_ = h.outbox.Close()
	mod2 := &fakeModule{}
	h2 := openHost(t, dir, mod2)
	st, _ := h2.GetStatus(ctx, &agentv1.GetStatusRequest{})
	if !st.Anchored || st.PolicySeq != 5 || st.KeysetSeq != 1 || !st.TokenCheckPassed {
		t.Fatalf("status %+v", st)
	}
	if _, err := h2.ApplyPolicy(ctx, &agentv1.ApplyPolicyRequest{Signed: policyDoc(t, tid, 5, k, nil)}); code(err) != codes.FailedPrecondition {
		t.Fatalf("replay after restart: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_ = h2.Run(cctx)
	if mod2.active == nil || !mod2.started {
		t.Fatal("installed policy not reactivated on start")
	}
}

func TestHostWrongTenantAndForeignKeyRefused(t *testing.T) {
	h := openHost(t, privDir(t), &fakeModule{})
	tid := idOf(tidA, compA).Tenant.String()
	k, other := newKey(), newKey()
	ctx := context.Background()
	if _, err := h.ApplyKeyset(ctx, &agentv1.ApplyKeysetRequest{Signed: keysetDoc(t, tidB.String(), 1, k)}); code(err) != codes.PermissionDenied {
		t.Fatalf("wrong-tenant keyset: %v", err)
	}
	h = openHost(t, privDir(t), &fakeModule{})
	if _, err := h.ApplyKeyset(ctx, &agentv1.ApplyKeysetRequest{Signed: keysetDoc(t, tid, 1, k)}); err != nil {
		t.Fatal(err)
	}
	_, err := h.ApplyPolicy(ctx, &agentv1.ApplyPolicyRequest{Signed: policyDoc(t, tid, 1, other, nil)})
	if code(err) != codes.PermissionDenied {
		t.Fatalf("unknown key: %v", err)
	}
	// A second anchor attempt is not a way to swap the key set.
	if _, err := h.ApplyKeyset(ctx, &agentv1.ApplyKeysetRequest{Signed: keysetDoc(t, tid, 2, other)}); err == nil {
		t.Fatal("keyset signed by an unknown key accepted")
	}
}

func TestHostCeilingAndModuleRefusalChangeNothing(t *testing.T) {
	mod := &fakeModule{}
	h := openHost(t, privDir(t), mod)
	tid := idOf(tidA, compA).Tenant.String()
	k := newKey()
	ctx := context.Background()
	if _, err := h.ApplyKeyset(ctx, &agentv1.ApplyKeysetRequest{Signed: keysetDoc(t, tid, 1, k)}); err != nil {
		t.Fatal(err)
	}
	over := policyDoc(t, tid, 1, k, func(p *agentpolicy.AddcPolicy) { p.Events.MaxEventsPerSecond = 1000 })
	if _, err := h.ApplyPolicy(ctx, &agentv1.ApplyPolicyRequest{Signed: over}); code(err) != codes.InvalidArgument {
		t.Fatalf("over ceiling: %v", err)
	}
	mod.validate = errors.New("unknown event id")
	if _, err := h.ApplyPolicy(ctx, &agentv1.ApplyPolicyRequest{Signed: policyDoc(t, tid, 1, k, nil)}); code(err) != codes.InvalidArgument {
		t.Fatalf("module refusal: %v", err)
	}
	if st, _ := h.GetStatus(ctx, nil); st.PolicySeq != 0 || mod.activated != 0 {
		t.Fatalf("refused policy changed state: %+v", st)
	}
	// The floor did not advance either: seq 1 is still acceptable once the module agrees.
	mod.validate = nil
	if _, err := h.ApplyPolicy(ctx, &agentv1.ApplyPolicyRequest{Signed: policyDoc(t, tid, 1, k, nil)}); err != nil {
		t.Fatalf("clean retry: %v", err)
	}
}

func TestHostGarbageDocumentsRefused(t *testing.T) {
	h := openHost(t, privDir(t), &fakeModule{})
	ctx := context.Background()
	for _, d := range [][]byte{nil, {1}, make([]byte, 64), make([]byte, maxDocBytes+1)} {
		if _, err := h.ApplyPolicy(ctx, &agentv1.ApplyPolicyRequest{Signed: &agentv1.SignedPolicy{Document: d}}); code(err) != codes.InvalidArgument {
			t.Fatalf("policy %d bytes: %v", len(d), err)
		}
		if _, err := h.ApplyKeyset(ctx, &agentv1.ApplyKeysetRequest{Signed: &agentv1.SignedKeyset{Document: d}}); code(err) != codes.InvalidArgument {
			t.Fatalf("keyset %d bytes: %v", len(d), err)
		}
	}
}

func TestHostStageUpdateFailsClosed(t *testing.T) {
	h := openHost(t, privDir(t), &fakeModule{})
	_, err := h.StageUpdate(context.Background(), &agentv1.StageUpdateRequest{MetadataBundle: []byte("x"), ArtefactDigest: make([]byte, 32)})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v", err)
	}
}

type fakeIngest struct {
	mu      sync.Mutex
	got     []uint64
	failing func(*agentv1.SubmitEventsRequest) error
}

func (f *fakeIngest) SubmitEvents(_ context.Context, in *agentv1.SubmitEventsRequest, _ ...grpc.CallOption) (*agentv1.SubmitEventsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failing != nil {
		if err := f.failing(in); err != nil {
			return nil, err
		}
	}
	for _, e := range in.Events {
		f.got = append(f.got, e.AgentSeq)
	}
	return &agentv1.SubmitEventsResponse{Accepted: uint64(len(in.Events)), HighestStoredSeq: in.Events[len(in.Events)-1].AgentSeq}, nil
}

func fill(t *testing.T, h *Host, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := h.outbox.Append(&agentv1.AgentEvent{Kind: agentv1.EventKind_EVENT_KIND_EVENT, Channel: "security", EventRecordId: uint64(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	_ = h.outbox.Flush()
}

func TestSenderDeliversAndAcks(t *testing.T) {
	h := openHost(t, privDir(t), &fakeModule{})
	fill(t, h, 5)
	f := &fakeIngest{}
	if _, err := h.sendOnce(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if len(f.got) != 5 || h.outbox.Stats().AckedThrough != 5 {
		t.Fatalf("got %v stats %+v", f.got, h.outbox.Stats())
	}
}

func TestSenderServerDownKeepsRecords(t *testing.T) {
	h := openHost(t, privDir(t), &fakeModule{})
	fill(t, h, 3)
	f := &fakeIngest{failing: func(*agentv1.SubmitEventsRequest) error { return status.Error(codes.Unavailable, "down") }}
	if _, err := h.sendOnce(context.Background(), f); err == nil {
		t.Fatal("expected error")
	}
	if h.outbox.Stats().AckedThrough != 0 {
		t.Fatal("acked without delivery")
	}
}

func TestSenderPoisonRecordDroppedRestDelivered(t *testing.T) {
	h := openHost(t, privDir(t), &fakeModule{})
	fill(t, h, 6)
	f := &fakeIngest{failing: func(in *agentv1.SubmitEventsRequest) error {
		for _, e := range in.Events {
			if e.AgentSeq == 3 {
				return status.Error(codes.InvalidArgument, "bad")
			}
		}
		return nil
	}}
	for i := 0; i < 10 && h.outbox.Stats().AckedThrough < 6; i++ {
		if _, err := h.sendOnce(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	if h.outbox.Stats().AckedThrough != 6 {
		t.Fatalf("stuck: %+v got %v", h.outbox.Stats(), f.got)
	}
	for _, s := range f.got {
		if s == 3 {
			t.Fatal("poison record delivered")
		}
	}
	if h.outbox.Stats().Dropped != 1 {
		t.Fatalf("dropped %d", h.outbox.Stats().Dropped)
	}
}

func TestSenderNeverAcksBeyondBatch(t *testing.T) {
	h := openHost(t, privDir(t), &fakeModule{})
	fill(t, h, 3)
	f := &fakeIngest{failing: nil}
	over := &overAck{fakeIngest: f}
	if _, err := h.sendOnce(context.Background(), over); err != nil {
		t.Fatal(err)
	}
	if h.outbox.Stats().AckedThrough != 3 {
		t.Fatalf("%+v", h.outbox.Stats())
	}
}

type overAck struct{ *fakeIngest }

func (o *overAck) SubmitEvents(ctx context.Context, in *agentv1.SubmitEventsRequest, c ...grpc.CallOption) (*agentv1.SubmitEventsResponse, error) {
	r, err := o.fakeIngest.SubmitEvents(ctx, in, c...)
	if r != nil {
		r.HighestStoredSeq = 1 << 40
	}
	return r, err
}
