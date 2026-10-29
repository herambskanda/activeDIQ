package rights

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	"google.golang.org/protobuf/proto"
)

func guidN(n byte) adguid.GUID {
	var g adguid.GUID
	g[0], g[15] = n, 0xC3
	return g
}

func request(w *world, correlated ...*v1.Tier0Member) *v1.VerifyConnectionRequest {
	return &v1.VerifyConnectionRequest{Connection: &v1.ConnectionRef{ConnectionId: "conn-1"}, VerificationId: pbGuid(guidN(99)), CorrelatedTier0: correlated}
}

func (w *world) stream(t *testing.T, ep *EpochState, req *v1.VerifyConnectionRequest) ([]*v1.VerifyConnectionResponse, error) {
	t.Helper()
	w.setTokens()
	ref, _ := dn.ParseObjectRef(w.id.DN)
	// The streamed run uses the world's fixed tier0 set through the directory: the classifier is
	// replaced by registering the set through ADInput in VerifyAD, so StreamAD is driven with the
	// real classifier unavailable; use the hook below.
	var out []*v1.VerifyConnectionResponse
	prev := snapshotHook
	snapshotHook = func(context.Context) (*tier0.ADSet, error) { return w.set, nil }
	defer func() { snapshotHook = prev }()
	err := StreamAD(context.Background(), w.f, ep, req, ref, testDirectory(), func(m *v1.VerifyConnectionResponse) error {
		out = append(out, m)
		return nil
	}, func() time.Time { return time.Unix(1_700_000_000, 0) })
	return out, err
}

func TestStreamShape(t *testing.T) {
	w := newWorld(t)
	w.put(w.id, "userAccountControl", "524800") // unconstrained delegation: one finding
	msgs, err := w.stream(t, nil, request(w))
	if err != nil {
		t.Fatal(err)
	}
	if msgs[0].GetHeader() == nil || msgs[len(msgs)-1].GetCompleted() == nil {
		t.Fatalf("header first and completed last: %d messages", len(msgs))
	}
	var findings, members int
	completed := 0
	for _, m := range msgs {
		findings += len(m.GetFindings().GetFindings())
		members += len(m.GetTier0Set().GetMembers())
		if m.GetCompleted() != nil {
			completed++
		}
	}
	c := msgs[len(msgs)-1].GetCompleted()
	if completed != 1 || findings != 1 || int(c.FindingCount) != findings || int(c.Tier0MemberCount) != members || members != 2 {
		t.Fatalf("counts: completed=%d findings=%d members=%d %v", completed, findings, members, c)
	}
	if c.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED || c.WriteGateOpenable || len(c.Checks) != 4 || c.Checks[0].Check != v1.VerificationCheck_VERIFICATION_CHECK_V5_IDENTITY ||
		c.Checks[0].Outcome != v1.CheckOutcome_CHECK_OUTCOME_PASS || c.Checks[1].Check != v7 {
		t.Fatalf("%v", c)
	}
	if msgs[0].GetHeader().CheckListVersion != CheckListVersionAD || msgs[0].GetHeader().Identity.GetAd() == nil {
		t.Fatal("header")
	}
}

func TestStreamChunksLargeSets(t *testing.T) {
	w := newWorld(t)
	for i := 0; i < membersPerChunk+5; i++ {
		_, g := w.f.obj("CN=m"+string(rune('a'+i%26))+strings.Repeat("x", i/26)+",CN=Users,DC=lab,DC=test", "", nil,
			map[string][][]byte{"nTSecurityDescriptor": {sdBytes(daSID)}})
		w.set.Add(g, tier0.C2)
	}
	msgs, err := w.stream(t, nil, request(w))
	if err != nil {
		t.Fatal(err)
	}
	chunks := 0
	for _, m := range msgs {
		if m.GetTier0Set() != nil {
			chunks++
		}
	}
	if chunks != 2 {
		t.Fatalf("chunks %d", chunks)
	}
}

func TestInvalidCorrelatedIsRejectedBeforeAnyRead(t *testing.T) {
	for name, m := range map[string]*v1.Tier0Member{
		"wrong basis": {Object: pbGuid(guidN(7)), Basis: []v1.Tier0Basis{tier0.C1}},
		"no basis":    {Object: pbGuid(guidN(7))},
		"two bases":   {Object: pbGuid(guidN(7)), Basis: []v1.Tier0Basis{tier0.C16, tier0.C1}},
		"no object":   {Basis: []v1.Tier0Basis{tier0.C16}},
		"E5 on AD":    {Object: pbGuid(guidN(7)), Basis: []v1.Tier0Basis{v1.Tier0Basis_TIER0_BASIS_E5_CORRELATED_TO_AD_TIER0}},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			msgs, err := w.stream(t, nil, request(w, m))
			if !IsInvalidArgument(err) || len(msgs) != 0 || len(w.f.reads) != 0 {
				t.Fatalf("err=%v sent=%d reads=%d", err, len(msgs), len(w.f.reads))
			}
		})
	}
	w := newWorld(t)
	_, err := w.stream(t, nil, request(w, &v1.Tier0Member{Object: pbGuid(guidN(7)), Basis: []v1.Tier0Basis{tier0.C16}}))
	if err != nil {
		t.Fatal(err)
	}
}

func TestCorrelatedGroupBlocksAndIsReported(t *testing.T) {
	w := newWorld(t)
	_, g := w.f.obj("CN=Ops,CN=Users,DC=lab,DC=test", domS+"-1300", nil,
		map[string][][]byte{"nTSecurityDescriptor": {sdBytes(daSID)}})
	w.put(w.id, "memberOf", "CN=Ops,CN=Users,DC=lab,DC=test")
	w.tokens = append(w.tokens, domS+"-1300")
	msgs, err := w.stream(t, nil, request(w, &v1.Tier0Member{Object: pbGuid(g), Basis: []v1.Tier0Basis{tier0.C16}}))
	if err != nil {
		t.Fatal(err)
	}
	var inSet, blocked bool
	for _, m := range msgs {
		for _, x := range m.GetTier0Set().GetMembers() {
			if guidText(x.Object) == g.String() && x.Basis[0] == tier0.C16 {
				inSet = true
			}
		}
		for _, f := range m.GetFindings().GetFindings() {
			if f.Kind == v1.FindingKind_FINDING_KIND_TIER0_GROUP_MEMBERSHIP && f.ObjectTier0Basis[0] == tier0.C16 {
				blocked = true
			}
		}
	}
	if !inSet || !blocked {
		t.Fatalf("inSet=%v blocked=%v", inSet, blocked)
	}
}

// ---- the shrink ratchet (contract §8.3a, CC-VER-16) ----

type epochFix struct {
	dir   string
	store FileBaselineStore
	sink  FileRecordSink
}

func newEpochFix(t *testing.T) *epochFix {
	d := t.TempDir()
	return &epochFix{d, FileBaselineStore{filepath.Join(d, "baseline.json")}, FileRecordSink{filepath.Join(d, "records.log")}}
}

func (e *epochFix) state() *EpochState { return NewEpochState(e.store, e.sink, nil) }

func (e *epochFix) records(t *testing.T) string {
	b, _ := os.ReadFile(e.sink.Path)
	return string(b)
}

func in(basis v1.Tier0Basis, ns ...byte) []ReportedEntry {
	var out []ReportedEntry
	for _, n := range ns {
		out = append(out, ReportedEntry{GUID: guidN(n).String(), Basis: basis})
	}
	return out
}

func TestShrinkRecord(t *testing.T) {
	ctx := context.Background()
	fx := newEpochFix(t)
	ep := fx.state()
	// run 1: designated A, B and correlated C. First ever run: no comparison, and the missing
	// baseline is itself recorded.
	if n, err := ep.Complete(ctx, "v1", append(in(tier0.Designated, 1, 2), in(tier0.C16, 3)...)); err != nil || n != 0 {
		t.Fatalf("run1 %d %v", n, err)
	}
	if !strings.Contains(fx.records(t), "tier0_baseline_missing") {
		t.Fatal("first run must record the missing baseline")
	}
	// a request context designates D
	if err := ep.Append(ReportedEntry{GUID: guidN(4).String(), Basis: tier0.Designated, Source: SourceRequestContext, Revision: "r7"}); err != nil {
		t.Fatal(err)
	}
	// run 2 with {A} only: B, C and D are dropped
	n, err := ep.Complete(ctx, "v2", in(tier0.Designated, 1))
	if err != nil || n != 3 {
		t.Fatalf("run2 %d %v", n, err)
	}
	rec := fx.records(t)
	for _, want := range []string{guidN(2).String(), guidN(3).String(), guidN(4).String(), SourceRequestContext, "r7", `"previous_verification_id":"v1"`} {
		if !strings.Contains(rec, want) {
			t.Errorf("record lacks %q:\n%s", want, rec)
		}
	}
	if strings.Contains(rec, guidN(1).String()+`","basis"`) && strings.Count(rec, "tier0_set_shrink") != 1 {
		t.Error("exactly one shrink record per run")
	}
	// run 3 grows the set: no record, run 3' swaps A for E: A is listed (a swap is compared as sets)
	before := strings.Count(fx.records(t), "tier0_set_shrink")
	if n, err := ep.Complete(ctx, "v3", in(tier0.Designated, 1, 5)); err != nil || n != 0 || strings.Count(fx.records(t), "tier0_set_shrink") != before {
		t.Fatalf("run3 %d %v", n, err)
	}
	if n, err := ep.Complete(ctx, "v3b", in(tier0.Designated, 5)); err != nil || n != 1 {
		t.Fatalf("swap %d %v", n, err)
	}
	// restart: a fresh state reads the persisted baseline, so run 4 with {} lists E
	ep2 := fx.state()
	n, err = ep2.Complete(ctx, "v4", nil)
	if err != nil || n != 1 || !strings.Contains(fx.records(t), guidN(5).String()) {
		t.Fatalf("after restart %d %v", n, err)
	}
}

func TestBaselineMissing(t *testing.T) {
	ctx := context.Background()
	// without a restart the in-memory set still decides
	fx := newEpochFix(t)
	ep := fx.state()
	if _, err := ep.Complete(ctx, "v1", in(tier0.Designated, 1, 2)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fx.store.Path); err != nil {
		t.Fatal(err)
	}
	if n, err := ep.Complete(ctx, "v2", in(tier0.Designated, 1)); err != nil || n != 1 {
		t.Fatalf("deleted baseline must not skip the comparison: %d %v", n, err)
	}
	if strings.Count(fx.records(t), "tier0_baseline_missing") != 2 {
		t.Fatalf("missing recorded for run 1 and run 2:\n%s", fx.records(t))
	}
	// after a restart with no baseline the comparison is skipped
	if err := os.Remove(fx.store.Path); err != nil {
		t.Fatal(err)
	}
	if n, err := fx.state().Complete(ctx, "v3", nil); err != nil || n != 0 {
		t.Fatalf("restart without baseline: %d %v", n, err)
	}
	// a corrupt file is "unreadable": same
	if err := os.WriteFile(fx.store.Path, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := fx.state().Complete(ctx, "v4", nil); err != nil || n != 0 {
		t.Fatalf("corrupt baseline: %d %v", n, err)
	}
	if info, err := os.Stat(fx.store.Path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("baseline mode %v %v", info, err)
	}
}

type failStore struct {
	FileBaselineStore
	failSave bool
}

func (s *failStore) Save(b *Baseline) error {
	if s.failSave {
		return errors.New("disk full")
	}
	return s.FileBaselineStore.Save(b)
}

type failSink struct {
	FileRecordSink
	fail bool
}

func (s *failSink) WriteShrink(ctx context.Context, r ShrinkRecord) error {
	if s.fail {
		return errors.New("event log")
	}
	return s.FileRecordSink.WriteShrink(ctx, r)
}

func TestLocalRecordFailureNeverShrinksAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	fx := newEpochFix(t)
	store := &failStore{FileBaselineStore: fx.store}
	sink := &failSink{FileRecordSink: fx.sink}
	ep := NewEpochState(store, sink, nil)
	if _, err := ep.Complete(ctx, "v1", in(tier0.Designated, 1, 2)); err != nil {
		t.Fatal(err)
	}
	// (i) the baseline cannot be written
	store.failSave = true
	if _, err := ep.Complete(ctx, "v2", in(tier0.Designated, 1)); !errors.Is(err, ErrLocalRecordFailed) {
		t.Fatalf("baseline failure: %v", err)
	}
	// (ii) the record cannot be written
	store.failSave, sink.fail = false, true
	if _, err := ep.Complete(ctx, "v2", in(tier0.Designated, 1)); !errors.Is(err, ErrLocalRecordFailed) {
		t.Fatalf("record failure: %v", err)
	}
	// the reported set was never shrunk: once the disk recovers, the same smaller run still reports B
	sink.fail = false
	if n, err := ep.Complete(ctx, "v2", in(tier0.Designated, 1)); err != nil || n != 1 || !strings.Contains(fx.records(t), guidN(2).String()) {
		t.Fatalf("recovery %d %v", n, err)
	}
	// (iii) a ratchet append that cannot be made durable is an error and leaves nothing behind
	store.failSave = true
	if err := ep.Append(ReportedEntry{GUID: guidN(8).String(), Basis: tier0.Designated, Source: SourceRequestContext}); !errors.Is(err, ErrLocalRecordFailed) {
		t.Fatalf("append failure: %v", err)
	}
	// (iv) a durable append survives a restart
	store.failSave = false
	if err := ep.Append(ReportedEntry{GUID: guidN(9).String(), Basis: tier0.Designated, Source: SourceRequestContext}); err != nil {
		t.Fatal(err)
	}
	n, err := fx.state().Complete(ctx, "v5", nil)
	if err != nil || n != 2 { // A (run input) and G (append) from the persisted baseline
		t.Fatalf("after restart: %d %v", n, err)
	}
	if !strings.Contains(fx.records(t), guidN(9).String()) || strings.Contains(fx.records(t), guidN(8).String()) {
		t.Fatal("appended entry missing, or a failed append left a trace")
	}
}

func TestStreamEndsWithoutCompletedOnLocalRecordFailure(t *testing.T) {
	w := newWorld(t)
	fx := newEpochFix(t)
	ep := fx.state()
	if _, err := w.stream(t, ep, request(w, &v1.Tier0Member{Object: pbGuid(guidN(7)), Basis: []v1.Tier0Basis{tier0.C16}})); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fx.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(fx.dir, 0o700)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	msgs, err := w.stream(t, ep, request(w))
	if !errors.Is(err, ErrLocalRecordFailed) {
		t.Fatalf("err %v", err)
	}
	for _, m := range msgs {
		if m.GetCompleted() != nil {
			t.Fatal("completed sent although the record could not be made durable")
		}
	}
}

func testDirectory() *v1.DirectoryIdentity {
	return &v1.DirectoryIdentity{Identity: &v1.DirectoryIdentity_AdForest{AdForest: &v1.AdForestIdentity{
		ForestRootNcGuid: pbGuid(guidN(7))}}}
}

func TestStreamCompletedCarriesDirectoryIdentity(t *testing.T) {
	w := newWorld(t)
	msgs, err := w.stream(t, nil, request(w))
	if err != nil {
		t.Fatal(err)
	}
	got := msgs[len(msgs)-1].GetCompleted().GetDirectoryIdentity()
	if !proto.Equal(got, testDirectory()) {
		t.Fatalf("completed directory identity = %v", got)
	}
}

func TestStreamRefusesWithoutDirectoryIdentity(t *testing.T) {
	w := newWorld(t)
	w.setTokens()
	ref, _ := dn.ParseObjectRef(w.id.DN)
	sent := 0
	err := StreamAD(context.Background(), w.f, nil, request(w), ref, nil, func(*v1.VerifyConnectionResponse) error { sent++; return nil }, nil)
	if err == nil || sent != 0 {
		t.Fatalf("err=%v sent=%d: a run with no bound directory must stream nothing", err, sent)
	}
}

// T-0358 / TM-D26 rule 10: pinned_c13 on the request reaches the snapshot, so over the stream path a
// renamed pinned group stays in the streamed tier0 set; without the pin it drops out.
func TestStreamPinnedC13KeepsRenamedGroupInTier0Set(t *testing.T) {
	pin := guidN(41)
	run := func(pins ...*v1.Guid) map[string]bool {
		w := newWorld(t)
		w.setTokens()
		ref, _ := dn.ParseObjectRef(w.id.DN)
		prev := snapshotWith
		// A stand-in for the classifier's rule: a pinned GUID is C13 whatever its name now is.
		snapshotWith = func(_ context.Context, _ ADDirectory, pinned, _ []adguid.GUID) (*tier0.ADSet, error) {
			s := tier0.NewADSet()
			for _, p := range pinned {
				s.AddC13(p)
			}
			return s, nil
		}
		defer func() { snapshotWith = prev }()
		req := request(w)
		req.PinnedC13 = pins
		var members = map[string]bool{}
		err := StreamAD(context.Background(), w.f, nil, req, ref, testDirectory(), func(m *v1.VerifyConnectionResponse) error {
			for _, x := range m.GetTier0Set().GetMembers() {
				g, _ := ParseGUID(x.GetObject())
				members[g.String()] = true
			}
			return nil
		}, func() time.Time { return time.Unix(1_700_000_000, 0) })
		if err != nil {
			t.Fatal(err)
		}
		return members
	}
	if got := run(pbGuid(pin)); !got[pin.String()] {
		t.Errorf("pinned renamed group missing from tier0 set: %v", got)
	}
	if got := run(); got[pin.String()] {
		t.Errorf("unpinned group in tier0 set: %v", got)
	}
}

func TestMalformedPinnedC13IsInvalidArgument(t *testing.T) {
	for name, g := range map[string]*v1.Guid{
		"short": {Value: []byte{1, 2, 3}},
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			req := request(w)
			req.PinnedC13 = []*v1.Guid{g}
			msgs, err := w.stream(t, nil, req)
			if !IsInvalidArgument(err) || len(msgs) != 0 || len(w.f.reads) != 0 {
				t.Fatalf("err=%v sent=%d reads=%d", err, len(msgs), len(w.f.reads))
			}
		})
	}
}
