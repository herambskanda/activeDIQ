package write

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// AC1: hand-crafted Apply and Plan on a tier0 user, group, DC, GPO and AdminSDHolder, with the
// server-side guard "disabled" (the request carries a valid, fresh context that says nothing about
// the object). Over both transports the call is refused and the provider is not called at all when
// the connector's own set already holds the object.
func TestTier0RefusedBeforeAnyDirectoryCall(t *testing.T) {
	classes := []struct {
		name string
		id   byte
		b    Basis
	}{
		{"user", 1, tier0.C2}, {"group", 2, tier0.C1}, {"dc", 3, tier0.C5}, {"gpo", 4, tier0.C9}, {"adminsdholder", 5, tier0.C3},
	}
	set := map[string][]Basis{}
	for _, c := range classes {
		set[mk(c.id).String()] = []Basis{c.b}
	}
	r := newRig(t, func() *Run { x := passRun(set); return &x }())
	for tname, tr := range transports(t, r.h) {
		for _, c := range classes {
			id := mk(c.id)
			ctx := context.Background()
			_, err := tr.Plan(ctx, planReq(id, ctxFor(id)))
			d := wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET)
			if len(d.GetBasis()) != 1 || d.GetBasis()[0] != c.b {
				t.Errorf("%s/%s plan: basis %v", tname, c.name, d.GetBasis())
			}
			_, err = tr.Apply(ctx, applyReq(id, ctxFor(id)))
			wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET)
		}
	}
	if n := r.prov.n(); n != 0 {
		t.Fatalf("provider called %d times for objects already in the connector's set", n)
	}
}

// The same objects, but unknown to the connector's set: the live re-read finds them. Only reads
// happen (the fake has no write method) and the refusal is LIVE_REREAD, on Plan and Apply.
func TestTier0FoundByLiveReread(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	id := mk(10) // "added to Domain Admins after the last sync"
	r.prov.tier0[id] = []Basis{tier0.C2}
	for tname, tr := range transports(t, r.h) {
		_, err := tr.Plan(context.Background(), planReq(id, ctxFor(id)))
		d := wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
		if len(d.GetBasis()) != 1 || d.GetBasis()[0] != tier0.C2 {
			t.Errorf("%s: basis %v", tname, d.GetBasis())
		}
		_, err = tr.Apply(context.Background(), applyReq(id, ctxFor(id)))
		wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
	}
}

// AC4: a non-tier0 target ends in CAPABILITY_UNSUPPORTED on both RPCs; Describe says so too.
func TestNonTier0IsUnsupported(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	id := mk(11)
	for tname, tr := range transports(t, r.h) {
		_, err := tr.Plan(context.Background(), planReq(id, ctxFor(id)))
		if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
			t.Errorf("%s plan: %s", tname, c)
		}
		_, err = tr.Apply(context.Background(), applyReq(id, ctxFor(id)))
		if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
			t.Errorf("%s apply: %s", tname, c)
		}
	}
	got := Capabilities()
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
	for _, c := range got {
		if c.GetState() != connectorv1.SupportState_SUPPORT_STATE_UNSUPPORTED {
			t.Errorf("%s reported %s", c.GetOperation(), c.GetState())
		}
	}
	if len(operations) != 0 {
		t.Fatal("the operation table must be empty until a kind ticket adds a row")
	}
}

// AC5: every classification read error fails closed, on both RPCs.
func TestClassificationErrorFailsClosed(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	id := mk(12)
	r.prov.classErr[id] = context.DeadlineExceeded
	for _, tr := range transports(t, r.h) {
		_, err := tr.Plan(context.Background(), planReq(id, ctxFor(id)))
		wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
		_, err = tr.Apply(context.Background(), applyReq(id, ctxFor(id)))
		wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
	}
}

func TestStep1RequestShape(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	id := mk(13)
	cases := map[string]struct {
		mut  func(*connectorv1.ApplyRequest)
		want connectorv1.ErrorCode
	}{
		"no connection id": {func(q *connectorv1.ApplyRequest) { q.Connection.ConnectionId = "" }, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"no identity":      {func(q *connectorv1.ApplyRequest) { q.Connection.DirectoryIdentity = nil }, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"other forest": {func(q *connectorv1.ApplyRequest) {
			q.Connection.DirectoryIdentity = &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: "x"}}
		}, connectorv1.ErrorCode_ERROR_CODE_DIRECTORY_IDENTITY_MISMATCH},
		"no target":       {func(q *connectorv1.ApplyRequest) { q.Target = nil }, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"short target":    {func(q *connectorv1.ApplyRequest) { q.Target.Object.Value = []byte{1} }, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"no precondition": {func(q *connectorv1.ApplyRequest) { q.Precondition = nil }, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
		"no digest":       {func(q *connectorv1.ApplyRequest) { q.PlanDigest = nil }, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT},
	}
	for name, c := range cases {
		q := applyReq(id, ctxFor(id))
		c.mut(q)
		_, err := r.h.Apply(context.Background(), q)
		if got := connErr(t, err).GetCode(); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	if r.prov.n() != 0 {
		t.Fatal("step 1 made a directory call")
	}
}

func TestContextRules(t *testing.T) {
	run := passRun(nil)
	id, other := mk(14), mk(15)
	fresh := t0time.Add(-time.Minute)
	type tc struct {
		name  string
		ctx   func() *connectorv1.Tier0Context
		stage connectorv1.Tier0RefusalStage
	}
	S := connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_MISSING
	cases := []tc{
		{"nil context", func() *connectorv1.Tier0Context { return nil }, S},
		{"no statement for target", func() *connectorv1.Tier0Context { return ctxFor(other) }, S},
		{"computed_at unset", func() *connectorv1.Tier0Context {
			c := ctxFor(id)
			c.Statements[0].ComputedAt = nil
			return c
		}, S},
		{"correlation unset", func() *connectorv1.Tier0Context {
			c := ctxFor(id)
			c.Statements[0].Correlation = nil
			return c
		}, S},
		{"stale", func() *connectorv1.Tier0Context {
			return &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{noLink(id, t0time.Add(-16*time.Minute))}}
		}, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_STALE},
		{"future", func() *connectorv1.Tier0Context {
			return &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{noLink(id, t0time.Add(6*time.Minute))}}
		}, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_STALE},
		{"oldest of merged statements counts", func() *connectorv1.Tier0Context {
			return &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{noLink(id, fresh), noLink(id, t0time.Add(-20*time.Minute))}}
		}, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_STALE},
		{"no_hybrid_link and peers contradict", func() *connectorv1.Tier0Context {
			return &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{noLink(id, fresh), peersStmt(id, fresh, goodPeer(false))}}
		}, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_CONTRADICTED},
		{"designated target", func() *connectorv1.Tier0Context {
			c := ctxFor(id)
			c.Designated = append(c.Designated, toWire(id))
			return c
		}, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_REQUEST_CONTEXT},
	}
	for _, state := range []connectorv1.CorrelationState{connectorv1.CorrelationState_CORRELATION_STATE_CANDIDATE,
		connectorv1.CorrelationState_CORRELATION_STATE_MATCHED, connectorv1.CorrelationState_CORRELATION_STATE_BROKEN} {
		state := state
		cases = append(cases, tc{"tier0 peer in state " + state.String(), func() *connectorv1.Tier0Context {
			p := goodPeer(true)
			p.State = state
			return &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{peersStmt(id, fresh, p)}}
		}, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_REQUEST_CONTEXT})
	}
	bad := map[string]func(*connectorv1.CorrelatedPeer){
		"state unspecified": func(p *connectorv1.CorrelatedPeer) {
			p.State = connectorv1.CorrelationState_CORRELATION_STATE_UNSPECIFIED
		},
		"kind unspecified": func(p *connectorv1.CorrelatedPeer) { p.PeerKind = connectorv1.ProviderKind_PROVIDER_KIND_UNSPECIFIED },
		"own kind":         func(p *connectorv1.CorrelatedPeer) { p.PeerKind = connectorv1.ProviderKind_PROVIDER_KIND_AD },
		"evidence unset":   func(p *connectorv1.CorrelatedPeer) { p.Evidence = nil },
		"evidence oneof unset": func(p *connectorv1.CorrelatedPeer) {
			p.Evidence = &connectorv1.CorrelationEvidence{}
		},
		"tier0 without basis": func(p *connectorv1.CorrelatedPeer) { p.PeerTier0, p.PeerTier0Basis = true, nil },
		"basis without tier0": func(p *connectorv1.CorrelatedPeer) {
			p.PeerTier0, p.PeerTier0Basis = false, []connectorv1.Tier0Basis{tier0.E1}
		},
	}
	for name, mut := range bad {
		mut := mut
		cases = append(cases, tc{"inconsistent peer: " + name, func() *connectorv1.Tier0Context {
			p := goodPeer(false)
			mut(p)
			return &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{peersStmt(id, fresh, p)}}
		}, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_REQUEST_CONTEXT})
	}
	for _, c := range cases {
		r := newRig(t, &run)
		_, err := r.h.Apply(context.Background(), applyReq(id, c.ctx()))
		wantTier0(t, err, c.stage)
		if r.prov.n() != 0 {
			t.Errorf("%s: %d directory calls before the refusal", c.name, r.prov.n())
		}
	}
}

// F4: a statement whose evidence names another object is refused after the live re-read; matching
// evidence passes to the kind check.
func TestEvidenceBoundToObject(t *testing.T) {
	run := passRun(nil)
	id := mk(16)
	mkCtx := func() *connectorv1.Tier0Context {
		return &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{peersStmt(id, t0time, goodPeer(false))}}
	}
	r := newRig(t, &run)
	r.prov.anchors[id] = Anchors{Source: [][]byte{[]byte("someone else")}}
	_, err := r.h.Plan(context.Background(), planReq(id, mkCtx()))
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_CONTRADICTED)

	r = newRig(t, &run)
	r.prov.anchors[id] = Anchors{Source: [][]byte{[]byte("anchor")}}
	_, err = r.h.Plan(context.Background(), planReq(id, mkCtx()))
	if connErr(t, err).GetCode() != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("matching evidence: %v", err)
	}

	r = newRig(t, &run)
	r.prov.anchErr = ErrNoAnchors
	_, err = r.h.Plan(context.Background(), planReq(id, mkCtx()))
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
}

// Rule 8: what an accepted context marked stays marked until the next completed run.
func TestRatchet(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	id := mk(17)
	marked := ctxFor(id)
	marked.Designated = []*connectorv1.Guid{toWire(id)}
	_, err := r.h.Apply(context.Background(), applyReq(id, marked))
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_REQUEST_CONTEXT)
	if len(r.base.got) != 1 || r.base.got[0].Basis != tier0.Designated {
		t.Fatalf("designation not made durable: %+v", r.base.got)
	}
	// A later request that omits the designation is refused from the connector's own set.
	_, err = r.h.Apply(context.Background(), applyReq(id, ctxFor(id)))
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET)
	// A peer mark ratchets too, even when the statement is later found contradicted.
	pid := mk(18)
	pc := &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{peersStmt(pid, t0time, goodPeer(true))}}
	_, err = r.h.Plan(context.Background(), planReq(pid, pc))
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_REQUEST_CONTEXT)
	_, err = r.h.Plan(context.Background(), planReq(pid, ctxFor(pid)))
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET)
	// The next completed run starts a new epoch.
	run2 := passRun(nil)
	r.gate.Complete(connID, run2)
	_, err = r.h.Plan(context.Background(), planReq(pid, ctxFor(pid)))
	if connErr(t, err).GetCode() != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("after a new run: %v", err)
	}
	// A stale statement adds nothing.
	sid := mk(19)
	sc := &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{peersStmt(sid, t0time.Add(-time.Hour), goodPeer(true))}}
	_, _ = r.h.Plan(context.Background(), planReq(sid, sc))
	if l := r.gate.Lookup(connID, sid); len(l) != 0 {
		t.Fatalf("stale statement ratcheted: %v", l)
	}
}

// A ratchet append that cannot be made durable closes the gate until a new run completes, and the
// call ends before any directory call.
func TestRatchetAppendFailureClosesGate(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	r.base.fail = true
	id := mk(20)
	c := ctxFor(id)
	c.Designated = []*connectorv1.Guid{toWire(mk(21))}
	_, err := r.h.Apply(context.Background(), applyReq(id, c))
	ce := connErr(t, err)
	if ce.GetCode() != connectorv1.ErrorCode_ERROR_CODE_ACTIVATION_REFUSED_OVERPRIVILEGED ||
		ce.GetActivationRefused().GetState() != connectorv1.WriteGateState_WRITE_GATE_STATE_LOCAL_RECORD_FAILED {
		t.Fatalf("%v", ce)
	}
	r.base.fail = false
	_, err = r.h.Apply(context.Background(), applyReq(id, ctxFor(id)))
	if ce := connErr(t, err); ce.GetActivationRefused().GetState() != connectorv1.WriteGateState_WRITE_GATE_STATE_LOCAL_RECORD_FAILED {
		t.Fatalf("gate reopened without a run: %v", ce)
	}
	if r.prov.n() != 0 {
		t.Fatalf("directory called %d times", r.prov.n())
	}
	r.gate.Complete(connID, passRun(nil))
	if _, err = r.h.Apply(context.Background(), applyReq(id, ctxFor(id))); connErr(t, err).GetCode() != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("after run: %v", err)
	}
}

func TestFileBaselineIsDurableAndPrivate(t *testing.T) {
	fb := &FileBaseline{Path: t.TempDir() + "/baseline.jsonl"}
	if err := fb.Append(connID, []Mark{{Object: mk(1), Basis: tier0.C16, Source: "request", Revision: 3}}); err != nil {
		t.Fatal(err)
	}
	st, err := osStat(fb.Path)
	if err != nil || st.Mode().Perm() != 0o600 || st.Size() == 0 {
		t.Fatalf("%v %v", st, err)
	}
	bad := &FileBaseline{Path: t.TempDir() + "/missing-dir/x"}
	if bad.Append(connID, []Mark{{Object: mk(1), Basis: tier0.C16}}) == nil {
		t.Fatal("append to an unwritable path must fail")
	}
}

func TestGateStates(t *testing.T) {
	over := func(v7 connectorv1.CheckOutcome, verdict connectorv1.VerificationVerdict, fps ...string) Run {
		r := passRun(nil)
		r.Checks[connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE] = v7
		r.Verdict = verdict
		for _, f := range fps {
			r.Blocking = append(r.Blocking, []byte(f))
		}
		return r
	}
	insuff := passRun(nil)
	insuff.Checks[connectorv1.VerificationCheck_VERIFICATION_CHECK_V8_READ_SUFFICIENCY] = connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL
	failedV := passRun(nil)
	failedV.Verdict = connectorv1.VerificationVerdict_VERIFICATION_VERDICT_FAILED
	W := connectorv1.WriteGateState_WRITE_GATE_STATE_UNSPECIFIED
	cases := []struct {
		name  string
		run   *Run
		age   time.Duration
		ov    *connectorv1.WriteGateOverride
		state connectorv1.WriteGateState
		by    bool
	}{
		{"never verified", nil, 0, nil, connectorv1.WriteGateState_WRITE_GATE_STATE_NOT_VERIFIED, false},
		{"stale", ptr(passRun(nil)), 26*time.Hour + time.Second, nil, connectorv1.WriteGateState_WRITE_GATE_STATE_STALE, false},
		{"26h exactly is open", ptr(passRun(nil)), 26 * time.Hour, nil, W, false},
		{"insufficient", &insuff, 0, nil, connectorv1.WriteGateState_WRITE_GATE_STATE_INSUFFICIENT, false},
		{"insufficient is not overridable", &insuff, 0, &connectorv1.WriteGateOverride{AcknowledgedFingerprints: [][]byte{[]byte("a")}}, connectorv1.WriteGateState_WRITE_GATE_STATE_INSUFFICIENT, false},
		{"run failed", &failedV, 0, nil, connectorv1.WriteGateState_WRITE_GATE_STATE_COULD_NOT_VERIFY, false},
		{"v7 could not verify", ptr(over(connectorv1.CheckOutcome_CHECK_OUTCOME_COULD_NOT_VERIFY, connectorv1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY)), 0, nil, connectorv1.WriteGateState_WRITE_GATE_STATE_COULD_NOT_VERIFY, false},
		{"v7 not run", ptr(over(connectorv1.CheckOutcome_CHECK_OUTCOME_NOT_RUN, connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS)), 0, nil, connectorv1.WriteGateState_WRITE_GATE_STATE_COULD_NOT_VERIFY, false},
		{"overprivileged", ptr(over(connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL, connectorv1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED, "a", "b")), 0, nil, connectorv1.WriteGateState_WRITE_GATE_STATE_OVERPRIVILEGED, false},
		{"partly acknowledged", ptr(over(connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL, connectorv1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED, "a", "b")), 0, &connectorv1.WriteGateOverride{AcknowledgedFingerprints: [][]byte{[]byte("a")}}, connectorv1.WriteGateState_WRITE_GATE_STATE_OVERPRIVILEGED, false},
		{"fully acknowledged", ptr(over(connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL, connectorv1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED, "a", "b")), 0, &connectorv1.WriteGateOverride{OverrideId: toWire(mk(70)), AcknowledgedFingerprints: [][]byte{[]byte("a"), []byte("b"), []byte("c")}}, W, true},
		{"fail naming nothing cannot be acknowledged", ptr(over(connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL, connectorv1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED)), 0, &connectorv1.WriteGateOverride{AcknowledgedFingerprints: [][]byte{[]byte("a")}}, connectorv1.WriteGateState_WRITE_GATE_STATE_OVERPRIVILEGED, false},
	}
	for _, c := range cases {
		r := newRig(t, c.run)
		r.now = t0time.Add(c.age)
		id := mk(30)
		q := applyReq(id, &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{noLink(id, r.now)}})
		q.Tier0Override = c.ov
		_, err := r.h.Apply(context.Background(), q)
		ce := connErr(t, err)
		if c.state == W {
			if ce.GetCode() != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED { // gate open: ends at the kind check
				t.Errorf("%s: %s", c.name, ce.GetCode())
			}
		} else if ce.GetCode() != connectorv1.ErrorCode_ERROR_CODE_ACTIVATION_REFUSED_OVERPRIVILEGED || ce.GetActivationRefused().GetState() != c.state {
			t.Errorf("%s: %s %v", c.name, ce.GetCode(), ce.GetActivationRefused())
		}
		ev := r.rec.last()
		if (ev.OverrideID != "") != c.by {
			t.Errorf("%s: override admission logged=%v want %v", c.name, ev.OverrideID != "", c.by)
		}
		if c.by && (ev.OverrideAcked != 2 || ev.OverrideListed != 3) {
			t.Errorf("%s: counts %d/%d", c.name, ev.OverrideAcked, ev.OverrideListed)
		}
	}
}

// CC-WRITE-08: an override bypasses the gate, never the tier0 refusal.
func TestOverrideNeverBypassesTier0(t *testing.T) {
	run := passRun(map[string][]Basis{mk(31).String(): {tier0.C1}})
	run.Checks[connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE] = connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL
	run.Verdict = connectorv1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED
	run.Blocking = [][]byte{[]byte("a")}
	r := newRig(t, &run)
	q := applyReq(mk(31), ctxFor(mk(31)))
	q.Tier0Override = &connectorv1.WriteGateOverride{OverrideId: toWire(mk(70)), AcknowledgedFingerprints: [][]byte{[]byte("a")}}
	_, err := r.h.Apply(context.Background(), q)
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET)
	if ev := r.rec.last(); ev.OverrideID == "" {
		t.Fatal("override admission not logged on a later refusal")
	}
}

func TestLimitsAreConstants(t *testing.T) { // CC-WRITE-22 (the fitness test checks no setting reads them)
	if MaxVerificationAge != 26*time.Hour || MaxStatementAge != 15*time.Minute || MaxFutureSkew != 5*time.Minute {
		t.Fatal("limits changed: that is a contract revision")
	}
}

func TestRefusalRecordHoldsNoValues(t *testing.T) {
	run := passRun(map[string][]Basis{mk(32).String(): {tier0.C3}})
	r := newRig(t, &run)
	_, _ = r.h.Apply(context.Background(), applyReq(mk(32), ctxFor(mk(32))))
	ev := r.rec.last()
	if ev.Outcome != "refused" || ev.Code != connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED.String() || ev.Stage == "" ||
		ev.Operation == "" || ev.Attempt != "1" || ev.Account == "" || ev.Tier0Revision != 7 || ev.Statements != 1 {
		t.Fatalf("%+v", ev)
	}
}

// --- known-kind path: the handler is generic over the operation table; a test table stands in for
// a future kind ticket. ---

type recordedOp struct {
	touched []byte
	plan    int
	apply   int
	tokens  []bool
}

func withTestOp(r *rig, touched ...byte) *recordedOp {
	rec := &recordedOp{}
	k := connectorv1.WriteKind(1)
	r.prov.guard = &stubGuard{} // allows; the guard's own tests are in propwrite_test.go
	r.h.ops = map[connectorv1.WriteKind]WriteOp{k: {
		PropertyWrite: declare(adUpdateTitle, nil),
		Touched: func(target guidT, _ *connectorv1.WriteChange) ([]guidT, error) {
			out := []guidT{target}
			for _, b := range touched {
				out = append(out, mk(b))
			}
			return out, nil
		},
		Digest: func(*connectorv1.ApplyRequest) ([]byte, error) { return []byte("digest"), nil },
		Plan: func(_ context.Context, a Authorised, _ *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
			rec.plan++
			rec.tokens = append(rec.tokens, a.Valid())
			return &connectorv1.PlanResponse{}, nil
		},
		Apply: func(_ context.Context, a Authorised, _ *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
			rec.apply++
			rec.tokens = append(rec.tokens, a.Valid())
			if r.prov.failAfter != nil {
				*r.prov.failAfter = true
			}
			return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED}, nil
		},
	}}
	return rec
}

func TestKnownKindTouchedSetAndStep9(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	rec := withTestOp(r, 41)
	tgt, second := mk(40), mk(41)
	mkReq := func(c *connectorv1.Tier0Context) *connectorv1.ApplyRequest {
		q := applyReq(tgt, c)
		q.Kind = 1
		return q
	}
	// second touched object has no statement: CONTEXT_MISSING at step 6, op never reached.
	_, err := r.h.Apply(context.Background(), mkReq(ctxFor(tgt)))
	if d := wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_MISSING); string(d.GetObject().GetValue()) != string(toWire(second).GetValue()) {
		t.Fatal("refusal must name the second touched object")
	}
	// second touched object is tier0 live: refused, op never reached.
	r.prov.tier0[second] = []Basis{tier0.C1}
	_, err = r.h.Apply(context.Background(), mkReq(ctxFor(tgt, second)))
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
	if rec.apply != 0 {
		t.Fatal("operation ran on a tier0 touched object")
	}
	// bad digest.
	delete(r.prov.tier0, second)
	q := mkReq(ctxFor(tgt, second))
	q.PlanDigest = []byte("other")
	_, err = r.h.Apply(context.Background(), q)
	if ce := connErr(t, err); ce.GetCode() != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT || ce.GetRejectedInput().GetRuleId() != "PlanDigestMismatch" {
		t.Fatalf("%v", ce)
	}
	// success; then the post-write re-read cannot reach the DC: both objects listed, empty basis.
	fa := false
	r.prov.failAfter = &fa
	resp, err := r.h.Apply(context.Background(), mkReq(ctxFor(tgt, second)))
	if err != nil {
		t.Fatal(err)
	}
	if rec.apply != 1 || !rec.tokens[0] || len(resp.GetTier0AfterWrite()) != 2 || len(resp.GetTier0AfterWrite()[0].GetBasis()) != 0 {
		t.Fatalf("apply=%d tokens=%v after=%v", rec.apply, rec.tokens, resp.GetTier0AfterWrite())
	}
	if len(resp.GetTier0().GetEvaluated()) != 2 {
		t.Fatalf("evaluation: %v", resp.GetTier0())
	}
	if ev := r.rec.last(); len(ev.Tier0AfterWrite) != 2 {
		t.Fatalf("not logged: %+v", ev)
	}
}

// Step 9 reports an object that became tier0 through the write, with its basis.
func TestStep9ReportsBasis(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	tgt := mk(43)
	withTestOp(r)
	q := applyReq(tgt, ctxFor(tgt))
	q.Kind = 1
	// Replace the fake's behaviour after the write: tier0 with C2, no error.
	r.h.ops[1] = func() WriteOp {
		w := r.h.ops[1]
		inner := w.Apply
		w.Apply = func(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
			r.prov.tier0[tgt] = []Basis{tier0.C2}
			return inner(ctx, a, req)
		}
		return w
	}()
	resp, err := r.h.Apply(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	m := resp.GetTier0AfterWrite()
	if len(m) != 1 || len(m[0].GetBasis()) != 1 || m[0].GetBasis()[0] != tier0.C2 {
		t.Fatalf("%v", m)
	}
}

func TestPlanThroughKnownKind(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	rec := withTestOp(r)
	tgt := mk(42)
	q := planReq(tgt, ctxFor(tgt))
	q.Kind = 1
	resp, err := r.h.Plan(context.Background(), q)
	if err != nil || rec.plan != 1 || len(resp.GetTier0().GetEvaluated()) != 1 || resp.GetTier0().GetVerificationId() == nil {
		t.Fatalf("%v %v %d", resp, err, rec.plan)
	}
	var zero Authorised
	if zero.Valid() || zero.Evaluated() != nil {
		t.Fatal("the zero token must not be valid")
	}
}

// The connector's own designations (run inputs, ratchet marks) are checked live even when the
// request omits them (security review of T-0098, finding 1): both calls, both transports.
func TestOwnDesignatedGroupCheckedLive(t *testing.T) {
	grp, user := mk(60), mk(61)
	for _, mkRun := range map[string]func() Run{
		"run input": func() Run {
			r := passRun(nil)
			r.Inputs = []Mark{{Object: grp, Basis: tier0.Designated, Source: "run"}}
			return r
		},
		"run set": func() Run { return passRun(map[string][]Basis{grp.String(): {tier0.Designated}}) },
	} {
		run := mkRun()
		r := newRig(t, &run)
		r.prov.members = map[guid.GUID][]guid.GUID{grp: {user}}
		for _, tr := range transports(t, r.h) {
			_, err := tr.Plan(context.Background(), planReq(user, ctxFor(user)))
			wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
			_, err = tr.Apply(context.Background(), applyReq(user, ctxFor(user)))
			wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
		}
	}
	// A designation ratcheted from an earlier accepted request counts too.
	run := passRun(nil)
	r := newRig(t, &run)
	r.prov.members = map[guid.GUID][]guid.GUID{grp: {user}}
	first := ctxFor(mk(62))
	first.Designated = []*connectorv1.Guid{toWire(grp)}
	_, _ = r.h.Plan(context.Background(), planReq(mk(62), first))
	_, err := r.h.Apply(context.Background(), applyReq(user, ctxFor(user)))
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
	// Not a member: passes the guard and reaches the empty operation table.
	r.prov.members = nil
	_, err = r.h.Apply(context.Background(), applyReq(user, ctxFor(user)))
	if connErr(t, err).GetCode() != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("%v", err)
	}
}

// Step 9 repeats step 7's reads, designated groups included.
func TestStep9UsesDesignatedSet(t *testing.T) {
	grp, tgt := mk(63), mk(64)
	run := passRun(nil)
	run.Inputs = []Mark{{Object: grp, Basis: tier0.Designated, Source: "run"}}
	r := newRig(t, &run)
	withTestOp(r)
	q := applyReq(tgt, ctxFor(tgt))
	q.Kind = 1
	w := r.h.ops[1]
	inner := w.Apply
	w.Apply = func(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
		r.prov.members = map[guid.GUID][]guid.GUID{grp: {tgt}} // joins during the write window
		return inner(ctx, a, req)
	}
	r.h.ops[1] = w
	resp, err := r.h.Apply(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	m := resp.GetTier0AfterWrite()
	if len(m) != 1 || len(m[0].GetBasis()) != 1 || m[0].GetBasis()[0] != tier0.Designated {
		t.Fatalf("after-write: %v", m)
	}
}

// json/v2 omitempty keeps numeric 0; the baseline line must still omit a zero revision (v1 bytes).
func TestFileBaselineOmitsZeroRevision(t *testing.T) {
	fb := &FileBaseline{Path: t.TempDir() + "/baseline.jsonl"}
	if err := fb.Append(connID, []Mark{{Object: mk(1), Basis: tier0.C16, Source: "run"}, {Object: mk(2), Basis: tier0.C16, Source: "request", Revision: 3}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fb.Path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 || strings.Contains(lines[0], "tier0_revision") || !strings.Contains(lines[1], `"tier0_revision":3`) {
		t.Fatalf("unexpected baseline lines: %q", lines)
	}
}

func TestApplyDACLRefusesWithoutGuardToken(t *testing.T) {
	if err := ApplyDACL(context.Background(), Authorised{}, nil, dn.ObjectRef{}, sd.DACLWrite{}); err == nil {
		t.Fatal("zero Authorised must be refused")
	}
}
