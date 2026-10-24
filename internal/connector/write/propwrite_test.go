package write

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/graph/graphtest"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Contract §8.9 / CC-WRITE-22 (build-time check) and the K0 half of CC-WRITE-23..29: the guard calls
// CheckPropertyWrite at step 4 on both RPCs and both transports, and the override cannot admit it.

type stubGuard struct {
	v     tier0.DynamicRuleRefusal
	err   error
	calls int
	seen  []tier0.PropertyWrite
}

func (s *stubGuard) CheckPropertyWrite(_ context.Context, w tier0.PropertyWrite) (tier0.DynamicRuleRefusal, error) {
	s.calls++
	s.seen = append(s.seen, w)
	return s.v, s.err
}

var adUpdateTitle = tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteUser, Op: tier0.OpUpdate, Keys: []string{"title"}}

func declare(pw tier0.PropertyWrite, err error) func(*connectorv1.WriteChange) (tier0.PropertyWrite, error) {
	return func(*connectorv1.WriteChange) (tier0.PropertyWrite, error) { return pw, err }
}

func TestAC1RegistrationWithoutPropertyWriteFailsTheBuildCheck(t *testing.T) {
	if err := validateOps(operations); err != nil {
		t.Fatalf("the shipped table: %v", err)
	}
	ok := WriteOp{PropertyWrite: declare(adUpdateTitle, nil),
		Touched: func(g guidT, _ *connectorv1.WriteChange) ([]guidT, error) { return []guidT{g}, nil },
		Digest:  func(*connectorv1.ApplyRequest) ([]byte, error) { return nil, nil },
		Plan: func(context.Context, Authorised, *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
			return nil, nil
		},
		Apply: func(context.Context, Authorised, *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
			return nil, nil
		}}
	k := connectorv1.WriteKind(1)
	if err := validateOps(map[connectorv1.WriteKind]WriteOp{k: ok}); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.PropertyWrite = nil
	err := validateOps(map[connectorv1.WriteKind]WriteOp{k: bad})
	if err == nil || !strings.Contains(err.Error(), "PropertyWrite") {
		t.Fatalf("a kind without PropertyWrite passed: %v", err)
	}
	// New refuses to build over such a table, so it cannot be reached at runtime either.
	r := newRig(t, nil)
	if _, err := New(r.prov, r.gate, func(h *Handler) { h.ops = map[connectorv1.WriteKind]WriteOp{k: bad} }); err == nil {
		t.Fatal("New accepted a table with a kind lacking PropertyWrite")
	}
}

func armed(t *testing.T, guard PropertyGuard, pw func(*connectorv1.WriteChange) (tier0.PropertyWrite, error), run Run) (*rig, *recordedOp) {
	t.Helper()
	r := newRig(t, &run)
	rec := withTestOp(r)
	op := r.h.ops[1]
	op.PropertyWrite = pw
	r.h.ops[1] = op
	r.prov.guard = guard
	return r, rec
}

func TestAC2RefusedAtStep4OnBothRPCsAndTransportsOverrideDoesNotAdmit(t *testing.T) {
	tgt := mk(40)
	overpriv := passRun(nil)
	overpriv.Checks[connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE] = connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL
	overpriv.Verdict = connectorv1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED
	overpriv.Blocking = [][]byte{[]byte("a")}
	cases := []struct {
		name  string
		run   Run
		ov    *connectorv1.WriteGateOverride
		stage connectorv1.Tier0RefusalStage
		g     *stubGuard
	}{
		{"connector-set verdict", passRun(nil), nil, stConnectorSet,
			&stubGuard{v: tier0.DynamicRuleRefusal{Refused: true, Reason: tier0.ReasonDesignatedDynamicRule, Stage: tier0.StageConnectorSet}}},
		{"live re-read verdict", passRun(nil), nil, stLive,
			&stubGuard{v: tier0.DynamicRuleRefusal{Refused: true, Reason: tier0.ReasonDesignatedDynamicRule, Stage: tier0.StageLiveReread}}},
		{"read failure fails closed", passRun(nil), nil, stLive, &stubGuard{err: errors.New("graph 500")}},
		{"override acknowledged, still refused", overpriv,
			&connectorv1.WriteGateOverride{OverrideId: toWire(mk(70)), AcknowledgedFingerprints: [][]byte{[]byte("a")}}, stConnectorSet,
			&stubGuard{v: tier0.DynamicRuleRefusal{Refused: true, Reason: tier0.ReasonDesignatedDynamicRule, Stage: tier0.StageConnectorSet}}},
	}
	for _, c := range cases {
		r, rec := armed(t, nil, declare(adUpdateTitle, nil), c.run)
		r.prov.guard = c.g
		for tname, tr := range transports(t, r.h) {
			p := planReq(tgt, ctxFor(tgt))
			p.Kind, p.Tier0Override = 1, c.ov
			_, err := tr.Plan(context.Background(), p)
			d := wantTier0(t, err, c.stage)
			if len(d.GetBasis()) != 1 || d.GetBasis()[0] != tier0.Designated {
				t.Errorf("%s/%s plan basis %v", c.name, tname, d.GetBasis())
			}
			a := applyReq(tgt, ctxFor(tgt))
			a.Kind, a.Tier0Override = 1, c.ov
			_, err = tr.Apply(context.Background(), a)
			wantTier0(t, err, c.stage)
		}
		if rec.plan != 0 || rec.apply != 0 {
			t.Errorf("%s: the operation body ran (plan %d, apply %d)", c.name, rec.plan, rec.apply)
		}
		if c.g.calls != 4 {
			t.Errorf("%s: guard consulted %d times, want 4 (2 RPCs x 2 transports)", c.name, c.g.calls)
		}
		if ev := r.rec.last(); ev.Stage != "4" {
			t.Errorf("%s: refused at stage %q, want 4", c.name, ev.Stage)
		}
	}
}

func TestPropertyGuardAllowsAndPassesTheDeclaration(t *testing.T) {
	tgt := mk(40)
	g := &stubGuard{}
	r, rec := armed(t, g, declare(adUpdateTitle, nil), passRun(nil))
	p := planReq(tgt, ctxFor(tgt))
	p.Kind = 1
	if _, err := r.h.Plan(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if rec.plan != 1 || len(g.seen) != 1 || g.seen[0].Op != tier0.OpUpdate || g.seen[0].Keys[0] != "title" {
		t.Fatalf("plan %d seen %+v", rec.plan, g.seen)
	}
}

func TestPropertyGuardFailsClosedOnBadDeclarationOrNoSnapshot(t *testing.T) {
	tgt := mk(40)
	entraDecl := adUpdateTitle
	entraDecl.Plane = tier0.PlaneEntra
	for name, pw := range map[string]func(*connectorv1.WriteChange) (tier0.PropertyWrite, error){
		"declaration errors":              declare(tier0.PropertyWrite{}, errors.New("bad change")),
		"declaration for the other plane": declare(entraDecl, nil),
	} {
		r, rec := armed(t, &stubGuard{}, pw, passRun(nil))
		p := planReq(tgt, ctxFor(tgt))
		p.Kind = 1
		_, err := r.h.Plan(context.Background(), p)
		if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT || rec.plan != 0 {
			t.Errorf("%s: %s plan=%d", name, c, rec.plan)
		}
	}
	// No snapshot (the provider's default guard): every property write is refused.
	r, rec := armed(t, nil, declare(adUpdateTitle, nil), passRun(nil))
	p := planReq(tgt, ctxFor(tgt))
	p.Kind = 1
	_, err := r.h.Plan(context.Background(), p)
	wantTier0(t, err, stConnectorSet)
	if rec.plan != 0 {
		t.Error("ran without a snapshot")
	}
}

func TestProvidersNeverReturnANilGuard(t *testing.T) {
	for _, p := range []Provider{&ADProvider{}, &EntraProvider{}} {
		g, err := p.PropertyGuard(context.Background())
		if err != nil || g == nil {
			t.Fatalf("%T: %v %v", p, g, err)
		}
		r, err := g.CheckPropertyWrite(context.Background(), adUpdateTitle)
		if err != nil || !r.Refused {
			t.Errorf("%T without a snapshot allowed a write: %+v %v", p, r, err)
		}
	}
}

// K0 rows of CC-WRITE-23/24/25/27/28 through the handler, over a real snapshot of a designated
// closure holding a dynamic group (graphtest), with the negative twin of each.
func TestK0RealSnapshotThroughTheHandler(t *testing.T) {
	const gA, gD = "77777777-7777-7777-7777-000000000100", "77777777-7777-7777-7777-000000000150"
	cred := graphtest.NewCredential(t)
	srv := graphtest.New(t, &graphtest.Tenant{
		TenantID: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222",
		SPID: "33333333-3333-3333-3333-333333333333", AppObjectID: "44444444-4444-4444-4444-444444444444",
		ServicePrincipals: map[string]graph.ServicePrincipal{"33333333-3333-3333-3333-333333333333": {ID: "33333333-3333-3333-3333-333333333333", AppID: "22222222-2222-2222-2222-222222222222"},
			"55555555-5555-5555-5555-555555555555": {ID: "55555555-5555-5555-5555-555555555555", AppID: "00000003-0000-0000-c000-000000000000"}},
		Groups:  []graph.Group{{ID: gA}, {ID: gD, GroupTypes: []string{"DynamicMembership"}, MembershipRule: `user.jobTitle -eq "X"`}},
		Members: map[string][]graph.DirectoryObject{gA: {{ID: gD, ODataType: "#microsoft.graph.group"}}},
	}, cred)
	c, err := graph.New(srv.Config(cred))
	if err != nil {
		t.Fatal(err)
	}
	set, err := tier0.New(c).Snapshot(context.Background(), tier0.Designation{ID: gA, Kind: tier0.KindGroup})
	if err != nil {
		t.Fatal(err)
	}
	user := func(op tier0.Op, keys ...string) tier0.PropertyWrite {
		return tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteUser, Op: op, Keys: keys}
	}
	rows := []struct {
		name    string
		pw      tier0.PropertyWrite
		refused bool
	}{
		{"CC-WRITE-27 title is a rule property", user(tier0.OpUpdate, "title"), true},
		{"CC-WRITE-27 twin: telephoneNumber is not", user(tier0.OpUpdate, "telephoneNumber"), false},
		{"CC-WRITE-25 create matches by absence", user(tier0.OpCreate), true},
		{"CC-WRITE-28 non-canonical key", user(tier0.OpUpdate, "title;binary"), true},
		{"CC-WRITE-28 empty key", user(tier0.OpUpdate, ""), true},
		{"CC-WRITE-28 numeric OID", user(tier0.OpUpdate, "2.5.4.12"), true},
	}
	tgt := mk(40)
	for _, row := range rows {
		r, rec := armed(t, set, declare(row.pw, nil), passRun(nil))
		a := applyReq(tgt, ctxFor(tgt))
		a.Kind = 1
		_, err := r.h.Apply(context.Background(), a)
		if row.refused {
			if connErr(t, err).GetCode() != connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED || rec.apply != 0 {
				t.Errorf("%s: err %v apply %d", row.name, err, rec.apply)
			}
			continue
		}
		if err != nil || rec.apply != 1 {
			t.Errorf("%s: err %v apply %d", row.name, err, rec.apply)
		}
	}
}
