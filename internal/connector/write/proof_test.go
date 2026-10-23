package write

// T-0066 proof map (connector-contract §9.8). Samba/fake: S; Windows-only cases stay with T-0156.
//
// TM-F-RIGHTS, AC1 (activation refused, extra and missing both reported):
//   AD    rights: TestMembershipPaths/PrimaryGroupEdge (CC-VER-02/03), TestStep2EffectiveRights (-05),
//         TestStep3DACL (-04), TestStep5Delegation (-07), TestReadErrorsNeverPass (-08), TestV9ExcessAndMissing
//         (-09), TestPass (-01), TestShrinkRecord/TestBaselineMissing (-16), TestLabADRefusals (S);
//         CC-VER-06 (SDProp) is Windows-only.
//   Entra rights: TestEveryDenyListPermissionRefuses, TestAnyDirectoryRoleRefuses,
//         TestExtraAndMissingPermissionsReported, TestExtraKeyCredentialsSecretsAndOwnersFlagged (-13),
//         TestCorrectlyGrantedAppPasses.
//   Gate  write: TestGateStates (CC-WRITE-07), TestOverrideNeverBypassesTier0 (-08).
// TM-F-T0GUARD, AC2 (Plan and Apply refused on tier0, both transports): the tests below and
//   handler_test.go (CC-WRITE-01/03/04/06/18/19/20/21), entra_test.go, lab_test.go (CC-WRITE-02 on Samba).
//
// The tests in this file cut across those:
//   CC-WRITE-09  Entra E1-E5, one target per basis, through the real Entra classifier and the fake Graph
//   CC-WRITE-12  every refusal gives the same code, stage, details, gate state and local record on
//                both transports
//   CC-WRITE-13  canary values never reach an error, a local record or the baseline

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/graph/graphtest"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func gid(n int) string { return fmt.Sprintf("77777777-7777-7777-7777-%012d", n) }

// CC-WRITE-09: a target for each Entra basis is refused over both transports; an ordinary user and
// an owner of an app holding only a harmless permission are not (negative twins).
func TestProofEntraE1ToE5(t *testing.T) {
	const (
		roleGA   = "62e90394-69f5-4237-9190-012177145e10"
		roleHIA  = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"
		rolePerm = "ab000000-0000-0000-0000-000000000001" // Application.ReadWrite.All
		rolePln  = "ab000000-0000-0000-0000-000000000002" // User.Read.All
		graphSP  = "55555555-5555-5555-5555-555555555555"
		badSP    = "99999999-9999-9999-9999-999999999999"
		plainSP  = "96969696-9696-9696-9696-969696969696"
	)
	holder, grpOwner, appOwner, hybrid, plain, plainOwner, group, corr := gid(1), gid(2), gid(3), gid(4), gid(5), gid(6), gid(10), gid(12)
	cred := graphtest.NewCredential(t)
	srv := graphtest.New(t, &graphtest.Tenant{
		TenantID: eTenant, ClientID: eClient, SPID: eSP, AppObjectID: eApp,
		ServicePrincipals: map[string]graph.ServicePrincipal{
			eSP: {ID: eSP, AppID: eClient},
			graphSP: {ID: graphSP, AppID: "00000003-0000-0000-c000-000000000000", AppRoles: []graph.AppRole{
				{ID: rolePerm, Value: "Application.ReadWrite.All"}, {ID: rolePln, Value: "User.Read.All"}}},
			badSP:   {ID: badSP, AppID: "98989898-9898-9898-9898-989898989898"},
			plainSP: {ID: plainSP, AppID: "95959595-9595-9595-9595-959595959595"},
		},
		Assignments: map[string][]graph.AppRoleAssignment{
			badSP:   {{ID: "a1", AppRoleID: rolePerm, PrincipalID: badSP, ResourceID: graphSP, PrincipalType: "ServicePrincipal"}},
			plainSP: {{ID: "a2", AppRoleID: rolePln, PrincipalID: plainSP, ResourceID: graphSP, PrincipalType: "ServicePrincipal"}},
		},
		Owners: map[string][]graph.DirectoryObject{
			badSP:   {{ID: appOwner, ODataType: "#microsoft.graph.user"}},
			plainSP: {{ID: plainOwner, ODataType: "#microsoft.graph.user"}},
			group:   {{ID: grpOwner, ODataType: "#microsoft.graph.user"}},
		},
		Roles: []graph.RoleAssignment{
			{ID: "r1", PrincipalID: holder, RoleDefinitionID: roleGA, DirectoryScopeID: "/", PrincipalType: "user", Role: graph.RoleDefinition{ID: roleGA, DisplayName: "Global Administrator"}},
			{ID: "r2", PrincipalID: hybrid, RoleDefinitionID: roleHIA, DirectoryScopeID: "/", PrincipalType: "user", Role: graph.RoleDefinition{ID: roleHIA, DisplayName: "Hybrid Identity Administrator"}},
		},
		Groups: []graph.Group{{ID: group, IsAssignableToRole: true}},
	}, cred)
	c, err := graph.New(srv.Config(cred))
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{base: &memBaseline{}, rec: &memRecorder{}, now: t0time}
	r.gate, _ = NewGateBook(r.base, func() time.Time { return r.now })
	r.gate.Complete(connID, Run{VerificationID: toWire(mk(99)).Value, CompletedAt: t0time, Verdict: connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS,
		Checks: map[connectorv1.VerificationCheck]connectorv1.CheckOutcome{
			connectorv1.VerificationCheck_VERIFICATION_CHECK_EV3_OVER_PRIVILEGE: connectorv1.CheckOutcome_CHECK_OUTCOME_PASS,
			connectorv1.VerificationCheck_VERIFICATION_CHECK_EV4_SUFFICIENCY:    connectorv1.CheckOutcome_CHECK_OUTCOME_PASS}})
	h, err := New(&EntraProvider{Reader: c, TenantID: eTenant}, r.gate, WithRecorder(r.rec), WithClock(func() time.Time { return r.now }))
	if err != nil {
		t.Fatal(err)
	}
	conn := &connectorv1.ConnectionRef{ConnectionId: connID, DirectoryIdentity: &connectorv1.DirectoryIdentity{
		Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: eTenant}}}
	adPeerT0 := goodPeer(true)
	adPeerT0.PeerKind, adPeerT0.PeerTier0Basis = connectorv1.ProviderKind_PROVIDER_KIND_AD, []connectorv1.Tier0Basis{tier0.C1}

	cases := []struct {
		name, id string
		ctx      func(id string) *connectorv1.Tier0Context
		stage    connectorv1.Tier0RefusalStage
		basis    tier0.Basis // zero: any basis, but at least one
	}{
		{"E1 role holder", holder, nil, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD, tier0.E1},
		{"E2 role-assignable group", group, nil, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD, tier0.E2},
		{"E2 owner of one", grpOwner, nil, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD, tier0.E2},
		{"E3 owner of an app holding a deny-listed permission", appOwner, nil, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD, tier0.E3},
		{"E4 hybrid identity administrator", hybrid, nil, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD, tier0.E4},
		{"E5 correlated with AD tier0", corr, func(id string) *connectorv1.Tier0Context {
			g := entraID(id)
			return &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{peersStmt(g, t0time, adPeerT0)}}
		}, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_REQUEST_CONTEXT, tier0.E5},
	}
	for tname, tr := range transports(t, h) {
		for _, tc := range cases {
			g := entraID(tc.id)
			tctx := ctxFor(g)
			if tc.ctx != nil {
				tctx = tc.ctx(tc.id)
			}
			_, err := tr.Plan(context.Background(), &connectorv1.PlanRequest{Connection: conn, Target: &connectorv1.WriteTarget{Object: toWire(g)}, Tier0: tctx})
			d := wantTier0(t, err, tc.stage)
			if !hasBasis(d.GetBasis(), tc.basis) {
				t.Errorf("%s/%s plan: basis %v, want %v", tname, tc.name, d.GetBasis(), tc.basis)
			}
			_, err = tr.Apply(context.Background(), &connectorv1.ApplyRequest{Connection: conn, Step: &connectorv1.StepKey{OperationId: toWire(mk(50))},
				Target: &connectorv1.WriteTarget{Object: toWire(g)}, Tier0: tctx,
				Precondition: &connectorv1.TargetPrecondition{StateDigest: []byte("d")}, PlanDigest: []byte("x")})
			wantTier0(t, err, tc.stage)
		}
		// Negative twins: neither is tier0, so both reach the kind check.
		for _, id := range []string{plain, plainOwner} {
			g := entraID(id)
			_, err := tr.Plan(context.Background(), &connectorv1.PlanRequest{Connection: conn, Target: &connectorv1.WriteTarget{Object: toWire(g)}, Tier0: ctxFor(g)})
			if code := connErr(t, err).GetCode(); code != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
				t.Errorf("%s: non-tier0 %s got %s", tname, id, code)
			}
		}
	}
}

func hasBasis(bs []connectorv1.Tier0Basis, want tier0.Basis) bool {
	for _, b := range bs {
		if b == want {
			return true
		}
	}
	return false
}

// refusalScenarios are the refusals of the write group that need no kind (K0). Each builds a fresh
// rig so the two transports start from the same state.
func refusalScenarios() map[string]func(t *testing.T) (*rig, func(tr transport) error) {
	apply := func(r *rig, q *connectorv1.ApplyRequest) func(transport) error {
		return func(tr transport) error { _, err := tr.Apply(context.Background(), q); return err }
	}
	over := func(fps ...string) Run {
		x := passRun(nil)
		x.Checks[connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE] = connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL
		x.Verdict = connectorv1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED
		for _, f := range fps {
			x.Blocking = append(x.Blocking, []byte(f))
		}
		return x
	}
	return map[string]func(t *testing.T) (*rig, func(tr transport) error){
		"never verified": func(t *testing.T) (*rig, func(transport) error) {
			r := newRig(t, nil)
			return r, apply(r, applyReq(mk(40), ctxFor(mk(40))))
		},
		"overprivileged": func(t *testing.T) (*rig, func(transport) error) {
			x := over("a", "b")
			r := newRig(t, &x)
			return r, apply(r, applyReq(mk(40), ctxFor(mk(40))))
		},
		"partly acknowledged": func(t *testing.T) (*rig, func(transport) error) {
			x := over("a", "b")
			r := newRig(t, &x)
			q := applyReq(mk(40), ctxFor(mk(40)))
			q.Tier0Override = &connectorv1.WriteGateOverride{OverrideId: toWire(mk(70)), AcknowledgedFingerprints: [][]byte{[]byte("a")}}
			return r, apply(r, q)
		},
		"context missing": func(t *testing.T) (*rig, func(transport) error) {
			run := passRun(nil)
			r := newRig(t, &run)
			return r, apply(r, applyReq(mk(40), nil))
		},
		"context stale": func(t *testing.T) (*rig, func(transport) error) {
			run := passRun(nil)
			r := newRig(t, &run)
			q := applyReq(mk(40), &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{noLink(mk(40), t0time.Add(-16*time.Minute))}})
			return r, apply(r, q)
		},
		"context contradicted": func(t *testing.T) (*rig, func(transport) error) {
			run := passRun(nil)
			r := newRig(t, &run)
			f := t0time.Add(-time.Minute)
			q := applyReq(mk(40), &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{noLink(mk(40), f), peersStmt(mk(40), f, goodPeer(false))}})
			return r, apply(r, q)
		},
		"designated target": func(t *testing.T) (*rig, func(transport) error) {
			run := passRun(nil)
			r := newRig(t, &run)
			c := ctxFor(mk(40))
			c.Designated = append(c.Designated, toWire(mk(40)))
			return r, apply(r, applyReq(mk(40), c))
		},
		"C16 peer": func(t *testing.T) (*rig, func(transport) error) {
			run := passRun(nil)
			r := newRig(t, &run)
			c := &connectorv1.Tier0Context{Tier0Revision: 7, Statements: []*connectorv1.CorrelationStatement{peersStmt(mk(40), t0time, goodPeer(true))}}
			return r, apply(r, applyReq(mk(40), c))
		},
		"connector set": func(t *testing.T) (*rig, func(transport) error) {
			run := passRun(map[string][]Basis{mk(40).String(): {tier0.C1}})
			r := newRig(t, &run)
			return r, apply(r, applyReq(mk(40), ctxFor(mk(40))))
		},
		"override never opens tier0": func(t *testing.T) (*rig, func(transport) error) {
			x := over("a")
			x.Set = map[string][]Basis{mk(40).String(): {tier0.C2}}
			r := newRig(t, &x)
			q := applyReq(mk(40), ctxFor(mk(40)))
			q.Tier0Override = &connectorv1.WriteGateOverride{OverrideId: toWire(mk(70)), AcknowledgedFingerprints: [][]byte{[]byte("a")}}
			return r, apply(r, q)
		},
		"live re-read": func(t *testing.T) (*rig, func(transport) error) {
			run := passRun(nil)
			r := newRig(t, &run)
			r.prov.tier0[mk(40)] = []Basis{tier0.C2}
			return r, apply(r, applyReq(mk(40), ctxFor(mk(40))))
		},
		"live re-read fails": func(t *testing.T) (*rig, func(transport) error) {
			run := passRun(nil)
			r := newRig(t, &run)
			r.prov.classErr[mk(40)] = context.DeadlineExceeded
			return r, apply(r, applyReq(mk(40), ctxFor(mk(40))))
		},
		"other forest": func(t *testing.T) (*rig, func(transport) error) {
			run := passRun(nil)
			r := newRig(t, &run)
			q := applyReq(mk(40), ctxFor(mk(40)))
			q.Connection.DirectoryIdentity = &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: "x"}}
			return r, apply(r, q)
		},
	}
}

// CC-WRITE-12: for every refusal the two transports return the same ConnectorError (code, stage,
// details), leave the same local record, and call the directory the same number of times.
func TestProofRefusalsAreIdenticalOnBothTransports(t *testing.T) {
	for name, build := range refusalScenarios() {
		t.Run(name, func(t *testing.T) {
			var errs, events, calls = map[string]*connectorv1.ConnectorError{}, map[string]Event{}, map[string]int{}
			var statuses = map[string]string{}
			for _, tname := range []string{"in-process", "grpc"} {
				r, call := build(t) // a fresh rig per transport: same start state
				tr := transports(t, r.h)[tname]
				err := call(tr)
				errs[tname] = connErr(t, err)
				if st, ok := status.FromError(err); ok {
					statuses[tname] = st.Code().String()
				}
				events[tname] = r.rec.last()
				calls[tname] = r.prov.n()
			}
			if !proto.Equal(errs["in-process"], errs["grpc"]) {
				t.Errorf("errors differ:\n in-process %v\n grpc       %v", errs["in-process"], errs["grpc"])
			}
			if statuses["in-process"] != statuses["grpc"] {
				t.Errorf("status codes differ: %v", statuses)
			}
			if fmt.Sprintf("%+v", events["in-process"]) != fmt.Sprintf("%+v", events["grpc"]) {
				t.Errorf("local records differ:\n %+v\n %+v", events["in-process"], events["grpc"])
			}
			if e := events["grpc"]; e.Outcome != "refused" || e.Code == "" || e.Stage == "" || e.Operation == "" {
				t.Errorf("incomplete local record: %+v", e)
			}
			if calls["in-process"] != calls["grpc"] {
				t.Errorf("directory calls differ: %v", calls)
			}
		})
	}
}

// CC-WRITE-13: values that must never leave the connector (fingerprints, evidence anchors, an
// attacker-chosen connection id) do not appear in any error, local record line or baseline entry.
func TestProofCanaryNeverEscapes(t *testing.T) {
	const canary = "CANARY-9f3a71"
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	x := passRun(map[string][]Basis{mk(41).String(): {tier0.C1}})
	x.Checks[connectorv1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE] = connectorv1.CheckOutcome_CHECK_OUTCOME_FAIL
	x.Verdict = connectorv1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED
	x.Blocking = [][]byte{[]byte(canary + "-fp")}
	r := newRig(t, &x)
	h, err := New(r.prov, r.gate, WithRecorder(SlogRecorder{L: log}), WithClock(func() time.Time { return r.now }))
	if err != nil {
		t.Fatal(err)
	}
	peer := goodPeer(true)
	peer.Evidence = &connectorv1.CorrelationEvidence{Evidence: &connectorv1.CorrelationEvidence_SourceAnchor{SourceAnchor: []byte(canary + "-anchor")}}
	peerCtx := &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{
		{Object: toWire(mk(42)), ComputedAt: timestamppb.New(t0time), Correlation: &connectorv1.CorrelationStatement_Peers{Peers: &connectorv1.CorrelatedPeers{Peers: []*connectorv1.CorrelatedPeer{peer}}}}}}
	var all [][]byte
	for _, tr := range transports(t, h) {
		for _, q := range []*connectorv1.ApplyRequest{
			applyReq(mk(41), ctxFor(mk(41))), // gate closed by the fingerprinted finding, then partly overridden
			applyReq(mk(42), peerCtx),
		} {
			q.Tier0Override = &connectorv1.WriteGateOverride{OverrideId: toWire(mk(70)), AcknowledgedFingerprints: [][]byte{[]byte(canary + "-ack")}}
			_, err := tr.Apply(context.Background(), q)
			ce := connErr(t, err)
			b, _ := proto.Marshal(ce)
			all = append(all, b, []byte(err.Error()), []byte(ce.GetMessage()))
		}
	}
	all = append(all, buf.Bytes())
	r.base.mu.Lock()
	all = append(all, []byte(fmt.Sprintf("%+v", r.base.got)))
	r.base.mu.Unlock()
	for _, b := range all {
		if strings.Contains(string(b), canary) {
			t.Fatalf("canary escaped: %q", b)
		}
	}
	if buf.Len() == 0 {
		t.Fatal("no local record was written")
	}
}
