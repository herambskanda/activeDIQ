package write

import (
	"context"
	"errors"
	"github.com/skenzeriq/activediq/internal/connector/provider/entra"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/graph/graphtest"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	eTenant = "11111111-1111-1111-1111-111111111111"
	eClient = "22222222-2222-2222-2222-222222222222"
	eSP     = "33333333-3333-3333-3333-333333333333"
	eApp    = "44444444-4444-4444-4444-444444444444"
	eGA     = "62e90394-69f5-4237-9190-012177145e10"
	eHolder = "77777777-7777-7777-7777-000000000001"
	eGroup  = "77777777-7777-7777-7777-000000000010"
	ePlain  = "77777777-7777-7777-7777-000000000007"
)

func entraRig(t *testing.T) (*Handler, *graphtest.Server, connectorv1.PlanRequest) {
	t.Helper()
	cred := graphtest.NewCredential(t)
	srv := graphtest.New(t, &graphtest.Tenant{
		TenantID: eTenant, ClientID: eClient, SPID: eSP, AppObjectID: eApp,
		ServicePrincipals: map[string]graph.ServicePrincipal{eSP: {ID: eSP, AppID: eClient},
			"55555555-5555-5555-5555-555555555555": {ID: "55555555-5555-5555-5555-555555555555", AppID: "00000003-0000-0000-c000-000000000000"}},
		Roles: []graph.RoleAssignment{{ID: "r1", PrincipalID: eHolder, RoleDefinitionID: eGA, DirectoryScopeID: "/", PrincipalType: "user",
			Role: graph.RoleDefinition{ID: eGA, DisplayName: "Global Administrator"}}},
		Groups:  []graph.Group{{ID: eGroup, IsAssignableToRole: true}},
		Members: map[string][]graph.DirectoryObject{eGroup: {{ID: "77777777-7777-7777-7777-000000000003", ODataType: "#microsoft.graph.user"}}},
	}, cred)
	c, err := graph.New(srv.Config(cred))
	if err != nil {
		t.Fatal(err)
	}
	now := t0time
	book, _ := NewGateBook(&memBaseline{}, func() time.Time { return now })
	book.Complete(connID, Run{VerificationID: toWire(mk(99)).Value, CompletedAt: now, Verdict: connectorv1.VerificationVerdict_VERIFICATION_VERDICT_PASS,
		Checks: map[connectorv1.VerificationCheck]connectorv1.CheckOutcome{
			connectorv1.VerificationCheck_VERIFICATION_CHECK_EV3_OVER_PRIVILEGE: connectorv1.CheckOutcome_CHECK_OUTCOME_PASS,
			connectorv1.VerificationCheck_VERIFICATION_CHECK_EV4_SUFFICIENCY:    connectorv1.CheckOutcome_CHECK_OUTCOME_PASS}})
	h, err := New(&entra.EntraProvider{Reader: c, TenantID: eTenant}, book, WithRecorder(&memRecorder{}), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return h, srv, connectorv1.PlanRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: connID,
		DirectoryIdentity: &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: eTenant}}}}
}

func entraID(s string) guid.GUID {
	g, err := guid.Parse(s)
	if err != nil {
		panic(err)
	}
	return g
}

// AC3 (Entra half): privileged-role holders and role-assignable groups (E1, E2) are found by the
// live Graph reads and refused; the Graph client has no write method, and the fitness test keeps
// it that way, so no Graph write can follow.
func TestEntraLiveTier0Refused(t *testing.T) {
	h, _, base := entraRig(t)
	for name, id := range map[string]string{"E1 role holder": eHolder, "E2 role-assignable group": eGroup, "E2 member of one": "77777777-7777-7777-7777-000000000003"} {
		g := entraID(id)
		req := &connectorv1.ApplyRequest{Connection: base.Connection, Step: &connectorv1.StepKey{OperationId: toWire(mk(50))},
			Target: &connectorv1.WriteTarget{Object: toWire(g)}, Tier0: ctxFor(g),
			Precondition: &connectorv1.TargetPrecondition{StateDigest: []byte("d")}, PlanDigest: []byte("x")}
		_, err := h.Apply(context.Background(), req)
		d := wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
		if len(d.GetBasis()) == 0 {
			t.Errorf("%s: no basis", name)
		}
	}
	// An ordinary user passes the guard and ends at the kind check.
	g := entraID(ePlain)
	_, err := h.Plan(context.Background(), &connectorv1.PlanRequest{Connection: base.Connection, Target: &connectorv1.WriteTarget{Object: toWire(g)}, Tier0: ctxFor(g)})
	if connErr(t, err).GetCode() != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("%v", err)
	}
}

// AC3: an Entra object correlated to an AD tier0 object (E5) is refused from the request's context
// before Graph is called: not even the token endpoint is contacted.
func TestEntraCorrelatedToADTier0RefusedBeforeGraph(t *testing.T) {
	h, srv, base := entraRig(t)
	g := entraID(ePlain)
	p := goodPeer(true)
	p.PeerKind = connectorv1.ProviderKind_PROVIDER_KIND_AD
	p.PeerTier0Basis = []connectorv1.Tier0Basis{tier0.C1}
	ctx := &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{peersStmt(g, t0time, p)}}
	for _, call := range []func() error{
		func() error {
			_, err := h.Plan(context.Background(), &connectorv1.PlanRequest{Connection: base.Connection, Target: &connectorv1.WriteTarget{Object: toWire(g)}, Tier0: ctx})
			return err
		},
		func() error {
			_, err := h.Apply(context.Background(), &connectorv1.ApplyRequest{Connection: base.Connection, Target: &connectorv1.WriteTarget{Object: toWire(g)}, Tier0: ctx,
				Precondition: &connectorv1.TargetPrecondition{StateDigest: []byte("d")}, PlanDigest: []byte("x")})
			return err
		},
	} {
		d := wantTier0(t, call(), connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_REQUEST_CONTEXT)
		if len(d.GetBasis()) != 1 || d.GetBasis()[0] != tier0.E5 {
			t.Fatalf("basis %v", d.GetBasis())
		}
	}
	if tok, calls := srv.Calls(); tok != 0 || calls != 0 {
		t.Fatalf("Graph contacted before the refusal: token=%d graph=%d", tok, calls)
	}
}

// AC3: an AD object correlated to Entra tier0 (C16) is refused without any directory call.
func TestADCorrelatedToEntraTier0RefusedBeforeDirectory(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	id := mk(60)
	c := &connectorv1.Tier0Context{Statements: []*connectorv1.CorrelationStatement{peersStmt(id, t0time, goodPeer(true))}}
	for _, tr := range transports(t, r.h) {
		d := wantTier0(t, func() error { _, err := tr.Apply(context.Background(), applyReq(id, c)); return err }(),
			connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_REQUEST_CONTEXT)
		if len(d.GetBasis()) != 1 || d.GetBasis()[0] != tier0.C16 {
			t.Fatalf("basis %v", d.GetBasis())
		}
	}
	if r.prov.n() != 0 {
		t.Fatalf("%d directory calls", r.prov.n())
	}
}

// groupReader answers GroupMembers from a table; the classifier methods are never reached because
// the base classifier is not part of this test (Classify is exercised through membersOf).
type groupReader struct {
	tier0.Reader
	members map[guid.GUID][]graph.DirectoryObject
	err     map[guid.GUID]error
}

func (g groupReader) GroupMembers(_ context.Context, id guid.GUID) ([]graph.DirectoryObject, error) {
	if e := g.err[id]; e != nil {
		return nil, e
	}
	m, ok := g.members[id]
	if !ok {
		return nil, &graph.Error{Code: graph.CodeNotFound}
	}
	return m, nil
}

// An Entra direct member of a designated group is tier0; missing group skipped; other errors refuse.
func TestEntraDesignatedMembership(t *testing.T) {
	ctx := context.Background()
	user, grp := entraID(ePlain), mk(82)
	h, _, _ := entraRig(t)
	p := h.prov.(*entra.EntraProvider)
	p.Reader = withMembers{p.Reader, groupReader{
		members: map[guid.GUID][]graph.DirectoryObject{entraID(eGroup): {}, grp: {{ID: user.String(), ODataType: "#microsoft.graph.user"}}},
		err:     map[guid.GUID]error{mk(80): errors.New("graph 500")}}}
	v, err := p.Classify(ctx, user, []guid.GUID{grp})
	if err != nil || !v.Tier0 || v.Bases[len(v.Bases)-1] != tier0.Designated {
		t.Fatalf("direct member: %+v %v", v, err)
	}
	if v, err := p.Classify(ctx, user, []guid.GUID{mk(81)}); err != nil || v.Tier0 {
		t.Fatalf("missing designated group: %+v %v", v, err)
	}
	if v, err := p.Classify(ctx, user, []guid.GUID{mk(80)}); err == nil || !v.Tier0 {
		t.Fatalf("read error must fail closed: %+v %v", v, err)
	}
	if v, err := p.Classify(ctx, entraID("77777777-7777-7777-7777-0000000000aa"), []guid.GUID{grp}); err != nil || v.Tier0 {
		t.Fatalf("non-member: %+v %v", v, err)
	}
}

// withMembers sends GroupMembers to the table and everything else to the live (fake Graph) reader.
type withMembers struct {
	tier0.Reader
	g groupReader
}

func (w withMembers) GroupMembers(ctx context.Context, id guid.GUID) ([]graph.DirectoryObject, error) {
	return w.g.GroupMembers(ctx, id)
}
