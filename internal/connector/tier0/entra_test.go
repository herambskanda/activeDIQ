package tier0_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/graph/graphtest"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
)

func g(n int) string { return fmt.Sprintf("77777777-7777-7777-7777-%012d", n) }

const (
	tenantID  = "11111111-1111-1111-1111-111111111111"
	clientID  = "22222222-2222-2222-2222-222222222222"
	spID      = "33333333-3333-3333-3333-333333333333"
	appObj    = "44444444-4444-4444-4444-444444444444"
	graphSP   = "55555555-5555-5555-5555-555555555555"
	roleGA    = "62e90394-69f5-4237-9190-012177145e10"
	roleHIA   = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"
	rolePerm  = "ab000000-0000-0000-0000-000000000001" // Application.ReadWrite.All
	rolePlain = "ab000000-0000-0000-0000-000000000002" // User.Read.All
	badSP     = "99999999-9999-9999-9999-999999999999"
	badApp    = "98989898-9898-9898-9898-989898989898"
	badAppObj = "97979797-9797-9797-9797-979797979797"
	plainSP   = "96969696-9696-9696-9696-969696969696"
)

var (
	roleHolder = g(1)
	eligible   = g(2)
	grpMember  = g(3)
	grpOwner   = g(4)
	appOwner   = g(5)
	hybridAdm  = g(6)
	plainUser  = g(7)
	roleGroup  = g(10)
	adPeer     = "aaaaaaaa-0000-0000-0000-000000000001"
	plainOwner = g(8)
	spOwner    = g(9)
)

func tenant() *graphtest.Tenant {
	return &graphtest.Tenant{
		TenantID: tenantID, ClientID: clientID, SPID: spID, AppObjectID: appObj,
		ServicePrincipals: map[string]graph.ServicePrincipal{
			spID: {ID: spID, AppID: clientID},
			graphSP: {ID: graphSP, AppID: "00000003-0000-0000-c000-000000000000", AppRoles: []graph.AppRole{
				{ID: rolePerm, Value: "Application.ReadWrite.All"}, {ID: rolePlain, Value: "User.Read.All"}}},
			badSP:   {ID: badSP, AppID: badApp},
			plainSP: {ID: plainSP, AppID: "95959595-9595-9595-9595-959595959595"},
		},
		Applications: []graph.Application{{ID: badAppObj, AppID: badApp}},
		Assignments: map[string][]graph.AppRoleAssignment{
			badSP:   {{ID: "a1", AppRoleID: rolePerm, PrincipalID: badSP, ResourceID: graphSP, PrincipalType: "ServicePrincipal"}},
			plainSP: {{ID: "a2", AppRoleID: rolePlain, PrincipalID: plainSP, ResourceID: graphSP, PrincipalType: "ServicePrincipal"}},
		},
		Owners: map[string][]graph.DirectoryObject{
			badSP:     {{ID: spOwner, ODataType: "#microsoft.graph.user"}},
			badAppObj: {{ID: appOwner, ODataType: "#microsoft.graph.user"}},
			plainSP:   {{ID: plainOwner, ODataType: "#microsoft.graph.user"}},
			roleGroup: {{ID: grpOwner, ODataType: "#microsoft.graph.user"}},
		},
		Roles: []graph.RoleAssignment{
			{ID: "r1", PrincipalID: roleHolder, RoleDefinitionID: roleGA, DirectoryScopeID: "/", PrincipalType: "user", Role: graph.RoleDefinition{ID: roleGA, DisplayName: "Global Administrator"}},
			{ID: "r2", PrincipalID: eligible, RoleDefinitionID: roleGA, DirectoryScopeID: "/administrativeUnits/x", Eligible: true, PrincipalType: "user", Role: graph.RoleDefinition{ID: roleGA, DisplayName: "Helpdesk Administrator"}},
			{ID: "r3", PrincipalID: hybridAdm, RoleDefinitionID: roleHIA, DirectoryScopeID: "/", PrincipalType: "user", Role: graph.RoleDefinition{ID: roleHIA, DisplayName: "Hybrid Identity Administrator"}},
		},
		Groups:  []graph.Group{{ID: roleGroup, IsAssignableToRole: true}, {ID: g(11)}},
		Members: map[string][]graph.DirectoryObject{roleGroup: {{ID: grpMember, ODataType: "#microsoft.graph.user"}}, g(11): {{ID: plainUser}}},
	}
}

func setup(t *testing.T) (*tier0.Classifier, *graphtest.Server) {
	t.Helper()
	cred := graphtest.NewCredential(t)
	srv := graphtest.New(t, tenant(), cred)
	c, err := graph.New(srv.Config(cred))
	if err != nil {
		t.Fatal(err)
	}
	return tier0.New(c), srv
}

var known = tier0.Input{CorrelationKnown: true}

func TestClassifyBases(t *testing.T) {
	c, _ := setup(t)
	cases := []struct {
		name, id string
		want     []tier0.Basis
	}{
		{"role holder", roleHolder, []tier0.Basis{tier0.E1}},
		{"PIM-eligible holder", eligible, []tier0.Basis{tier0.E1}},
		{"role-assignable group", roleGroup, []tier0.Basis{tier0.E2}},
		{"group member", grpMember, []tier0.Basis{tier0.E2}},
		{"group owner", grpOwner, []tier0.Basis{tier0.E2}},
		{"owner of app with deny-listed permission (application)", appOwner, []tier0.Basis{tier0.E3}},
		{"owner of app with deny-listed permission (SP)", spOwner, []tier0.Basis{tier0.E3}},
		{"hybrid identity administrator", hybridAdm, []tier0.Basis{tier0.E1, tier0.E4}},
		{"plain user", plainUser, nil},
		{"owner of app with harmless permission", plainOwner, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := c.Classify(context.Background(), tc.id, known)
			if err != nil {
				t.Fatal(err)
			}
			if r.Tier0 != (tc.want != nil) || fmt.Sprint(r.Bases) != fmt.Sprint(tc.want) {
				t.Fatalf("got %+v want %v", r, tc.want)
			}
		})
	}
}

func TestE5AnyCorrelationState(t *testing.T) {
	c, _ := setup(t)
	for _, st := range []tier0.State{tier0.StateCandidate, tier0.StateMatched, tier0.StateBroken, tier0.StateUnspecified} {
		in := tier0.Input{CorrelationKnown: true, Peers: []tier0.Peer{{ADObject: adPeer, State: st}},
			ADTier0: map[string]bool{"AAAAAAAA-0000-0000-0000-000000000001": true}}
		r, err := c.Classify(context.Background(), plainUser, in)
		if err != nil || !r.Tier0 || fmt.Sprint(r.Bases) != fmt.Sprint([]tier0.Basis{tier0.E5}) {
			t.Fatalf("state %d: %+v %v", st, r, err)
		}
	}
	// Peer not in the AD tier0 set: not E5.
	r, _ := c.Classify(context.Background(), plainUser, tier0.Input{CorrelationKnown: true,
		Peers: []tier0.Peer{{ADObject: adPeer, State: tier0.StateMatched}}, ADTier0: map[string]bool{}})
	if r.Tier0 {
		t.Fatalf("%+v", r)
	}
}

func TestDesignatedAdditions(t *testing.T) {
	c, _ := setup(t)
	in := tier0.Input{CorrelationKnown: true, Designated: []string{plainUser}}
	r, err := c.Classify(context.Background(), plainUser, in)
	if err != nil || !r.Tier0 || r.Bases[0] != tier0.Designated {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestMissingCorrelationRefuses(t *testing.T) {
	c, _ := setup(t)
	r, err := c.Classify(context.Background(), plainUser, tier0.Input{})
	if err == nil || !r.Tier0 || !r.Unknown {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestFailClosedOnGraphError(t *testing.T) {
	c, srv := setup(t)
	// The role-assignments read is the first Graph call: make the eligibility list (second) fail.
	srv.FailGraph(graphtest.Failure{Status: 200, Body: `{"value":[]}`}, graphtest.Failure{Status: 403})
	r, err := c.Classify(context.Background(), plainUser, known)
	if err == nil || !r.Tier0 || !r.Unknown {
		t.Fatalf("unreadable eligibility must refuse: %+v %v", r, err)
	}
	if graph.CodeOf(err) != graph.CodeInsufficient {
		t.Fatalf("error not reported with its code: %v", err)
	}
}

// failNth wraps a Reader and fails its nth call (1-based) with err; counts all calls.
type failNth struct {
	tier0.Reader
	n, calls int
}

var errBoom = fmt.Errorf("boom")

func (f *failNth) hit() error {
	f.calls++
	if f.calls == f.n {
		return errBoom
	}
	return nil
}
func (f *failNth) DirectoryRoleAssignments(ctx context.Context, p string) ([]graph.RoleAssignment, error) {
	if err := f.hit(); err != nil {
		return nil, err
	}
	return f.Reader.DirectoryRoleAssignments(ctx, p)
}
func (f *failNth) RoleAssignableGroups(ctx context.Context) ([]graph.Group, error) {
	if err := f.hit(); err != nil {
		return nil, err
	}
	return f.Reader.RoleAssignableGroups(ctx)
}
func (f *failNth) GroupMembers(ctx context.Context, id string) ([]graph.DirectoryObject, error) {
	if err := f.hit(); err != nil {
		return nil, err
	}
	return f.Reader.GroupMembers(ctx, id)
}
func (f *failNth) GroupOwners(ctx context.Context, id string) ([]graph.DirectoryObject, error) {
	if err := f.hit(); err != nil {
		return nil, err
	}
	return f.Reader.GroupOwners(ctx, id)
}
func (f *failNth) ServicePrincipalByAppID(ctx context.Context, id string) (graph.ServicePrincipal, error) {
	if err := f.hit(); err != nil {
		return graph.ServicePrincipal{}, err
	}
	return f.Reader.ServicePrincipalByAppID(ctx, id)
}
func (f *failNth) ServicePrincipalByID(ctx context.Context, id string) (graph.ServicePrincipal, error) {
	if err := f.hit(); err != nil {
		return graph.ServicePrincipal{}, err
	}
	return f.Reader.ServicePrincipalByID(ctx, id)
}
func (f *failNth) AppRoleAssignedTo(ctx context.Context, id string) ([]graph.AppRoleAssignment, error) {
	if err := f.hit(); err != nil {
		return nil, err
	}
	return f.Reader.AppRoleAssignedTo(ctx, id)
}
func (f *failNth) ApplicationByAppID(ctx context.Context, id string) (graph.Application, error) {
	if err := f.hit(); err != nil {
		return graph.Application{}, err
	}
	return f.Reader.ApplicationByAppID(ctx, id)
}
func (f *failNth) ApplicationOwners(ctx context.Context, id string) ([]graph.DirectoryObject, error) {
	if err := f.hit(); err != nil {
		return nil, err
	}
	return f.Reader.ApplicationOwners(ctx, id)
}
func (f *failNth) ServicePrincipalOwners(ctx context.Context, id string) ([]graph.DirectoryObject, error) {
	if err := f.hit(); err != nil {
		return nil, err
	}
	return f.Reader.ServicePrincipalOwners(ctx, id)
}

// Failing any single read of the snapshot must refuse the target as tier0 and report the error.
func TestEveryReadFailsClosed(t *testing.T) {
	cred := graphtest.NewCredential(t)
	srv := graphtest.New(t, tenant(), cred)
	cl, err := graph.New(srv.Config(cred))
	if err != nil {
		t.Fatal(err)
	}
	probe := &failNth{Reader: cl}
	if _, err := tier0.New(probe).Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probe.calls < 8 {
		t.Fatalf("suspiciously few reads: %d", probe.calls)
	}
	for n := 1; n <= probe.calls; n++ {
		r, err := tier0.New(&failNth{Reader: cl, n: n}).Classify(context.Background(), plainUser, known)
		if err == nil || !r.Tier0 || !r.Unknown {
			t.Fatalf("read %d failing: %+v %v", n, r, err)
		}
	}
}

// A role assignment whose principal type Graph did not report cannot be ruled out as an app.
func TestUnknownPrincipalTypeRefuses(t *testing.T) {
	tn := tenant()
	tn.Roles[0].PrincipalType = ""
	cred := graphtest.NewCredential(t)
	srv := graphtest.New(t, tn, cred)
	cl, _ := graph.New(srv.Config(cred))
	r, err := tier0.New(cl).Classify(context.Background(), plainUser, known)
	if err == nil || !r.Tier0 || !r.Unknown {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestSyncClientAppIsE4(t *testing.T) {
	cred := graphtest.NewCredential(t)
	srv := graphtest.New(t, tenant(), cred)
	cl, _ := graph.New(srv.Config(cred))
	r, err := tier0.New(cl, "95959595-9595-9595-9595-959595959595").Classify(context.Background(), plainSP, known)
	if err != nil || fmt.Sprint(r.Bases) != fmt.Sprint([]tier0.Basis{tier0.E4}) {
		t.Fatalf("%+v %v", r, err)
	}
}
