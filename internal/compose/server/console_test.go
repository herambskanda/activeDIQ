package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type recAuthz struct {
	err     error
	called  bool
	chain   authority.Chain
	perm    authz.Permission
	target  authority.TargetRef
	tenant  string
	tenantO bool
	facts   authority.Facts
}

func (r *recAuthz) Authorize(ctx context.Context, c authority.Chain, p authz.Permission, t authority.TargetRef, f authority.Facts) error {
	r.facts = f
	r.called, r.chain, r.perm, r.target = true, c, p, t
	r.tenant, r.tenantO = authority.TenantFrom(ctx)
	return r.err
}

func TestConsoleAuthzAllowsATenantSessionOnlyWhenRBACGrants(t *testing.T) {
	tn := tenant.New().String()
	p := apihost.Principal{ID: tenant.New().String(), Tenant: tn, Kind: apihost.KindSession, SessionID: "s"}
	ra := &recAuthz{}
	ok, err := consoleAuthz{ra, testCatalogue()}.Allow(context.Background(), p, "connections.takeover.attest", "tenant")
	if err != nil || !ok {
		t.Fatalf("allow = %v, %v", ok, err)
	}
	if ra.chain.Requester.ID != authority.PrincipalID(p.ID) || ra.chain.Requester.Kind != authority.Human || len(ra.chain.Via) != 0 ||
		ra.perm != "connections.takeover.attest" || ra.target.GUID != tn || ra.target.Class != rbac.TargetClassTenant || ra.target.Connection != "" || !ra.tenantO || ra.tenant != tn {
		t.Fatalf("authorizer saw %+v", ra)
	}
	// RBAC refusal is a clean "no"; any other error is a fault and propagates.
	if ok, err := (consoleAuthz{&recAuthz{err: rbac.ErrDenied}, testCatalogue()}).Allow(context.Background(), p, "x", "tenant"); ok || err != nil {
		t.Errorf("denied = %v, %v", ok, err)
	}
	boom := errors.New("db down")
	if ok, err := (consoleAuthz{&recAuthz{err: boom}, testCatalogue()}).Allow(context.Background(), p, "x", "tenant"); ok || !errors.Is(err, boom) {
		t.Errorf("fault = %v, %v", ok, err)
	}
}

func TestConsoleAuthzDeniesByDefault(t *testing.T) {
	good := apihost.Principal{ID: tenant.New().String(), Tenant: tenant.New().String(), Kind: apihost.KindSession}
	tok := good
	tok.Kind = apihost.KindToken
	noID := good
	noID.ID = ""
	badTenant := good
	badTenant.Tenant = "nope"
	for name, c := range map[string]struct {
		a     consoleAuthz
		p     apihost.Principal
		scope string
	}{
		"platform scope": {consoleAuthz{&recAuthz{}, testCatalogue()}, good, "platform"},
		"api token":      {consoleAuthz{&recAuthz{}, testCatalogue()}, tok, "tenant"},
		"no account":     {consoleAuthz{&recAuthz{}, testCatalogue()}, noID, "tenant"},
		"bad tenant":     {consoleAuthz{&recAuthz{}, testCatalogue()}, badTenant, "tenant"},
		"no authorizer":  {consoleAuthz{cat: testCatalogue()}, good, "tenant"},
	} {
		if ok, err := c.a.Allow(context.Background(), c.p, "x", c.scope); ok || err != nil {
			t.Errorf("%s: allowed (%v, %v)", name, ok, err)
		}
		if ra, isRec := c.a.az.(*recAuthz); isRec && ra.called {
			t.Errorf("%s: authorizer was consulted", name)
		}
	}
}

func TestSessionStepUpRefusesWithoutAStack(t *testing.T) {
	if ok, err := (sessionStepUp{}).Fresh(context.Background(), tenant.New(), "s"); ok || err != nil {
		t.Fatalf("nil step-up = %v, %v", ok, err)
	}
}

// The console stack is assembled with real authn types and mounts every port.
func TestBuildConsolePorts(t *testing.T) {
	c, err := buildConsole(&store.DB{}, nopSink{}, testKeys(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := c.ports(testLimiter(t), &recAuthz{}, testCatalogue())
	if p.Authn == nil || p.Authz == nil || p.Limits == nil || p.StepUp == nil {
		t.Fatalf("ports = %+v", p)
	}
	if _, err := buildConsole(nil, nopSink{}, testKeys(), nil); err == nil {
		t.Error("nil database accepted")
	}
}

func (*recAuthz) FactsQuery(authority.Chain, authz.Permission, authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{}
}

type memSrc struct{ as []rbac.Assignment }

func (m memSrc) Assignments(context.Context, tenant.ID, string, time.Time) ([]rbac.Assignment, error) {
	return m.as, nil
}
func (m memSrc) SubjectAssignments(context.Context, tenant.ID, rbac.Subjects, time.Time, bool) ([]rbac.Assignment, error) {
	return nil, nil
}
func (m memSrc) PendingOrActive(context.Context, tenant.ID, string, time.Time) ([]rbac.Assignment, error) {
	return m.as, nil
}

// consoleAuthz over the real rbac.Authorizer: only a tenant-store root holding the permission grants.
func TestConsoleAuthzOverRealRBAC(t *testing.T) {
	const perm = "connections.takeover.attest"
	tn, other := tenant.New(), tenant.New()
	root := func(k rbac.RootKind, conn, guid string) []rbac.Root {
		return []rbac.Root{{Kind: k, Connection: conn, GUID: guid}}
	}
	cases := map[string]struct {
		a    rbac.Assignment
		want bool
	}{
		"tenant root with permission": {rbac.Assignment{Permissions: []authz.Permission{perm}, Roots: root(rbac.TenantStore, tn.String(), tn.String())}, true},
		"entra_tenant root only":      {rbac.Assignment{Permissions: []authz.Permission{perm}, Roots: root(rbac.EntraTenant, tenant.New().String(), tenant.New().String())}, false},
		"ou subtree root only":        {rbac.Assignment{Permissions: []authz.Permission{perm}, Roots: root(rbac.OUSubtree, tenant.New().String(), tenant.New().String())}, false},
		"tier0_scope root only":       {rbac.Assignment{Permissions: []authz.Permission{perm}, Roots: root(rbac.Tier0Scope, tenant.New().String(), tenant.New().String())}, false},
		"another tenant's root":       {rbac.Assignment{Permissions: []authz.Permission{perm}, Roots: root(rbac.TenantStore, other.String(), other.String())}, false},
		"tenant root, no permission":  {rbac.Assignment{Permissions: []authz.Permission{"inventory.read"}, Roots: root(rbac.TenantStore, tn.String(), tn.String())}, false},
	}
	for name, c := range cases {
		az, err := rbac.New(memSrc{[]rbac.Assignment{c.a}})
		if err != nil {
			t.Fatal(err)
		}
		p := apihost.Principal{ID: tenant.New().String(), Tenant: tn.String(), Kind: apihost.KindSession, SessionID: "s"}
		ok, err := consoleAuthz{az, testCatalogue()}.Allow(context.Background(), p, perm, "tenant")
		if err != nil || ok != c.want {
			t.Errorf("%s: allow = %v, %v; want %v", name, ok, err, c.want)
		}
	}
}

// testCatalogue is the real catalogue plus "x", the placeholder permission some cases ask for.
func testCatalogue() apihost.Permissions { return append(permissionCatalogue(), "x") }
