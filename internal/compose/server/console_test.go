package server

import (
	"context"
	"errors"
	"testing"

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
}

func (r *recAuthz) Authorize(ctx context.Context, c authority.Chain, p authz.Permission, t authority.TargetRef, _ authority.Facts) error {
	r.called, r.chain, r.perm, r.target = true, c, p, t
	r.tenant, r.tenantO = authority.TenantFrom(ctx)
	return r.err
}

func TestConsoleAuthzAllowsATenantSessionOnlyWhenRBACGrants(t *testing.T) {
	tn := tenant.New().String()
	p := apihost.Principal{ID: tenant.New().String(), Tenant: tn, Kind: apihost.KindSession, SessionID: "s"}
	ra := &recAuthz{}
	ok, err := consoleAuthz{ra}.Allow(context.Background(), p, "connections.takeover.attest", "tenant")
	if err != nil || !ok {
		t.Fatalf("allow = %v, %v", ok, err)
	}
	if ra.chain.Requester.ID != authority.PrincipalID(p.ID) || ra.chain.Requester.Kind != authority.Human || len(ra.chain.Via) != 0 ||
		ra.perm != "connections.takeover.attest" || ra.target.GUID != tn || ra.target.Connection != "" || !ra.tenantO || ra.tenant != tn {
		t.Fatalf("authorizer saw %+v", ra)
	}
	// RBAC refusal is a clean "no"; any other error is a fault and propagates.
	if ok, err := (consoleAuthz{&recAuthz{err: rbac.ErrDenied}}).Allow(context.Background(), p, "x", "tenant"); ok || err != nil {
		t.Errorf("denied = %v, %v", ok, err)
	}
	boom := errors.New("db down")
	if ok, err := (consoleAuthz{&recAuthz{err: boom}}).Allow(context.Background(), p, "x", "tenant"); ok || !errors.Is(err, boom) {
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
		"platform scope": {consoleAuthz{&recAuthz{}}, good, "platform"},
		"api token":      {consoleAuthz{&recAuthz{}}, tok, "tenant"},
		"no account":     {consoleAuthz{&recAuthz{}}, noID, "tenant"},
		"bad tenant":     {consoleAuthz{&recAuthz{}}, badTenant, "tenant"},
		"no authorizer":  {consoleAuthz{}, good, "tenant"},
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
	c, err := buildConsole(&store.DB{}, nopSink{})
	if err != nil {
		t.Fatal(err)
	}
	p := c.ports(testLimiter(t), &recAuthz{})
	if p.Authn == nil || p.Authz == nil || p.Limits == nil || p.StepUp == nil {
		t.Fatalf("ports = %+v", p)
	}
	if _, err := buildConsole(nil, nopSink{}); err == nil {
		t.Error("nil database accepted")
	}
}

func (*recAuthz) FactsQuery(authority.Chain, authz.Permission, authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{}
}
