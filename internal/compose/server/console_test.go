package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/authn"
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

// The relying party is the public URL's origin: RP ID without the port, exactly one origin, nothing else.
func TestWebAuthnRelyingPartyFromPublicURL(t *testing.T) {
	for in, want := range map[string]authn.WebAuthnConfig{
		"https://diq.example.com":      {RPID: "diq.example.com", RPDisplayName: "activeDIQ", Origins: []string{"https://diq.example.com"}},
		"https://diq.example.com/":     {RPID: "diq.example.com", RPDisplayName: "activeDIQ", Origins: []string{"https://diq.example.com"}},
		"https://DIQ.Example.com:443":  {RPID: "diq.example.com", RPDisplayName: "activeDIQ", Origins: []string{"https://diq.example.com"}},
		"https://diq.example.com:8443": {RPID: "diq.example.com", RPDisplayName: "activeDIQ", Origins: []string{"https://diq.example.com:8443"}},
	} {
		got, err := webAuthnRelyingParty(in)
		if err != nil || got.RPID != want.RPID || len(got.Origins) != 1 || got.Origins[0] != want.Origins[0] {
			t.Errorf("%s: %+v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "https://10.0.0.5", "https://[::1]", "https://diq.example.com.", "http://diq.example.com", "https://diq.example.com/x", "https://u:p@diq.example.com", "https://diq.example.com/?a=b", "diq.example.com", "https://"} {
		if _, err := webAuthnRelyingParty(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Without a public URL the stack has no WebAuthn factor, so Tags leaves the interface nil (a typed nil
// would turn the 501 into a panic); with one it is built over the shared stores.
func TestBuildConsoleWebAuthnOnlyWithPublicURL(t *testing.T) {
	off, err := buildConsole(&store.DB{}, nopSink{}, testKeys(), nil)
	if err != nil || off.WebAuthn != nil {
		t.Fatalf("off: %v %v", off.WebAuthn, err)
	}
	on, err := buildConsole(&store.DB{}, nopSink{}, testKeys(), nil, withPublicURL("https://diq.example.com"))
	if err != nil || on.WebAuthn == nil {
		t.Fatalf("on: %v %v", on.WebAuthn, err)
	}
	if _, err := buildConsole(&store.DB{}, nopSink{}, testKeys(), nil, withPublicURL("http://diq.example.com")); err == nil {
		t.Error("a non-https public URL built a relying party")
	}
}

// T-0861: the WebAuthn origin and the attestation redirect URI come from the same canonical value, however
// the operator spelled the URL.
func TestRelyingPartyAndRedirectURIShareOneCanonicalOrigin(t *testing.T) {
	for _, in := range []string{"https://DIQ.Example.com:443", "https://diq.example.com/", "https://Diq.example.com:443/"} {
		rp, err := webAuthnRelyingParty(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		po, err := config.ParsePublicURL(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		redirect := po.Origin + attestCallbackPath
		if rp.Origins[0] != po.Origin || !strings.HasPrefix(redirect, rp.Origins[0]+"/") || rp.RPID != "diq.example.com" {
			t.Errorf("%s: rp %+v, redirect %s", in, rp, redirect)
		}
		// The loaded config carries the canonical origin, so buildAttestation sees the same bytes.
		c, err := config.Load(func(k string) string {
			if k == config.EnvPublicURL {
				return in
			}
			return ""
		})
		if err != nil || c.PublicURL != rp.Origins[0] {
			t.Errorf("%s: loaded %q, rp origin %q, %v", in, c.PublicURL, rp.Origins[0], err)
		}
	}
}
