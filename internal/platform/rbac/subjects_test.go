package rbac

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	tenantID = "33333333-3333-4333-8333-333333333333" // the tenant ctxT() carries
	grpGUID  = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	policy   = "77777777-7777-4777-8777-777777777777"
	rowID    = "88888888-8888-4888-8888-888888888888"
	del      = authz.Permission("objects.user.delete")
	roleMake = authz.Permission("authz.role.create")
)

type fakeMembers struct {
	g   authz.Groups
	err error
}

func (f fakeMembers) GroupsOf(context.Context, string, string) (authz.Groups, error) {
	return f.g, f.err
}

type fakeTokens struct {
	tok authz.Token
	err error
}

func (f fakeTokens) Constraint(context.Context, tenant.ID, string, string) (authz.Token, error) {
	return f.tok, f.err
}

func newAz(t *testing.T, src fakeSrc, opts ...Option) *Authorizer {
	t.Helper()
	a, err := New(src, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var (
	userTarget = authority.TargetRef{Connection: conn, GUID: obj, Class: "user", NC: "nc"}
	userFacts  = authority.Facts{Exists: true, Ancestors: []string{ouA, ncHead}, AncestorsComplete: true}
	ouRoot     = []Root{{Kind: OUSubtree, Connection: conn, GUID: ouA}}
	member     = authz.Groups{Complete: true, Groups: []authz.Group{{Connection: conn, GUID: grpGUID}}}
)

func groupAssign(perms []authz.Permission, roots []Root) Assignment {
	return Assignment{ID: "g1", Subject: SubjectGroup, GroupConn: conn, GroupGUID: grpGUID, Permissions: perms, Roots: roots}
}

// DM-36.I2: a member of a group-subject assignment gets the grant, and only a member does.
func TestGroupSubjectGrantAppliesToMembers(t *testing.T) {
	ga := groupAssign([]authz.Permission{del}, ouRoot)
	cases := []struct {
		name  string
		opts  []Option
		allow bool
	}{
		{"member", []Option{WithMembership(fakeMembers{g: member})}, true},
		{"not a member", []Option{WithMembership(fakeMembers{g: authz.Groups{Complete: true, Groups: []authz.Group{{Connection: conn, GUID: ouB}}}})}, false},
		{"incomplete membership grants nothing", []Option{WithMembership(fakeMembers{g: authz.Groups{Groups: member.Groups}})}, false},
		{"no membership port", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newAz(t, fakeSrc{sub: []Assignment{ga}, as: []Assignment{{ID: "own", Permissions: []authz.Permission{"x.y"}}}}, c.opts...)
			err := a.Authorize(ctxT(), human(acct), del, userTarget, userFacts)
			if c.allow != (err == nil) {
				t.Fatalf("allow=%v got %v", c.allow, err)
			}
		})
	}
	t.Run("membership read error is an error, not a grant", func(t *testing.T) {
		a := newAz(t, fakeSrc{sub: []Assignment{ga}}, WithMembership(fakeMembers{err: errors.New("down")}))
		if err := a.Authorize(ctxT(), human(acct), del, userTarget, userFacts); err == nil || errors.Is(err, ErrDenied) {
			t.Fatalf("want a plain error, got %v", err)
		}
	})
	t.Run("group grant stays inside its scope", func(t *testing.T) {
		a := newAz(t, fakeSrc{sub: []Assignment{groupAssign([]authz.Permission{del}, []Root{{Kind: OUSubtree, Connection: conn, GUID: ouB}})}}, WithMembership(fakeMembers{g: member}))
		if err := a.Authorize(ctxT(), human(acct), del, userTarget, userFacts); !errors.Is(err, ErrDenied) {
			t.Fatalf("got %v", err)
		}
	})
}

// DM-36.I4: no group grant carries tenant-owner or a control-plane permission, even if one is stored.
func TestGroupSubjectNeverCarriesControlPlane(t *testing.T) {
	storeT := authority.TargetRef{GUID: rowID, Class: "role"}
	roots := []Root{{Kind: TenantStore, Connection: tenantID, GUID: tenantID}}
	a := newAz(t, fakeSrc{sub: []Assignment{groupAssign([]authz.Permission{roleMake}, roots)}}, WithMembership(fakeMembers{g: member}))
	if err := a.Authorize(ctxT(), human(acct), roleMake, storeT, authority.Facts{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("control-plane permission through a group: %v", err)
	}
	own := newAz(t, fakeSrc{as: []Assignment{{ID: "a", Permissions: []authz.Permission{roleMake}, Roots: roots}}})
	if err := own.Authorize(ctxT(), human(acct), roleMake, storeT, authority.Facts{}); err != nil {
		t.Fatalf("personal grant: %v", err)
	}
	owner := groupAssign([]authz.Permission{del}, ouRoot)
	owner.TenantOwner = true
	b := newAz(t, fakeSrc{sub: []Assignment{owner}}, WithMembership(fakeMembers{g: member}))
	if err := b.Authorize(ctxT(), human(acct), del, userTarget, userFacts); !errors.Is(err, ErrDenied) {
		t.Fatalf("tenant-owner through a group: %v", err)
	}
}

// A correlation-derived membership applies only while the correlation gate passes.
func TestGroupSubjectCorrelationDerivedIsGated(t *testing.T) {
	ga := groupAssign([]authz.Permission{del}, ouRoot)
	run := func(c *authz.Correlation) error {
		m := authz.Groups{Complete: true, Groups: []authz.Group{{Connection: conn, GUID: grpGUID, Via: &authz.Derivation{Correlation: c}}}}
		return newAz(t, fakeSrc{sub: []Assignment{ga}}, WithMembership(fakeMembers{g: m})).Authorize(authority.WithAuthorityFactor(ctxT(), true), human(acct), del, userTarget, userFacts)
	}
	if err := run(&authz.Correlation{State: authz.CorrelationMatched, Takeover: authz.TakeoverAttested}); err != nil {
		t.Fatalf("matched and attested: %v", err)
	}
	for name, c := range map[string]*authz.Correlation{
		"candidate":  {State: "candidate", Takeover: authz.TakeoverAttested},
		"unattested": {State: authz.CorrelationMatched},
		"tier0":      {State: authz.CorrelationMatched, Takeover: authz.TakeoverAttested, Tier0Either: true},
		"no facts":   nil,
	} {
		if err := run(c); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Store targets are covered by a tenant-wide root and by nothing else; the tenant root covers no directory object.
func TestStoreTargetsNeedATenantRoot(t *testing.T) {
	storeT := authority.TargetRef{GUID: rowID, Class: "role"}
	tr := Root{Kind: TenantStore, Connection: tenantID, GUID: tenantID}
	p := []authz.Permission{roleMake}
	cases := []struct {
		name  string
		roots []Root
		allow bool
	}{
		{"tenant root", []Root{tr}, true},
		{"no roots", nil, false},
		{"OU root", ouRoot, false},
		{"connection-wide root", []Root{{Kind: EntraTenant, Connection: conn, GUID: conn}}, false},
		{"tier0 scope root", []Root{{Kind: Tier0Scope, Connection: conn, GUID: conn}}, false},
		{"tenant root of another tenant", []Root{{Kind: TenantStore, Connection: conn2, GUID: conn2}}, false},
		{"tenant root with a mismatched connection", []Root{{Kind: TenantStore, Connection: conn2, GUID: tenantID}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newAz(t, fakeSrc{as: []Assignment{{ID: "a", Permissions: p, Roots: c.roots}}})
			err := a.Authorize(ctxT(), human(acct), roleMake, storeT, authority.Facts{})
			if c.allow != (err == nil) {
				t.Fatalf("allow=%v got %v", c.allow, err)
			}
		})
	}
	t.Run("tenant root does not cover a directory object", func(t *testing.T) {
		a := newAz(t, fakeSrc{as: []Assignment{{ID: "a", Permissions: []authz.Permission{del}, Roots: []Root{tr}}}})
		if err := a.Authorize(ctxT(), human(acct), del, userTarget, userFacts); !errors.Is(err, ErrDenied) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("tenant root does not cover tier0 scope", func(t *testing.T) {
		a := newAz(t, fakeSrc{as: []Assignment{{ID: "a", Permissions: []authz.Permission{manage}, Roots: []Root{tr}}}})
		if err := a.Authorize(ctxT(), human(acct), manage, scopeTarget, authority.Facts{Exists: true}); !errors.Is(err, ErrDenied) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("store target that is not a GUID", func(t *testing.T) {
		a := newAz(t, fakeSrc{as: []Assignment{{ID: "a", Permissions: p, Roots: []Root{tr}}}})
		if err := a.Authorize(ctxT(), human(acct), roleMake, authority.TargetRef{GUID: "roles/1", Class: "role"}, authority.Facts{}); !errors.Is(err, ErrDenied) {
			t.Fatalf("got %v", err)
		}
	})
}

func tokenChain(via ...authority.Principal) authority.Chain {
	c := human(acct)
	c.Via = via
	return c
}

var apiTok = authority.Principal{ID: "tok-1", Kind: authority.APIToken}

// DM-32.I1: a token intersects its owner's authority.
func TestAPITokenConstrainsTheOwner(t *testing.T) {
	src := fakeSrc{as: []Assignment{{ID: "a", Permissions: []authz.Permission{del, "objects.user.unlock"}, Roots: ouRoot}}}
	future := time.Now().Add(time.Hour)
	run := func(opts ...Option) func(authz.Permission) error {
		a := newAz(t, src, opts...)
		return func(p authz.Permission) error {
			return a.Authorize(ctxT(), tokenChain(apiTok), p, userTarget, userFacts)
		}
	}
	ok := run(WithTokens(fakeTokens{tok: authz.Token{Permissions: []authz.Permission{del}, ExpiresAt: future}}))
	if err := ok(del); err != nil {
		t.Fatalf("subset: %v", err)
	}
	if err := ok("objects.user.unlock"); !errors.Is(err, ErrDenied) {
		t.Fatalf("outside the subset: %v", err)
	}
	narrow := authz.Scope{Include: []authz.ScopeRoot{{ID: mustID(t, ouB)}}}
	n := run(WithTokens(fakeTokens{tok: authz.Token{Permissions: []authz.Permission{del}, ExpiresAt: future, Scope: &narrow}}))
	if err := n(del); !errors.Is(err, ErrDenied) {
		t.Fatalf("outside the token's scope narrowing: %v", err)
	}
	if err := run(WithTokens(fakeTokens{tok: authz.Token{Permissions: []authz.Permission{del}, ExpiresAt: time.Now().Add(-time.Second)}}))(del); !errors.Is(err, ErrDenied) {
		t.Fatalf("expired: %v", err)
	}
	if err := run(WithTokens(fakeTokens{err: errors.New("revoked")}))(del); !errors.Is(err, ErrDenied) {
		t.Fatalf("unusable token: %v", err)
	}
	if err := run()(del); !errors.Is(err, ErrDenied) {
		t.Fatalf("no token source must refuse: %v", err)
	}
}

func mustID(t *testing.T, s string) authz.ObjectID {
	t.Helper()
	id, err := authz.ParseObjectID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// DM-60.I2: an automation policy acts as its own subject; the run needs both the requester's and the policy's grant.
func TestAutomationPolicyNeedsItsOwnGrant(t *testing.T) {
	auto := authority.Principal{ID: policy, Kind: authority.Automation}
	owner := []Assignment{{ID: "a", Permissions: []authz.Permission{del}, Roots: ouRoot}}
	run := func(sub []Assignment) error {
		return newAz(t, fakeSrc{as: owner, sub: sub}).Authorize(ctxT(), tokenChain(auto), del, userTarget, userFacts)
	}
	pol := func(perms []authz.Permission, roots []Root) Assignment {
		return Assignment{ID: "p", Subject: SubjectAutomation, Permissions: perms, Roots: roots}
	}
	if err := run([]Assignment{pol([]authz.Permission{del}, ouRoot)}); err != nil {
		t.Fatalf("both grant: %v", err)
	}
	if err := run(nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("policy with no assignment: %v", err)
	}
	if err := run([]Assignment{pol([]authz.Permission{del}, []Root{{Kind: OUSubtree, Connection: conn, GUID: ouB}})}); !errors.Is(err, ErrDenied) {
		t.Fatalf("policy scoped elsewhere: %v", err)
	}
	if err := run([]Assignment{pol([]authz.Permission{roleMake}, ouRoot)}); !errors.Is(err, ErrDenied) {
		t.Fatalf("policy without the permission: %v", err)
	}
}

func TestChainShapesRefused(t *testing.T) {
	a := newAz(t, fakeSrc{as: []Assignment{{ID: "a", Permissions: []authz.Permission{del}, Roots: ouRoot}}}, WithTokens(fakeTokens{tok: authz.Token{Permissions: []authz.Permission{del}, ExpiresAt: time.Now().Add(time.Hour)}}))
	for name, c := range map[string]authority.Chain{
		"two tokens":           tokenChain(apiTok, apiTok),
		"system via":           tokenChain(authority.Principal{ID: "s", Kind: authority.System}),
		"token requester":      {Requester: apiTok},
		"automation requester": {Requester: authority.Principal{ID: policy, Kind: authority.Automation}},
	} {
		if err := a.Authorize(ctxT(), c, del, userTarget, userFacts); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
