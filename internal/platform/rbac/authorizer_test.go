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
	conn   = "11111111-1111-4111-8111-111111111111"
	conn2  = "22222222-2222-4222-8222-222222222222"
	ouA    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	ouB    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	obj    = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	ncHead = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	acct   = "99999999-9999-4999-8999-999999999999"
	manage = authz.Permission("inventory.tier0_designation.manage")
)

type fakeSrc struct {
	as  []Assignment
	err error
}

func (f fakeSrc) Assignments(context.Context, tenant.ID, string, time.Time) ([]Assignment, error) {
	return f.as, f.err
}

func human(id string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(id), Kind: authority.Human}}
}

func ctxT() context.Context {
	return authority.WithTenant(context.Background(), "33333333-3333-4333-8333-333333333333")
}

func az(t *testing.T, as ...Assignment) *Authorizer {
	t.Helper()
	a, err := New(fakeSrc{as: as})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

var scopeTarget = authority.TargetRef{Connection: conn, GUID: conn, Class: TargetClassTier0Scope}

func TestTier0ScopeIsCoveredOnlyByAnExplicitTier0ScopeGrant(t *testing.T) {
	manageP := []authz.Permission{manage}
	cases := []struct {
		name  string
		roots []Root
		allow bool
	}{
		{"connection-wide entra_tenant root", []Root{{Kind: EntraTenant, Connection: conn, GUID: conn}}, false},
		{"naming-context root", []Root{{Kind: NamingContext, Connection: conn, GUID: ncHead}}, false},
		{"OU root", []Root{{Kind: OUSubtree, Connection: conn, GUID: ouA}}, false},
		{"OU root whose GUID equals the connection", []Root{{Kind: OUSubtree, Connection: conn, GUID: conn}}, false},
		{"no roots", nil, false},
		{"tier0_scope for another connection", []Root{{Kind: Tier0Scope, Connection: conn2, GUID: conn2}}, false},
		{"tier0_scope exclude", []Root{{Kind: Tier0Scope, Connection: conn, GUID: conn, Exclude: true}}, false},
		{"explicit tier0_scope for the connection", []Root{{Kind: Tier0Scope, Connection: conn, GUID: conn}}, true},
		{"tier0_scope plus unrelated roots", []Root{{Kind: EntraTenant, Connection: conn, GUID: conn}, {Kind: Tier0Scope, Connection: conn, GUID: conn}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := az(t, Assignment{ID: "a1", Permissions: manageP, Roots: c.roots})
			// The facts the live reader returns for a tier0_scope target: exists, not tier0, no chain.
			err := a.Authorize(ctxT(), human(acct), manage, scopeTarget, authority.Facts{Exists: true})
			if c.allow && err != nil {
				t.Fatalf("want allowed, got %v", err)
			}
			if !c.allow && !errors.Is(err, ErrDenied) {
				t.Fatalf("want denied, got %v", err)
			}
		})
	}
}

func TestTier0ScopeGrantWithoutThePermissionIsDenied(t *testing.T) {
	a := az(t, Assignment{ID: "a1", Permissions: []authz.Permission{"objects.user.delete"}, Roots: []Root{{Kind: Tier0Scope, Connection: conn, GUID: conn}}})
	if err := a.Authorize(ctxT(), human(acct), manage, scopeTarget, authority.Facts{Exists: true}); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestTier0ScopeGrantCoversNothingElse(t *testing.T) {
	a := az(t, Assignment{ID: "a1", Permissions: []authz.Permission{manage, "objects.user.delete"}, Roots: []Root{{Kind: Tier0Scope, Connection: conn, GUID: conn}}})
	tgt := authority.TargetRef{Connection: conn, GUID: obj, Class: "user", NC: "nc"}
	f := authority.Facts{Exists: true, Ancestors: []string{ouA, ncHead}, AncestorsComplete: true}
	if err := a.Authorize(ctxT(), human(acct), "objects.user.delete", tgt, f); !errors.Is(err, ErrDenied) {
		t.Fatalf("a tier0_scope grant must not cover an object: %v", err)
	}
	// The Tier-0 scope permission is refused on a non-scope target even when a root would cover it.
	b := az(t, Assignment{ID: "a2", Permissions: []authz.Permission{manage}, Roots: []Root{{Kind: EntraTenant, Connection: conn, GUID: conn}}})
	if err := b.Authorize(ctxT(), human(acct), manage, tgt, f); !errors.Is(err, ErrDenied) {
		t.Fatalf("manage on an object: %v", err)
	}
}

func objectCase(t *testing.T, roots []Root, f authority.Facts) error {
	t.Helper()
	a := az(t, Assignment{ID: "a1", Permissions: []authz.Permission{"objects.user.delete"}, Roots: roots})
	return a.Authorize(ctxT(), human(acct), "objects.user.delete", authority.TargetRef{Connection: conn, GUID: obj, Class: "user", NC: "nc"}, f)
}

func TestObjectScopeDecidedThroughTheEvaluator(t *testing.T) {
	chain := authority.Facts{Exists: true, Ancestors: []string{ouA, ncHead}, AncestorsComplete: true}
	ou := func(g string, ex bool) Root { return Root{Kind: OUSubtree, Connection: conn, GUID: g, Exclude: ex} }
	if err := objectCase(t, []Root{ou(ouA, false)}, chain); err != nil {
		t.Fatalf("OU grant over the chain: %v", err)
	}
	if err := objectCase(t, []Root{ou(ouB, false)}, chain); !errors.Is(err, ErrDenied) {
		t.Fatalf("other OU: %v", err)
	}
	if err := objectCase(t, []Root{{Kind: NamingContext, Connection: conn, GUID: ncHead}}, chain); err != nil {
		t.Fatalf("naming-context grant: %v", err)
	}
	if err := objectCase(t, []Root{{Kind: EntraTenant, Connection: conn, GUID: conn}}, chain); err != nil {
		t.Fatalf("connection-wide grant over an object: %v", err)
	}
	if err := objectCase(t, []Root{{Kind: EntraTenant, Connection: conn2, GUID: conn2}}, chain); !errors.Is(err, ErrDenied) {
		t.Fatalf("other connection: %v", err)
	}
	if err := objectCase(t, []Root{ou(ouA, false), ou(ncHead, true)}, chain); !errors.Is(err, ErrDenied) {
		t.Fatalf("exclude beats include: %v", err)
	}
	if err := objectCase(t, []Root{ou(ouA, false), {Kind: OUSubtree, Connection: conn, GUID: "not-a-guid", Exclude: true}}, chain); !errors.Is(err, ErrDenied) {
		t.Fatalf("an exclude that cannot be resolved must narrow: %v", err)
	}
	if err := objectCase(t, []Root{{Kind: Tier0Scope, Connection: conn, GUID: conn}}, chain); !errors.Is(err, ErrDenied) {
		t.Fatalf("tier0_scope root over an object: %v", err)
	}
}

func TestObjectFactsThatAreIncompleteOrTier0AreRefused(t *testing.T) {
	roots := []Root{{Kind: OUSubtree, Connection: conn, GUID: ouA}}
	for name, f := range map[string]authority.Facts{
		"chain incomplete": {Exists: true, Ancestors: []string{ouA}},
		"no object":        {Ancestors: []string{ouA}, AncestorsComplete: true},
		"tier0":            {Exists: true, Tier0: true, Ancestors: []string{ouA}, AncestorsComplete: true},
		"bad chain GUID":   {Exists: true, Ancestors: []string{"nope"}, AncestorsComplete: true},
	} {
		if err := objectCase(t, roots, f); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestChainsAndContextsThatCannotBeAuthorisedAreRefused(t *testing.T) {
	a := az(t, Assignment{ID: "a1", Permissions: []authz.Permission{manage}, Roots: []Root{{Kind: Tier0Scope, Connection: conn, GUID: conn}}})
	ok := authority.Facts{Exists: true}
	via := human(acct)
	via.Via = []authority.Principal{{ID: "tok", Kind: authority.APIToken}}
	auto := authority.Chain{Requester: authority.Principal{ID: acct, Kind: authority.Automation}}
	for name, c := range map[string]authority.Chain{"token in chain": via, "automation": auto, "empty": {}} {
		if err := a.Authorize(ctxT(), c, manage, scopeTarget, ok); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := a.Authorize(context.Background(), human(acct), manage, scopeTarget, ok); !errors.Is(err, ErrDenied) {
		t.Errorf("no tenant: %v", err)
	}
	if err := a.Authorize(authority.WithTenant(context.Background(), "x"), human(acct), manage, scopeTarget, ok); !errors.Is(err, ErrDenied) {
		t.Errorf("bad tenant: %v", err)
	}
	bad := authority.TargetRef{Connection: conn, GUID: "nope", Class: TargetClassTier0Scope}
	if err := a.Authorize(ctxT(), human(acct), manage, bad, ok); !errors.Is(err, ErrDenied) {
		t.Errorf("bad scope GUID: %v", err)
	}
	mismatch := authority.TargetRef{Connection: conn2, GUID: conn, Class: TargetClassTier0Scope}
	if err := a.Authorize(ctxT(), human(acct), manage, mismatch, ok); !errors.Is(err, ErrDenied) {
		t.Errorf("connection/GUID mismatch: %v", err)
	}
}

func TestSourceErrorIsNotADecision(t *testing.T) {
	a, _ := New(fakeSrc{err: errors.New("db down")})
	err := a.Authorize(ctxT(), human(acct), manage, scopeTarget, authority.Facts{Exists: true})
	if err == nil || errors.Is(err, ErrDenied) {
		t.Fatalf("got %v, want a non-denial error", err)
	}
}

func TestFactsQueryAsksNothingAboutAScopeAndTier0AndAncestryAboutAnObject(t *testing.T) {
	a := az(t)
	q := a.FactsQuery(human(acct), manage, scopeTarget)
	if q.Tier0 || q.Ancestry {
		t.Fatalf("scope query = %+v", q)
	}
	q = a.FactsQuery(human(acct), "objects.user.delete", authority.TargetRef{Connection: conn, GUID: obj, Class: "user"})
	if !q.Tier0 || !q.Ancestry {
		t.Fatalf("object query = %+v", q)
	}
}

func TestNewRefusesNoSource(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("want error")
	}
}

// Acceptance 4: enumerate the roles; the permission is in no Tier-2 role.
func TestTier0ScopePermissionIsInNoTier2Role(t *testing.T) {
	if err := ValidateRoles(BuiltInRoles()); err != nil {
		t.Fatal(err)
	}
	for _, r := range BuiltInRoles() {
		for _, p := range r.Permissions {
			if p == manage && r.Tier != Tier0 {
				t.Errorf("role %q (tier %d) holds %s", r.Name, r.Tier, p)
			}
		}
	}
	if err := ValidateRoles([]Role{{Name: "x", Tier: Tier2, Permissions: []authz.Permission{manage}}}); err == nil {
		t.Fatal("ValidateRoles must refuse a Tier-2 role holding the permission")
	}
}
