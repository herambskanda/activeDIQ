package authz_test

import (
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// TM-F-AUTHZ (threat-model §7.7, §15), CI half. Covers TM-TB1-T8/T11/T12, TM-TB2-T8, TM-TB15-T2.
// Black-box over the exported evaluator only. Each case is an attack from the §7.7 proof list and
// must be refused. The Samba-lab half (live parent chain from a DC, role-granting AD group DACLs)
// is a separate follow-up that depends on ScopedSearch (T-0115).

var clock = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func evaluator() authz.Evaluator { return authz.Evaluator{Now: func() time.Time { return clock }} }

func id(name string) authz.ObjectID {
	var o authz.ObjectID
	o[0] = 0xBB
	copy(o[1:], name)
	return o
}

func root(name string, anc ...string) authz.ScopeRoot {
	r := authz.ScopeRoot{ID: id(name), Complete: true}
	for _, a := range anc {
		r.Ancestors = append(r.Ancestors, id(a))
	}
	return r
}

func obj(name string, anc ...string) authz.Target {
	t := authz.Target{ID: id(name), Complete: true}
	for _, a := range anc {
		t.Ancestors = append(t.Ancestors, id(a))
	}
	return t
}

func scope(r ...authz.ScopeRoot) authz.Scope { return authz.Scope{Include: r} }

const (
	reset  authz.Permission = "objects.user.reset_password"
	del    authz.Permission = "objects.user.delete"
	rbac   authz.Permission = "rbac.assign"
	domain                  = "domain"
)

func holder(name string, perms []authz.Permission, s authz.Scope) *authz.Principal {
	return &authz.Principal{ID: name, Assignments: []authz.Assignment{{Role: authz.Role{Permissions: perms}, Scope: s}}}
}

func TestTMFAuthz(t *testing.T) {
	e := evaluator()
	sales := scope(root("ou-sales", domain))
	tech := holder("tech", []authz.Permission{reset}, sales)

	t.Run("scope escape: user in a sibling OU is refused", func(t *testing.T) {
		d := e.Authorize(tech, nil, reset, obj("bob", "ou-finance", domain))
		if d.Allowed || d.Reason != authz.ReasonNotInScope {
			t.Fatalf("got %+v", d)
		}
	})
	t.Run("scope escape: sub-OU excluded from the delegation is refused", func(t *testing.T) {
		s := authz.Scope{Include: []authz.ScopeRoot{root("ou-sales", domain)}, Exclude: []authz.ScopeRoot{root("ou-execs", "ou-sales", domain)}}
		p := holder("tech", []authz.Permission{reset}, s)
		if d := e.Authorize(p, nil, reset, obj("ceo", "ou-execs", "ou-sales", domain)); d.Allowed {
			t.Fatalf("excluded sub-OU allowed: %+v", d)
		}
		if d := e.Authorize(p, nil, reset, obj("amy", "ou-sales", domain)); !d.Allowed {
			t.Fatalf("control: in-scope user refused: %+v", d)
		}
	})
	t.Run("scope escape: permission not in the role is refused inside scope", func(t *testing.T) {
		if d := e.Authorize(tech, nil, del, obj("amy", "ou-sales", domain)); d.Allowed {
			t.Fatalf("got %+v", d)
		}
	})
	t.Run("scope escape: tier0 target is refused even for a domain-wide role", func(t *testing.T) {
		p := holder("admin", []authz.Permission{reset}, scope(root(domain)))
		tg := obj("krbtgt", domain)
		tg.Tier0 = true
		if d := e.Authorize(p, nil, reset, tg); d.Allowed || d.Reason != authz.ReasonTier0 {
			t.Fatalf("got %+v", d)
		}
	})
	t.Run("scope escape: unresolved or zero facts fail closed", func(t *testing.T) {
		incomplete := obj("amy", "ou-sales", domain)
		incomplete.Complete = false
		if d := e.Authorize(tech, nil, reset, incomplete); d.Allowed {
			t.Fatalf("incomplete chain allowed: %+v", d)
		}
		if d := e.Authorize(tech, nil, reset, authz.Target{Complete: true}); d.Allowed {
			t.Fatalf("zero target allowed: %+v", d)
		}
	})

	t.Run("move between check and write: Plan allows, Apply re-reads the live chain and refuses", func(t *testing.T) {
		atPlan := obj("amy", "ou-sales", domain)
		if d := e.Authorize(tech, nil, reset, atPlan); !d.Allowed {
			t.Fatalf("plan-time control refused: %+v", d)
		}
		atApply := obj("amy", "ou-finance", domain) // same objectGUID, moved out of scope
		if d := e.Authorize(tech, nil, reset, atApply); d.Allowed {
			t.Fatalf("moved object allowed at Apply: %+v", d)
		}
		atApply.Complete = false // live re-read failed: must not fall back to the Plan facts
		if d := e.Authorize(tech, nil, reset, atApply); d.Allowed {
			t.Fatalf("unreadable chain at Apply allowed: %+v", d)
		}
	})

	t.Run("bulk: one out-of-scope item is refused, the others are reported per row", func(t *testing.T) {
		items := []authz.Target{obj("a", "ou-sales", domain), obj("b", "ou-finance", domain), obj("c", "ou-sales", domain)}
		res := e.AuthorizeItems(tech, nil, reset, items)
		if res.Allowed != 2 || res.Refused != 1 || len(res.Items) != 3 {
			t.Fatalf("got allowed=%d refused=%d items=%d", res.Allowed, res.Refused, len(res.Items))
		}
		if !res.Items[0].Allowed || res.Items[1].Allowed || !res.Items[2].Allowed {
			t.Fatalf("per-row result wrong: %+v", res.Items)
		}
	})
	t.Run("bulk: a dead owner refuses every item", func(t *testing.T) {
		dead := *tech
		dead.Disabled = true
		if res := e.AuthorizeItems(&dead, nil, reset, []authz.Target{obj("a", "ou-sales", domain)}); res.Allowed != 0 {
			t.Fatalf("got %+v", res)
		}
	})

	t.Run("self-escalation: grant of a role the grantor does not hold is refused", func(t *testing.T) {
		err := e.CheckGrant(tech, nil, authz.Role{Permissions: []authz.Permission{reset, rbac}}, sales)
		if !errors.Is(err, authz.ErrEscalation) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("self-escalation: grant over a wider scope than the grantor holds is refused", func(t *testing.T) {
		err := e.CheckGrant(tech, nil, authz.Role{Permissions: []authz.Permission{reset}}, scope(root(domain)))
		if !errors.Is(err, authz.ErrEscalation) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("self-escalation: a token cannot grant what the token lacks", func(t *testing.T) {
		both := holder("tech", []authz.Permission{reset, rbac}, sales)
		tok := &authz.Token{Permissions: []authz.Permission{reset}, ExpiresAt: clock.Add(time.Hour)}
		err := e.CheckGrant(both, tok, authz.Role{Permissions: []authz.Permission{rbac}}, sales)
		if !errors.Is(err, authz.ErrEscalation) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("self-escalation: unresolved scope facts fail closed", func(t *testing.T) {
		bad := authz.ScopeRoot{ID: id("ou-sales")} // not Complete
		err := e.CheckGrant(tech, nil, authz.Role{Permissions: []authz.Permission{reset}}, scope(bad))
		if !errors.Is(err, authz.ErrFactsIncomplete) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("self-escalation: empty role or scope is refused", func(t *testing.T) {
		if err := e.CheckGrant(tech, nil, authz.Role{}, sales); !errors.Is(err, authz.ErrInvalidGrant) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("dead-owner token: disabled owner kills the token", func(t *testing.T) {
		owner := holder("owner", []authz.Permission{reset}, sales)
		tok := &authz.Token{Permissions: []authz.Permission{reset}, ExpiresAt: clock.Add(time.Hour)}
		if err := e.CheckToken(owner, tok); err != nil {
			t.Fatalf("control: %v", err)
		}
		owner.Disabled = true
		if err := e.CheckToken(owner, tok); !errors.Is(err, authz.ErrOwnerDead) {
			t.Fatalf("got %v", err)
		}
		if d := e.Authorize(owner, tok, reset, obj("amy", "ou-sales", domain)); d.Allowed {
			t.Fatalf("disabled owner's token authorised: %+v", d)
		}
	})
	t.Run("dead-owner token: owner who lost all authority kills the token", func(t *testing.T) {
		owner := &authz.Principal{ID: "owner"}
		tok := &authz.Token{Permissions: []authz.Permission{reset}, ExpiresAt: clock.Add(time.Hour)}
		if err := e.CheckToken(owner, tok); !errors.Is(err, authz.ErrOwnerDead) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("token beyond its owner: permission and scope exceed the owner's", func(t *testing.T) {
		tok := &authz.Token{Permissions: []authz.Permission{reset, del}, ExpiresAt: clock.Add(time.Hour)}
		if d := e.Authorize(tech, tok, del, obj("amy", "ou-sales", domain)); d.Allowed {
			t.Fatalf("token granted a permission the owner lacks: %+v", d)
		}
		wide := &authz.Token{Permissions: []authz.Permission{reset}, ExpiresAt: clock.Add(time.Hour), Scope: &authz.Scope{Include: []authz.ScopeRoot{root(domain)}}}
		if d := e.Authorize(tech, wide, reset, obj("bob", "ou-finance", domain)); d.Allowed {
			t.Fatalf("token scope widened the owner's: %+v", d)
		}
	})
	t.Run("dead-owner token: expired and no-expiry tokens are refused", func(t *testing.T) {
		for name, exp := range map[string]time.Time{"expired": clock.Add(-time.Second), "no expiry": {}} {
			tok := &authz.Token{Permissions: []authz.Permission{reset}, ExpiresAt: exp}
			if d := e.Authorize(tech, tok, reset, obj("amy", "ou-sales", domain)); d.Allowed {
				t.Fatalf("%s token authorised: %+v", name, d)
			}
			if err := e.CheckToken(tech, tok); !errors.Is(err, authz.ErrTokenInvalid) {
				t.Fatalf("%s: got %v", name, err)
			}
		}
	})
}
