package authz

import (
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func ev() Evaluator { return Evaluator{Now: func() time.Time { return now }} }

func root(id string, anc ...string) ScopeRoot {
	r := ScopeRoot{ID: ObjectID(id)}
	for _, a := range anc {
		r.Ancestors = append(r.Ancestors, ObjectID(a))
	}
	return r
}

func target(id string, anc ...string) Target {
	t := Target{ID: ObjectID(id), Complete: true}
	for _, a := range anc {
		t.Ancestors = append(t.Ancestors, ObjectID(a))
	}
	return t
}

func tech(perms []Permission, s Scope) *Principal {
	return &Principal{ID: "tech", Assignments: []Assignment{{Role: Role{Permissions: perms}, Scope: s}}}
}

func tokenFor(p ...Permission) *Token { return &Token{Permissions: p, ExpiresAt: now.Add(time.Hour)} }

const (
	pReset  Permission = "objects.user.reset_password"
	pDelete Permission = "objects.user.delete"
)

func TestEffectiveIsRoleAndScopeAndToken(t *testing.T) {
	p := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("ouA", "dom")}})
	inA := target("u1", "ouA", "dom")
	outB := target("u2", "ouB", "dom")

	cases := []struct {
		name string
		tok  *Token
		perm Permission
		tgt  Target
		want bool
		why  Reason
	}{
		{"role+scope, session", nil, pReset, inA, true, ReasonAllowed},
		{"outside scope", nil, pReset, outB, false, ReasonNotInScope},
		{"permission not in role", nil, pDelete, inA, false, ReasonNotInScope},
		{"token carries it", tokenFor(pReset), pReset, inA, true, ReasonAllowed},
		{"token lacks it though role has it", tokenFor(pDelete), pReset, inA, false, ReasonTokenExcludes},
		{"empty token allows nothing", tokenFor(), pReset, inA, false, ReasonTokenExcludes},
		{"token cannot add what role lacks", tokenFor(pDelete), pDelete, inA, false, ReasonNotInScope},
		{"expired token", &Token{Permissions: []Permission{pReset}, ExpiresAt: now}, pReset, inA, false, ReasonTokenExpired},
		{"token without expiry", &Token{Permissions: []Permission{pReset}}, pReset, inA, false, ReasonTokenExpired},
	}
	for _, c := range cases {
		d := ev().Authorize(p, c.tok, c.perm, c.tgt)
		if d.Allowed != c.want || d.Reason != c.why {
			t.Errorf("%s: got %+v, want allowed=%v reason=%s", c.name, d, c.want, c.why)
		}
	}
}

func TestDenyByDefault(t *testing.T) {
	e := ev()
	tg := target("u1", "ouA")
	if d := e.Authorize(nil, nil, pReset, tg); d.Allowed {
		t.Error("nil principal allowed")
	}
	if d := e.Authorize(&Principal{ID: "x"}, nil, pReset, tg); d.Allowed {
		t.Error("principal without assignments allowed")
	}
	empty := tech([]Permission{pReset}, Scope{})
	if d := e.Authorize(empty, nil, pReset, tg); d.Allowed {
		t.Error("empty scope allowed")
	}
}

func TestLiveChainAndExcludes(t *testing.T) {
	p := tech([]Permission{pReset}, Scope{
		Include: []ScopeRoot{root("ouA", "dom")},
		Exclude: []ScopeRoot{root("ouVIP", "ouA", "dom")},
	})
	if !ev().Authorize(p, nil, pReset, target("u", "ouA", "dom")).Allowed {
		t.Error("in-scope refused")
	}
	if ev().Authorize(p, nil, pReset, target("u", "ouVIP", "ouA", "dom")).Allowed {
		t.Error("excluded sub-OU allowed")
	}
	// The object moved out of ouA: the live chain no longer contains it.
	if ev().Authorize(p, nil, pReset, target("u", "ouB", "dom")).Allowed {
		t.Error("moved object still allowed")
	}
	// Chain not read live/completely: fail closed.
	inc := target("u", "ouA", "dom")
	inc.Complete = false
	if d := ev().Authorize(p, nil, pReset, inc); d.Allowed || d.Reason != ReasonFactsIncomplete {
		t.Errorf("incomplete facts: %+v", d)
	}
	if d := ev().Authorize(p, nil, pReset, Target{Complete: true}); d.Allowed {
		t.Error("target without GUID allowed")
	}
}

func TestTier0NeverLifted(t *testing.T) {
	p := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("dom")}})
	tg := target("admin", "dom")
	tg.Tier0 = true
	if d := ev().Authorize(p, nil, pReset, tg); d.Allowed || d.Reason != ReasonTier0 {
		t.Errorf("tier0: %+v", d)
	}
}

func TestNoEscalation(t *testing.T) {
	grantor := &Principal{ID: "g", Assignments: []Assignment{{
		Role: Role{Permissions: []Permission{pReset}},
		Scope: Scope{
			Include: []ScopeRoot{root("ouA", "dom")},
			Exclude: []ScopeRoot{root("ouVIP", "ouA", "dom")},
		},
	}}}
	reset := Role{Permissions: []Permission{pReset}}
	both := Role{Permissions: []Permission{pReset, pDelete}}
	e := ev()

	tests := []struct {
		name string
		role Role
		s    Scope
		tok  *Token
		err  error
	}{
		{"same role, sub-OU", reset, Scope{Include: []ScopeRoot{root("ouHR", "ouA", "dom")}}, nil, nil},
		{"same role, same OU, excluding the VIP OU", reset,
			Scope{Include: []ScopeRoot{root("ouA", "dom")}, Exclude: []ScopeRoot{root("ouVIP", "ouA", "dom")}}, nil, nil},
		{"extra privilege", both, Scope{Include: []ScopeRoot{root("ouHR", "ouA", "dom")}}, nil, ErrEscalation},
		{"wider scope", reset, Scope{Include: []ScopeRoot{root("dom")}}, nil, ErrEscalation},
		{"sibling OU", reset, Scope{Include: []ScopeRoot{root("ouB", "dom")}}, nil, ErrEscalation},
		{"one root out of two", reset, Scope{Include: []ScopeRoot{root("ouHR", "ouA", "dom"), root("ouB", "dom")}}, nil, ErrEscalation},
		{"reaches into grantor exclusion", reset, Scope{Include: []ScopeRoot{root("ouA", "dom")}}, nil, ErrEscalation},
		{"root inside grantor exclusion", reset, Scope{Include: []ScopeRoot{root("ouVIP", "ouA", "dom")}}, nil, ErrEscalation},
		{"token lacks the permission", reset, Scope{Include: []ScopeRoot{root("ouHR", "ouA", "dom")}}, tokenFor(pDelete), ErrEscalation},
		{"empty role", Role{}, Scope{Include: []ScopeRoot{root("ouA", "dom")}}, nil, ErrInvalidGrant},
		{"empty scope", reset, Scope{}, nil, ErrInvalidGrant},
	}
	for _, c := range tests {
		if err := e.CheckGrant(grantor, c.tok, c.role, c.s); !errors.Is(err, c.err) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.err)
		}
	}
	dead := *grantor
	dead.Disabled = true
	if err := e.CheckGrant(&dead, nil, reset, Scope{Include: []ScopeRoot{root("ouHR", "ouA", "dom")}}); !errors.Is(err, ErrOwnerDead) {
		t.Errorf("disabled grantor: %v", err)
	}
}

func TestDeadOwnerToken(t *testing.T) {
	scope := Scope{Include: []ScopeRoot{root("ouA")}}
	tg := target("u", "ouA")
	tok := tokenFor(pReset)

	live := tech([]Permission{pReset}, scope)
	if err := ev().CheckToken(live, tok); err != nil {
		t.Fatalf("live owner: %v", err)
	}
	disabled := tech([]Permission{pReset}, scope)
	disabled.Disabled = true
	lost := &Principal{ID: "tech"}
	for name, owner := range map[string]*Principal{"disabled": disabled, "lost authority": lost} {
		if err := ev().CheckToken(owner, tok); !errors.Is(err, ErrOwnerDead) {
			t.Errorf("%s: CheckToken = %v", name, err)
		}
		if d := ev().Authorize(owner, tok, pReset, tg); d.Allowed {
			t.Errorf("%s: token still authorises", name)
		}
	}
	// Authority narrowed after issue: the token cannot exceed the owner's current authority.
	narrowed := tech([]Permission{pDelete}, scope)
	if d := ev().Authorize(narrowed, tok, pReset, tg); d.Allowed {
		t.Error("token exceeded narrowed owner")
	}
}

func TestBulkPerItem(t *testing.T) {
	p := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("ouA")}})
	items := []Target{target("1", "ouA"), target("2", "ouB"), target("3", "ouA"), {ID: "4"}}
	res := ev().AuthorizeItems(p, nil, pReset, items)
	if res.Allowed != 2 || res.Refused != 2 || len(res.Items) != 4 {
		t.Fatalf("counts: %+v", res)
	}
	want := []bool{true, false, true, false}
	for i, it := range res.Items {
		if it.Allowed != want[i] || it.Target.ID != items[i].ID {
			t.Errorf("item %d: %+v", i, it)
		}
	}
	p.Disabled = true
	if r := ev().AuthorizeItems(p, nil, pReset, items); r.Allowed != 0 || r.Refused != 4 {
		t.Errorf("dead owner bulk: %+v", r)
	}
}

func TestOwnerScopedReport(t *testing.T) {
	owner := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("ouA")}})
	rows := []Target{target("1", "ouA"), target("2", "ouB"), target("3", "ouB")}
	got, err := ev().FilterForOwner(owner, pReset, rows)
	if err != nil || len(got.Permitted) != 1 || got.Permitted[0].ID != "1" || got.Omitted != 2 {
		t.Fatalf("report: %+v %v", got, err)
	}
	// Owner loses the scope: next run delivers only the new scope.
	owner.Assignments[0].Scope = Scope{Include: []ScopeRoot{root("ouB")}}
	got, _ = ev().FilterForOwner(owner, pReset, rows)
	if len(got.Permitted) != 2 || got.Omitted != 1 {
		t.Errorf("after scope change: %+v", got)
	}
	owner.Disabled = true
	if _, err := ev().FilterForOwner(owner, pReset, rows); !errors.Is(err, ErrOwnerDead) {
		t.Errorf("disabled owner: %v", err)
	}
}
