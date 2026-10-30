package authz

import (
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func ev() Evaluator { return Evaluator{Now: func() time.Time { return now }} }

// oid maps a readable test name to a deterministic non-zero ObjectID.
func oid(name string) ObjectID {
	var id ObjectID
	id[0] = 0xAA
	copy(id[1:], name)
	return id
}

func root(id string, anc ...string) ScopeRoot {
	r := ScopeRoot{ID: oid(id), Complete: true}
	for _, a := range anc {
		r.Ancestors = append(r.Ancestors, oid(a))
	}
	return r
}

func target(id string, anc ...string) Target {
	t := Target{ID: oid(id), Complete: true}
	for _, a := range anc {
		t.Ancestors = append(t.Ancestors, oid(a))
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
	items := []Target{target("1", "ouA"), target("2", "ouB"), target("3", "ouA"), {ID: oid("4")}}
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

func TestGrantFailsClosedOnIncompleteRoots(t *testing.T) {
	reset := Role{Permissions: []Permission{pReset}}
	e := ev()
	incomplete := func(r ScopeRoot) ScopeRoot { r.Complete = false; return r }
	mk := func(excl ScopeRoot) *Principal {
		return &Principal{ID: "g", Assignments: []Assignment{{Role: reset,
			Scope: Scope{Include: []ScopeRoot{root("corp")}, Exclude: []ScopeRoot{excl}}}}}
	}
	// (a) grantor exclusion lacks its chain: must not let a grant of corp with no exclusion pass.
	g := mk(ScopeRoot{ID: oid("admins")})
	if err := e.CheckGrant(g, nil, reset, Scope{Include: []ScopeRoot{root("corp")}}); !errors.Is(err, ErrFactsIncomplete) {
		t.Errorf("incomplete grantor exclusion: %v", err)
	}
	// Control: with the live chain the same grant is an escalation.
	g = mk(root("admins", "corp"))
	if err := e.CheckGrant(g, nil, reset, Scope{Include: []ScopeRoot{root("corp")}}); !errors.Is(err, ErrEscalation) {
		t.Errorf("complete chain: %v", err)
	}
	// (b) incomplete new include root, and incomplete new exclude root.
	if err := e.CheckGrant(g, nil, reset, Scope{Include: []ScopeRoot{incomplete(root("hr", "corp"))}}); !errors.Is(err, ErrFactsIncomplete) {
		t.Errorf("incomplete include: %v", err)
	}
	if err := e.CheckGrant(g, nil, reset, Scope{Include: []ScopeRoot{root("hr", "corp")},
		Exclude: []ScopeRoot{incomplete(root("x", "hr", "corp"))}}); !errors.Is(err, ErrFactsIncomplete) {
		t.Errorf("incomplete exclude: %v", err)
	}
}

func TestBlankIDsNeverMatch(t *testing.T) {
	p := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{{Complete: true}}})
	tg := Target{ID: oid("u"), Ancestors: []ObjectID{{}}, Complete: true}
	if d := ev().Authorize(p, nil, pReset, tg); d.Allowed || d.Reason != ReasonFactsIncomplete {
		t.Errorf("blank chain element: %+v", d)
	}
	g := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("ouA")}})
	err := ev().CheckGrant(g, nil, Role{Permissions: []Permission{pReset}}, Scope{Include: []ScopeRoot{{Complete: true}}})
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("blank root: %v", err)
	}
	if (ScopeRoot{Ancestors: []ObjectID{oid("a")}}).within(ObjectID{}) {
		t.Error("blank within matched")
	}
}

func TestTokenScopeNarrowing(t *testing.T) {
	p := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("corp")}})
	tok := tokenFor(pReset)
	narrow := Scope{Include: []ScopeRoot{root("ouA", "corp")}}
	tok.Scope = &narrow
	if d := ev().Authorize(p, tok, pReset, target("u", "ouA", "corp")); !d.Allowed {
		t.Errorf("inside token scope: %+v", d)
	}
	if d := ev().Authorize(p, tok, pReset, target("u", "ouB", "corp")); d.Allowed {
		t.Errorf("outside token scope allowed: %+v", d)
	}
	empty := Scope{}
	tok.Scope = &empty
	if d := ev().Authorize(p, tok, pReset, target("u", "ouA", "corp")); d.Allowed {
		t.Error("empty token scope allowed")
	}
	// Grant through a narrowed token cannot exceed the token scope.
	tok.Scope = &narrow
	reset := Role{Permissions: []Permission{pReset}}
	if err := ev().CheckGrant(p, tok, reset, Scope{Include: []ScopeRoot{root("ouB", "corp")}}); !errors.Is(err, ErrEscalation) {
		t.Errorf("grant beyond token scope: %v", err)
	}
	if err := ev().CheckGrant(p, tok, reset, Scope{Include: []ScopeRoot{root("ouHR", "ouA", "corp")}}); err != nil {
		t.Errorf("grant within token scope: %v", err)
	}
}

func TestTokenInvalidIsNotOwnerDead(t *testing.T) {
	p := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("ouA")}})
	if err := ev().CheckToken(p, nil); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("nil token: %v", err)
	}
	if err := ev().CheckToken(p, &Token{ExpiresAt: now}); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expired token: %v", err)
	}
}

func TestParseObjectIDStrict(t *testing.T) {
	const canon = "aaaaaaaa-0000-0000-0000-000000000001"
	want, err := ParseObjectID(canon)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if got, err := ParseObjectID("AAAAAAAA-0000-0000-0000-000000000001"); err != nil || got != want {
		t.Errorf("upper case must equal the same object: %v %v", got, err)
	}
	for _, bad := range []string{"", "x", "{" + canon + "}", canon + "0", "aaaaaaaa00000000000000000000000000001",
		"zzzzzzzz-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000000"} {
		if _, err := ParseObjectID(bad); !errors.Is(err, ErrInvalidObjectID) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

// A spelling variant of an excluded GUID parses to the same value, so the exclusion still bites;
// a non-parseable ID can never be built into a fact, and the zero value is refused everywhere.
func TestVariantExclusionStillExcludes(t *testing.T) {
	admins, _ := ParseObjectID("AAAAAAAA-0000-0000-0000-000000000001")
	adminsLower, _ := ParseObjectID("aaaaaaaa-0000-0000-0000-000000000001")
	p := tech([]Permission{pReset}, Scope{
		Include: []ScopeRoot{root("corp")},
		Exclude: []ScopeRoot{{ID: admins, Ancestors: []ObjectID{oid("corp")}, Complete: true}}})
	tg := Target{ID: oid("u"), Ancestors: []ObjectID{adminsLower, oid("corp")}, Complete: true}
	if d := ev().Authorize(p, nil, pReset, tg); d.Allowed {
		t.Errorf("excluded OU reachable via spelling variant: %+v", d)
	}
}

func TestZeroIDsRefused(t *testing.T) {
	zero := ScopeRoot{Complete: true}
	// zero exclusion root in a scope: Authorize and CheckGrant both fail closed.
	g := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("corp")}, Exclude: []ScopeRoot{zero}})
	reset := Role{Permissions: []Permission{pReset}}
	if err := ev().CheckGrant(g, nil, reset, Scope{Include: []ScopeRoot{root("hr", "corp")}, Exclude: []ScopeRoot{zero}}); !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("zero exclude in grant: %v", err)
	}
	if err := ev().CheckGrant(g, nil, reset, Scope{Include: []ScopeRoot{root("hr", "corp")}}); !errors.Is(err, ErrFactsIncomplete) {
		t.Errorf("zero exclude in grantor scope must fail closed: %v", err)
	}
	if err := ev().CheckGrant(g, nil, reset, Scope{Include: []ScopeRoot{{ID: oid("hr"), Ancestors: []ObjectID{{}}, Complete: true}}}); !errors.Is(err, ErrFactsIncomplete) {
		t.Errorf("zero ancestor in new root: %v", err)
	}
	if d := ev().Authorize(g, nil, pReset, Target{Ancestors: []ObjectID{oid("corp")}, Complete: true}); d.Allowed {
		t.Errorf("zero target id: %+v", d)
	}
}

func TestObjectIDCanonicalOrder(t *testing.T) {
	text, err := ParseObjectID("01234567-89ab-cdef-0011-223344556677")
	if err != nil {
		t.Fatal(err)
	}
	oct, err := ObjectIDFromOctets([]byte{0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77})
	if err != nil || text != oct {
		t.Fatalf("text %x != octets %x (%v)", text, oct, err)
	}
	if _, err := ObjectIDFromOctets(make([]byte, 16)); !errors.Is(err, ErrInvalidObjectID) {
		t.Errorf("zero octets: %v", err)
	}
	if _, err := ObjectIDFromOctets(oct[:15]); !errors.Is(err, ErrInvalidObjectID) {
		t.Errorf("short octets: %v", err)
	}
	// exclusion built from text, chain built from octets: must deny.
	corp := oid("corp")
	p := &Principal{ID: "tech", Assignments: []Assignment{{
		Role:  Role{Permissions: []Permission{pReset}},
		Scope: Scope{Include: []ScopeRoot{{ID: corp, Complete: true}}, Exclude: []ScopeRoot{{ID: text, Complete: true}}},
	}}}
	tgt := Target{ID: oid("user"), Ancestors: []ObjectID{oct, corp}, Complete: true}
	if d := ev().Authorize(p, nil, pReset, tgt); d.Allowed {
		t.Errorf("text-built exclusion skipped for octet-built chain: %+v", d)
	}
}

func TestZeroExcludeDeniesInAuthorize(t *testing.T) {
	zero := ScopeRoot{Complete: true}
	tgt := target("user", "admins", "corp")
	p := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("corp")}, Exclude: []ScopeRoot{zero}})
	if d := ev().Authorize(p, nil, pReset, tgt); d.Allowed {
		t.Errorf("zero exclude in assignment widened scope: %+v", d)
	}
	ok := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("corp")}})
	tok := tokenFor(pReset)
	tok.Scope = &Scope{Include: []ScopeRoot{root("corp")}, Exclude: []ScopeRoot{zero}}
	if d := ev().Authorize(ok, tok, pReset, tgt); d.Allowed {
		t.Errorf("zero exclude in token scope widened scope: %+v", d)
	}
}

// DM-34.I1: tenant-owner holds every permission, over its scope and no further.
func TestTenantOwnerHoldsEveryPermissionInItsScope(t *testing.T) {
	p := &Principal{ID: "owner", Assignments: []Assignment{{Role: Role{TenantOwner: true}, Scope: Scope{Include: []ScopeRoot{root("ouA", "dom")}}}}}
	if d := ev().Authorize(p, nil, pDelete, target("u1", "ouA", "dom")); !d.Allowed {
		t.Errorf("owner in scope: %+v", d)
	}
	if d := ev().Authorize(p, nil, pDelete, target("u2", "ouB", "dom")); d.Allowed {
		t.Errorf("owner outside scope: %+v", d)
	}
	// A token still narrows the owner to its subset.
	if d := ev().Authorize(p, tokenFor(pReset), pDelete, target("u1", "ouA", "dom")); d.Allowed {
		t.Errorf("owner's token reached beyond its subset: %+v", d)
	}
}

// T-0250 (TM-D1): a platform-scope-only permission is never held by a role, never granted by one,
// and not implied by the tenant-owner role.
func TestPlatformOnlyPermission(t *testing.T) {
	const perm Permission = "connections.tier0_override.acknowledge"
	ev := Evaluator{}
	root := ScopeRoot{ID: ObjectID{1}, Complete: true}
	scope := Scope{Include: []ScopeRoot{root}}
	owner := &Principal{ID: "o", Assignments: []Assignment{{Role: Role{TenantOwner: true}, Scope: scope}}}
	if err := ev.CheckGrant(owner, nil, Role{Permissions: []Permission{"x.y", perm}}, scope); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("grant of a platform-only role: %v, want ErrInvalidGrant", err)
	}
	target := Target{ID: ObjectID{2}, Ancestors: []ObjectID{{1}}, Complete: true}
	if d := ev.Authorize(owner, nil, perm, target); d.Allowed {
		t.Fatal("tenant owner holds a platform-only permission")
	}
	listed := &Principal{ID: "l", Assignments: []Assignment{{Role: Role{Permissions: []Permission{perm}}, Scope: scope}}}
	if d := ev.Authorize(listed, nil, perm, target); d.Allowed {
		t.Fatal("a listed platform-only permission was effective at delegation scope")
	}
}

func oneLevel(id string, anc ...string) ScopeRoot {
	r := root(id, anc...)
	r.OneLevel = true
	return r
}

// T-0881: a OneLevel include root covers a target whose nearest parent is the root, and nothing else.
func TestOneLevelRootIsNeverASubtree(t *testing.T) {
	p := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{oneLevel("ouA", "dom")}})
	allow := func(tg Target) bool { return ev().Authorize(p, nil, pReset, tg).Allowed }
	if !allow(target("u", "ouA", "dom")) {
		t.Error("direct child refused")
	}
	if allow(target("u", "ouSub", "ouA", "dom")) {
		t.Error("child of a child OU allowed: one-level read as a subtree")
	}
	if allow(target("ouA", "dom")) {
		t.Error("the root OU itself allowed")
	}
	if allow(target("u")) {
		t.Error("target with no parent allowed")
	}
	// An exclude still beats the include for a direct child.
	px := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{oneLevel("ouA", "dom")}, Exclude: []ScopeRoot{root("ouA", "dom")}})
	if ev().Authorize(px, nil, pReset, target("u", "ouA", "dom")).Allowed {
		t.Error("exclude did not beat one-level include")
	}
	// A token scope with a one-level root narrows the same way.
	wide := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("dom")}})
	tok := tokenFor(pReset)
	tok.Scope = &Scope{Include: []ScopeRoot{oneLevel("ouA", "dom")}}
	if !ev().Authorize(wide, tok, pReset, target("u", "ouA", "dom")).Allowed {
		t.Error("direct child refused through a one-level token scope")
	}
	if ev().Authorize(wide, tok, pReset, target("u", "ouSub", "ouA", "dom")).Allowed {
		t.Error("token one-level scope read as a subtree")
	}
}

// A one-level grantor root contains only the identical one-level root: a grant of its subtree, a
// deeper OU or a different level would reach objects the grantor cannot act on.
func TestOneLevelGrantorContainment(t *testing.T) {
	role := Role{Permissions: []Permission{pReset}}
	grantor := func(s Scope) *Principal { return tech([]Permission{pReset}, s) }
	oneA := grantor(Scope{Include: []ScopeRoot{oneLevel("ouA", "dom")}})
	if err := ev().CheckGrant(oneA, nil, role, Scope{Include: []ScopeRoot{oneLevel("ouA", "dom")}}); err != nil {
		t.Errorf("same one-level root refused: %v", err)
	}
	for name, s := range map[string]ScopeRoot{
		"subtree of the same OU":  root("ouA", "dom"),
		"a child OU as a subtree": root("ouSub", "ouA", "dom"),
		"a child OU as one level": oneLevel("ouSub", "ouA", "dom"),
		"the parent as one level": oneLevel("dom"),
	} {
		if err := ev().CheckGrant(oneA, nil, role, Scope{Include: []ScopeRoot{s}}); !errors.Is(err, ErrEscalation) {
			t.Errorf("%s: want escalation, got %v", name, err)
		}
	}
	// A subtree grantor contains a one-level root beneath it.
	sub := grantor(Scope{Include: []ScopeRoot{root("ouA", "dom")}})
	if err := ev().CheckGrant(sub, nil, role, Scope{Include: []ScopeRoot{oneLevel("ouSub", "ouA", "dom")}}); err != nil {
		t.Errorf("one-level inside a held subtree refused: %v", err)
	}
	if err := ev().CheckGrant(sub, nil, role, Scope{Include: []ScopeRoot{oneLevel("ouB", "dom")}}); !errors.Is(err, ErrEscalation) {
		t.Errorf("one-level outside the held subtree: %v", err)
	}
}

// AuthorizeRead is Authorize without the Tier-0 write limit (DM-35.I5) and without correlation-derived
// grants; every other rule is the same.
func TestAuthorizeReadDiffersFromAuthorizeOnlyForTier0AndVia(t *testing.T) {
	p := tech([]Permission{pReset}, Scope{Include: []ScopeRoot{root("ouA")}, Exclude: []ScopeRoot{root("ouX")}})
	tier0 := target("1", "ouA")
	tier0.Tier0 = true
	if d := ev().Authorize(p, nil, pReset, tier0); d.Allowed || d.Reason != ReasonTier0 {
		t.Fatalf("write path must refuse Tier-0: %+v", d)
	}
	if d := ev().AuthorizeRead(p, nil, pReset, tier0); !d.Allowed {
		t.Fatalf("read path must not be narrowed by Tier-0: %+v", d)
	}
	for name, c := range map[string]struct {
		p   *Principal
		tok *Token
		tgt Target
		why Reason
	}{
		"outside the scope":    {p, nil, target("2", "ouB"), ReasonNotInScope},
		"in an exclude":        {p, nil, target("3", "ouX", "ouA"), ReasonNotInScope},
		"incomplete facts":     {p, nil, Target{ID: oid("4"), Ancestors: []ObjectID{oid("ouA")}}, ReasonFactsIncomplete},
		"permission not held":  {tech([]Permission{pDelete}, Scope{Include: []ScopeRoot{root("ouA")}}), nil, target("5", "ouA"), ReasonNotInScope},
		"token without perm":   {p, tokenFor(pDelete), target("6", "ouA"), ReasonTokenExcludes},
		"token scope excludes": {p, &Token{Permissions: []Permission{pReset}, ExpiresAt: now.Add(time.Hour), Scope: &Scope{Include: []ScopeRoot{root("ouB")}}}, target("7", "ouA"), ReasonTokenExcludes},
		"empty token scope":    {p, &Token{Permissions: []Permission{pReset}, ExpiresAt: now.Add(time.Hour), Scope: &Scope{}}, target("8", "ouA"), ReasonTokenExcludes},
		"disabled owner":       {&Principal{ID: "tech", Disabled: true, Assignments: p.Assignments}, nil, target("9", "ouA"), ReasonOwnerDisabled},
		"expired token":        {p, &Token{Permissions: []Permission{pReset}, ExpiresAt: now.Add(-time.Second)}, target("10", "ouA"), ReasonTokenExpired},
	} {
		d := ev().AuthorizeRead(c.p, c.tok, pReset, c.tgt)
		if d.Allowed || d.Reason != c.why {
			t.Errorf("%s: %+v, want refused with %s", name, d, c.why)
		}
	}
	// A correlation-derived assignment grants no read; the same assignment held directly does.
	via := &Principal{ID: "tech", Assignments: []Assignment{{
		Role: Role{Permissions: []Permission{pReset}}, Scope: Scope{Include: []ScopeRoot{root("ouA")}},
		Via: &Derivation{Correlation: &Correlation{State: CorrelationMatched, Takeover: TakeoverAttested}}}}}
	via.AuthorityFactor = true
	if d := ev().Authorize(via, nil, pReset, target("11", "ouA")); !d.Allowed {
		t.Fatalf("precondition: the gated write path admits this Via grant: %+v", d)
	}
	if d := ev().AuthorizeRead(via, nil, pReset, target("11", "ouA")); d.Allowed {
		t.Fatalf("a Via grant must contribute nothing to a read: %+v", d)
	}
}

func TestCheckTokenFor(t *testing.T) {
	if err := ev().CheckTokenFor(nil, pReset); err != nil {
		t.Fatalf("a session has no token to refuse: %v", err)
	}
	if err := ev().CheckTokenFor(tokenFor(pReset), pReset); err != nil {
		t.Fatalf("usable token: %v", err)
	}
	for name, tk := range map[string]*Token{
		"unlisted":  tokenFor(pDelete),
		"expired":   {Permissions: []Permission{pReset}, ExpiresAt: now.Add(-time.Second)},
		"no expiry": {Permissions: []Permission{pReset}},
	} {
		if err := ev().CheckTokenFor(tk, pReset); !errors.Is(err, ErrTokenRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRoleHolds(t *testing.T) {
	if !(Role{Permissions: []Permission{pReset}}).Holds(pReset) || (Role{Permissions: []Permission{pReset}}).Holds(pDelete) {
		t.Fatal("listed permission only")
	}
	if !(Role{TenantOwner: true}).Holds(pDelete) {
		t.Fatal("tenant-owner holds every permission")
	}
	po := platformOnly[0]
	if (Role{TenantOwner: true, Permissions: []Permission{po}}).Holds(po) {
		t.Fatal("no role holds a platform-only permission")
	}
}
