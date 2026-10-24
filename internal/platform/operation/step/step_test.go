package step

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
)

func chain() authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: "p1", Kind: authority.Human}}
}

func mint(t *testing.T, key Key, d Digest, recheck RecheckFunc) (Step, func()) {
	t.Helper()
	m := testMinter()
	s, revoke, err := m.Mint(Spec{Key: key, Attempt: 1, Actor: chain(), Digest: d, Recheck: recheck})
	if err != nil {
		t.Fatal(err)
	}
	return s, revoke
}

func ok(context.Context, authority.Facts) error { return nil }

func TestZeroStepIsRefused(t *testing.T) {
	var s Step
	if !errors.Is(s.Valid(), ErrZeroStep) {
		t.Fatalf("Valid = %v", s.Valid())
	}
	if _, err := s.Recheck(context.Background(), authority.Facts{}); !errors.Is(err, ErrZeroStep) {
		t.Fatalf("Recheck on zero = %v", err)
	}
	if s.Tx() != nil || s.Key() != (Key{}) {
		t.Fatal("zero step leaks state")
	}
}

func TestRevokedStepAndClearanceDie(t *testing.T) {
	key := Key{Operation: "op1"}
	d := Compute("modify", authority.TargetRef{GUID: "g"}, nil)
	s, revoke := mint(t, key, d, ok)
	c, err := s.Recheck(context.Background(), authority.Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Check(key, d); err != nil {
		t.Fatalf("fresh clearance: %v", err)
	}
	revoke()
	if !errors.Is(s.Valid(), ErrRevoked) {
		t.Fatalf("revoked step Valid = %v", s.Valid())
	}
	if err := c.Check(key, d); !errors.Is(err, ErrRevoked) {
		t.Fatalf("clearance of a revoked step = %v", err)
	}
	if _, err := s.Recheck(context.Background(), authority.Facts{}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Recheck after revoke = %v", err)
	}
}

func TestClearanceReplayRefused(t *testing.T) {
	d := Compute("modify", authority.TargetRef{GUID: "g"}, nil)
	s, _ := mint(t, Key{Operation: "op1"}, d, ok)
	c, _ := s.Recheck(context.Background(), authority.Facts{})
	if err := c.Check(Key{Operation: "op2"}, d); !errors.Is(err, ErrNoClearance) {
		t.Fatalf("other operation = %v", err)
	}
	if err := c.Check(Key{Operation: "op1", Item: 1}, d); !errors.Is(err, ErrNoClearance) {
		t.Fatalf("other item = %v", err)
	}
	other := Compute("modify", authority.TargetRef{GUID: "other"}, nil)
	if err := c.Check(Key{Operation: "op1"}, other); !errors.Is(err, ErrNoClearance) {
		t.Fatalf("other digest = %v", err)
	}
	if err := (Clearance{}).Check(Key{}, Digest{}); !errors.Is(err, ErrZeroStep) {
		t.Fatalf("zero clearance = %v", err)
	}
}

func TestRecheckDeniedYieldsNoClearance(t *testing.T) {
	s, _ := mint(t, Key{Operation: "op1"}, Digest{}, func(context.Context, authority.Facts) error { return errors.New("out of scope") })
	c, err := s.Recheck(context.Background(), authority.Facts{})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
	if (c != Clearance{}) {
		t.Fatal("a refused re-check returned a clearance")
	}
}

func TestMintRefusesIncompleteSpec(t *testing.T) {
	m := testMinter()
	for name, sp := range map[string]Spec{
		"no recheck":   {Key: Key{Operation: "o"}, Actor: chain()},
		"no actor":     {Key: Key{Operation: "o"}, Recheck: ok},
		"no operation": {Actor: chain(), Recheck: ok},
	} {
		if _, _, err := m.Mint(sp); err == nil {
			t.Errorf("%s: Mint accepted", name)
		}
	}
}

func TestForgedMinterIsRefused(t *testing.T) {
	sp := Spec{Key: Key{Operation: "o"}, Actor: chain(), Recheck: ok}
	var zero Minter
	for name, m := range map[string]*Minter{"zero value": &zero, "new": new(Minter), "nil": nil} {
		s, rev, err := m.Mint(sp)
		if !errors.Is(err, ErrNotMinter) {
			t.Errorf("%s: err = %v", name, err)
		}
		if s.Valid() == nil || rev != nil {
			t.Errorf("%s: produced a live step", name)
		}
	}
}

func TestMinterIsTakenOnce(t *testing.T) {
	mu.Lock()
	taken = false
	mu.Unlock()
	if _, err := TakeMinter(); err != nil {
		t.Fatal(err)
	}
	if !MinterTaken() {
		t.Fatal("MinterTaken false after take")
	}
	if _, err := TakeMinter(); !errors.Is(err, ErrMinterTaken) {
		t.Fatalf("second take = %v", err)
	}
}

func TestDigest(t *testing.T) {
	tg := authority.TargetRef{Connection: "c", GUID: "g", Class: "user"}
	a := Compute("modify", tg, []Attr{{Name: "mail", Values: []string{"a@x"}}, {Name: "title", Values: []string{"t"}}})
	b := Compute("modify", tg, []Attr{{Name: "title", Values: []string{"t"}}, {Name: "mail", Values: []string{"a@x"}}})
	if a != b {
		t.Fatal("attribute order changed the digest")
	}
	for name, d := range map[string]Digest{
		"other value":  Compute("modify", tg, []Attr{{Name: "mail", Values: []string{"b@x"}}, {Name: "title", Values: []string{"t"}}}),
		"other target": Compute("modify", authority.TargetRef{Connection: "c", GUID: "h", Class: "user"}, []Attr{{Name: "mail", Values: []string{"a@x"}}, {Name: "title", Values: []string{"t"}}}),
		"other kind":   Compute("delete", tg, []Attr{{Name: "mail", Values: []string{"a@x"}}, {Name: "title", Values: []string{"t"}}}),
		"other nc":     Compute("modify", authority.TargetRef{Connection: "c", GUID: "g", Class: "user", NC: "nc2"}, []Attr{{Name: "mail", Values: []string{"a@x"}}, {Name: "title", Values: []string{"t"}}}),
		"missing attr": Compute("modify", tg, []Attr{{Name: "mail", Values: []string{"a@x"}}}),
	} {
		if d == a {
			t.Errorf("%s: digest unchanged", name)
		}
	}
	// framing: moving a byte between adjacent values must change the digest
	if Compute("k", tg, []Attr{{Name: "a", Values: []string{"bc", "d"}}}) == Compute("k", tg, []Attr{{Name: "a", Values: []string{"b", "cd"}}}) {
		t.Fatal("ambiguous encoding")
	}
	// a secret value is excluded, its presence is included
	s1 := Compute("k", tg, []Attr{{Name: "unicodePwd", Values: []string{"one"}, Secret: true}})
	s2 := Compute("k", tg, []Attr{{Name: "unicodePwd", Values: []string{"two"}, Secret: true}})
	if s1 != s2 {
		t.Fatal("secret value changed the digest")
	}
	if s1 == Compute("k", tg, nil) {
		t.Fatal("secret presence not in the digest")
	}
}

func TestMintCopiesPins(t *testing.T) {
	pins := authority.Pins{"nc1": "dc1.example"}
	s, _, err := testMinter().Mint(Spec{Key: Key{Operation: "o"}, Actor: chain(), Recheck: ok, Pins: pins, NC: "nc1"})
	if err != nil {
		t.Fatal(err)
	}
	pins["nc1"] = "rogue.example"
	if h, _ := s.DC("nc1"); h != "dc1.example" {
		t.Errorf("DC = %q after caller mutated its map", h)
	}
}
