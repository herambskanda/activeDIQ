package sd

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// verifyPlan plans adding allow(X1) and deny(X2) on a base of two allows, returns the plan and its decoded value.
func verifyPlan(t *testing.T, adds ...NewACE) (DACLWrite, SD) {
	t.Helper()
	sys, user := mustSID("S-1-5-18"), mustSID("S-1-5-21-1-2-3-1105")
	raw := buildBase(t, []NewACE{{Trustee: sys, Mask: 0xF01FF}}, user)
	s, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	w, _, err := PlanDACL(s, ACEDiff{Add: adds}, nil,
		ObjectCtx{ObjectGUID: *mustGUID("11111111-0000-0000-0000-000000000001"), Connector: PrincipalFromToken(user, []sid.SID{mustSID("S-1-1-0")})}, PlanOpts{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(w.Value())
	if err != nil {
		t.Fatal(err)
	}
	return w, p
}

// stored re-encodes p's ACEs in the given order (indexes into p) with control ctl, as a DC read-back.
func stored(t *testing.T, p SD, order []int, ctl Control) SD {
	t.Helper()
	var l []ACE
	size := aclHeaderLen
	for _, i := range order {
		l = append(l, p.DACL.ACEs[i])
		size += len(p.DACL.ACEs[i].Raw)
	}
	s, err := Decode(Raw(encodeDACLSD(ctl, 2, l, size)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifyAfter(t *testing.T) {
	a, b := mustSID("S-1-5-21-1-2-3-2001"), mustSID("S-1-5-21-1-2-3-2002")
	w, p := verifyPlan(t, NewACE{Trustee: a, Mask: MaskReadProp}, NewACE{Trustee: b, Mask: MaskReadProp})
	n := len(p.DACL.ACEs)
	ident := make([]int, n)
	for i := range ident {
		ident[i] = i
	}
	swapped := append([]int(nil), ident...)
	swapped[n-1], swapped[n-2] = swapped[n-2], swapped[n-1] // two allows for different trustees: rights unchanged

	cases := []struct {
		name      string
		s         SD
		wantErr   bool
		reordered bool
	}{
		{"identical", stored(t, p, ident, p.Control), false, false},
		{"DC re-sort, same rights", stored(t, p, swapped, p.Control), false, true},
		{"DI recomputed by DC", stored(t, p, ident, p.Control|ControlDACLAutoInh), false, false},
		{"ACE dropped", stored(t, p, ident[:n-1], p.Control), true, false},
		{"PD differs", stored(t, p, ident, p.Control^ControlDACLProtected), true, false},
	}
	for _, c := range cases {
		v, err := w.VerifyAfter(c.s)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
			continue
		}
		if err != nil && codec.Code(err) != ErrWriteDiverged {
			t.Errorf("%s: code %q", c.name, codec.Code(err))
		}
		if err == nil && v.Reordered != c.reordered {
			t.Errorf("%s: Reordered=%v want %v", c.name, v.Reordered, c.reordered)
		}
	}
	if _, err := (DACLWrite{}).VerifyAfter(p); err == nil {
		t.Error("zero write verified")
	}
}

// A re-order that flips an effective decision (deny moved behind an allow for the same trustee) is a real difference.
func TestVerifyAfterRightsChange(t *testing.T) {
	x := mustSID("S-1-5-21-1-2-3-2001")
	w, p := verifyPlan(t, NewACE{Trustee: x, Mask: MaskReadProp, Deny: true}, NewACE{Trustee: x, Mask: MaskReadProp})
	n := len(p.DACL.ACEs)
	ident := make([]int, n)
	for i := range ident {
		ident[i] = i
	}
	// find the deny and the allow for x and put the allow first
	di, ai := -1, -1
	for i, e := range p.DACL.ACEs {
		if e.Trustee == x && e.deny() {
			di = i
		}
		if e.Trustee == x && e.allow() {
			ai = i
		}
	}
	if di < 0 || ai < 0 || di > ai {
		t.Skipf("planner order unexpected (deny %d allow %d)", di, ai)
	}
	re := append([]int(nil), ident...)
	re[di], re[ai] = ai, di
	if _, err := w.VerifyAfter(stored(t, p, re, p.Control)); err == nil {
		t.Error("deny/allow swap accepted")
	}
}
