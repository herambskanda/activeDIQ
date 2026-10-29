package sd

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// verifyCat classifies the two GUIDs the tests use: A is a property set, B a member attribute of it.
var verifyCat = mapCatalog{
	*mustGUID("aaaaaaaa-0000-0000-0000-00000000000a"): PropertySet,
	*mustGUID("bbbbbbbb-0000-0000-0000-00000000000b"): Attribute,
}

// verifyPlan plans adding allow(X1) and deny(X2) on a base of two allows, returns the plan and its decoded value.
func verifyPlan(t *testing.T, adds ...NewACE) (DACLWrite, SD) {
	t.Helper()
	sys, user := mustSID("S-1-5-18"), mustSID("S-1-5-21-1-2-3-1105")
	raw := buildBase(t, []NewACE{{Trustee: sys, Mask: 0xF01FF}}, user)
	s, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	w, _, err := PlanDACL(s, ACEDiff{Add: adds}, verifyCat,
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
	s, err := Decode(Raw(encodeDACLSD(ctl, p.DACL.Revision, l, size)))
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

// moveFront returns the stored read-back of p with ACE i moved to position 0.
func moveFront(t *testing.T, p SD, i int) SD {
	t.Helper()
	o := []int{i}
	for k := range p.DACL.ACEs {
		if k != i {
			o = append(o, k)
		}
	}
	return stored(t, p, o, p.Control)
}

// Re-orders that change (or may change) what the DACL grants are real differences; harmless ones are accepted.
func TestVerifyAfterRightsChange(t *testing.T) {
	x, y := mustSID("S-1-5-21-1-2-3-2001"), mustSID("S-1-5-21-1-2-3-2002")
	ga, gb := mustGUID("aaaaaaaa-0000-0000-0000-00000000000a"), mustGUID("bbbbbbbb-0000-0000-0000-00000000000b")
	const wp, rp = MaskWriteProp, MaskReadProp
	cases := []struct {
		name    string
		adds    []NewACE
		opaque  bool
		wantErr bool
	}{
		{"same trustee deny/allow, same mask", []NewACE{{Trustee: x, Mask: rp, Deny: true}, {Trustee: x, Mask: rp}}, false, true},
		{"different trustees deny/allow, same mask", []NewACE{{Trustee: x, Mask: rp, Deny: true}, {Trustee: y, Mask: rp}}, false, true},
		{"deny/allow, disjoint masks", []NewACE{{Trustee: x, Mask: wp, Deny: true}, {Trustee: x, Mask: rp}}, false, false},
		{"allow(GUID A)/deny(GUID B), overlapping mask (propset vs attribute)",
			[]NewACE{{Trustee: x, Mask: rp, ObjectType: ga}, {Trustee: x, Mask: rp, Deny: true, ObjectType: gb}}, false, true},
		{"allow(GUID A)/deny(no GUID), overlapping mask",
			[]NewACE{{Trustee: x, Mask: rp, ObjectType: ga}, {Trustee: x, Mask: rp, Deny: true}}, false, true},
		{"two allows with different GUIDs", []NewACE{{Trustee: x, Mask: rp, ObjectType: ga}, {Trustee: x, Mask: rp, ObjectType: gb}}, false, false},
		{"decision ACE that is not understood", []NewACE{{Trustee: x, Mask: rp}, {Trustee: y, Mask: rp}}, true, true},
	}
	for _, c := range cases {
		w, p := verifyPlan(t, c.adds...)
		// the two added ACEs are the last two distinct ACEs of the planned DACL that carry our trustees
		var idx []int
		for k, e := range p.DACL.ACEs {
			if e.Trustee == x || e.Trustee == y {
				idx = append(idx, k)
			}
		}
		if len(idx) != 2 {
			t.Fatalf("%s: planner produced %d candidate ACEs, want 2", c.name, len(idx))
		}
		s := moveFront(t, p, idx[1]) // the DC puts the later of our two ACEs first
		if c.opaque {
			s.DACL.ACEs[0].Kind = Opaque // an ACE type we cannot evaluate is never proven harmless
		}
		_, err := w.VerifyAfter(s)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		} else if err != nil && codec.Code(err) != ErrWriteDiverged {
			t.Errorf("%s: code %q", c.name, codec.Code(err))
		}
	}
}
