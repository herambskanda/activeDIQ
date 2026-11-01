package sd

import (
	"encoding/binary"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
)

// A tiny byte builder independent of the package's encoders, so the golden cases do not test the
// code with itself.
type pcACE struct {
	typ, flags byte
	mask       uint32
	obj, inh   string // GUID text, "" = absent
	trustee    string
}

func pcSID(t *testing.T, s string) []byte {
	t.Helper()
	return mustSID(s).Bytes()
}

func (a pcACE) bytes(t *testing.T) []byte {
	t.Helper()
	body := binary.LittleEndian.AppendUint32(nil, a.mask)
	if a.typ == TypeAccessDeniedObject || a.typ == TypeAccessAllowedObject {
		var fl uint32
		var gs []byte
		if a.obj != "" {
			fl |= 1
			gs = append(gs, mustGUID(a.obj).Bytes()...)
		}
		if a.inh != "" {
			fl |= 2
			gs = append(gs, mustGUID(a.inh).Bytes()...)
		}
		body = binary.LittleEndian.AppendUint32(body, fl)
		body = append(body, gs...)
	}
	body = append(body, pcSID(t, a.trustee)...)
	out := []byte{a.typ, a.flags, 0, 0}
	out = append(out, body...)
	binary.LittleEndian.PutUint16(out[2:], uint16(len(out)))
	return out
}

// pcSD builds a self-relative SD with a DACL of the given ACEs and no owner/group.
func pcSD(t *testing.T, aces ...pcACE) Raw {
	t.Helper()
	acl := []byte{4, 0, 0, 0, 0, 0, 0, 0}
	for _, a := range aces {
		acl = append(acl, a.bytes(t)...)
	}
	binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(aces)))
	h := make([]byte, 20)
	h[0] = 1
	binary.LittleEndian.PutUint16(h[2:], ControlSelfRelative|ControlDACLPresent)
	binary.LittleEndian.PutUint32(h[16:], 20)
	return Raw(append(h, acl...))
}

const cpGUID = "ab721a53-1e2f-11d0-9819-00aa0040529b"

func denyCP(trustee string) pcACE {
	return pcACE{typ: TypeAccessDeniedObject, mask: MaskControlAccess, obj: cpGUID, trustee: trustee}
}

func allowCP(trustee string) pcACE {
	return pcACE{typ: TypeAccessAllowedObject, mask: MaskControlAccess, obj: cpGUID, trustee: trustee}
}

func TestClassifyPasswordChange(t *testing.T) {
	resetPw := "00299570-246d-11d0-a768-00aa006e0529"
	cases := []struct {
		name string
		aces []pcACE
		want PasswordChange
	}{
		{"both deny ACEs", []pcACE{denyCP("S-1-1-0"), denyCP("S-1-5-10")}, PasswordChangeBlocked},
		{"both, reverse order, with allows after", []pcACE{denyCP("S-1-5-10"), denyCP("S-1-1-0"), allowCP("S-1-1-0"), allowCP("S-1-5-10")}, PasswordChangeBlocked},
		{"only Everyone", []pcACE{denyCP("S-1-1-0"), allowCP("S-1-5-10")}, PasswordChangeBlockedOneACE},
		{"only SELF", []pcACE{denyCP("S-1-5-10")}, PasswordChangeBlockedOneACE},
		{"same trustee twice is one ACE", []pcACE{denyCP("S-1-1-0"), denyCP("S-1-1-0")}, PasswordChangeBlockedOneACE},
		{"default user allows only", []pcACE{allowCP("S-1-1-0"), allowCP("S-1-5-10")}, PasswordChangeNoDenyACE},
		{"empty DACL", nil, PasswordChangeNoDenyACE},
		{"deny of Reset Password is not it", []pcACE{{typ: TypeAccessDeniedObject, mask: MaskControlAccess, obj: resetPw, trustee: "S-1-1-0"}, {typ: TypeAccessDeniedObject, mask: MaskControlAccess, obj: resetPw, trustee: "S-1-5-10"}}, PasswordChangeNoDenyACE},
		{"deny with a different trustee", []pcACE{denyCP("S-1-5-11"), denyCP("S-1-5-32-544")}, PasswordChangeNoDenyACE},
		{"inherited deny is not an explicit ACE", []pcACE{{typ: TypeAccessDeniedObject, flags: FlagInherited, mask: MaskControlAccess, obj: cpGUID, trustee: "S-1-1-0"}, {typ: TypeAccessDeniedObject, flags: FlagInherited, mask: MaskControlAccess, obj: cpGUID, trustee: "S-1-5-10"}}, PasswordChangeNoDenyACE},
		{"inherit-only deny does not apply here", []pcACE{{typ: TypeAccessDeniedObject, flags: FlagInheritOnly | FlagContainerInherit, mask: MaskControlAccess, obj: cpGUID, trustee: "S-1-1-0"}}, PasswordChangeNoDenyACE},
		{"deny without the control-access bit", []pcACE{{typ: TypeAccessDeniedObject, mask: MaskReadProp, obj: cpGUID, trustee: "S-1-1-0"}}, PasswordChangeNoDenyACE},
		{"deny with no object type is not counted", []pcACE{{typ: TypeAccessDenied, mask: MaskControlAccess, trustee: "S-1-1-0"}}, PasswordChangeNoDenyACE},
		{"deny with an inherited-object type is not counted", []pcACE{{typ: TypeAccessDeniedObject, mask: MaskControlAccess, obj: cpGUID, inh: "bf967aba-0de6-11d0-a285-00aa003049e2", trustee: "S-1-1-0"}}, PasswordChangeNoDenyACE},
		{"deny with extra bits still counts", []pcACE{{typ: TypeAccessDeniedObject, mask: MaskControlAccess | MaskReadProp, obj: cpGUID, trustee: "S-1-1-0"}}, PasswordChangeBlockedOneACE},
		{"allow-typed ACE with the right shape is not a deny", []pcACE{allowCP("S-1-1-0"), allowCP("S-1-5-10")}, PasswordChangeNoDenyACE},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ClassifyPasswordChange(pcSD(t, c.aces...))
			if err != nil || got != c.want {
				t.Fatalf("got %v err=%v, want %v", got, err, c.want)
			}
		})
	}
}

func TestClassifyPasswordChangeAcceptance(t *testing.T) {
	// AC1: true for the two-ACE user, false for one without them.
	with, _ := ClassifyPasswordChange(pcSD(t, denyCP("S-1-1-0"), denyCP("S-1-5-10")))
	without, _ := ClassifyPasswordChange(pcSD(t, allowCP("S-1-1-0"), allowCP("S-1-5-10")))
	if !with.Blocks() || without.Blocks() {
		t.Fatalf("with=%v without=%v", with, without)
	}
}

func TestClassifyPasswordChangeNullDACL(t *testing.T) {
	h := make([]byte, 20)
	h[0] = 1
	binary.LittleEndian.PutUint16(h[2:], ControlSelfRelative|ControlDACLPresent) // present, offset 0
	got, err := ClassifyPasswordChange(Raw(h))
	if err != nil || got != PasswordChangeNoDenyACE {
		t.Fatalf("null DACL: %v %v", got, err)
	}
}

func TestClassifyPasswordChangeNotConfirmed(t *testing.T) {
	good := pcSD(t, denyCP("S-1-1-0"), denyCP("S-1-5-10"))
	noDACL := make([]byte, 20)
	noDACL[0] = 1
	binary.LittleEndian.PutUint16(noDACL[2:], ControlSelfRelative)

	bad := map[string]Raw{
		"nil":             nil,
		"short":           good[:10],
		"truncated ACL":   good[:len(good)-3],
		"bad revision":    append(Raw{2}, good[1:]...),
		"no DACL at all":  Raw(noDACL),
		"ACE count wrong": func() Raw { b := append(Raw(nil), good...); binary.LittleEndian.PutUint16(b[20+4:], 5); return b }(),
	}
	for name, r := range bad {
		t.Run(name, func(t *testing.T) {
			got, err := ClassifyPasswordChange(r)
			if err == nil || codec.Code(err) == "" {
				t.Fatalf("want a typed error, got %v %v", got, err)
			}
			if got != PasswordChangeNotConfirmed || got.Blocks() {
				t.Fatalf("partial value reported: %v", got)
			}
		})
	}
	var zero PasswordChange
	if zero != PasswordChangeNotConfirmed {
		t.Fatal("zero value must be not confirmed")
	}
}

// Every prefix and every single-byte flip of a good descriptor either yields a typed error with
// NotConfirmed, or a real state: never a panic and never a state alongside an error.
func TestClassifyPasswordChangeNoPartialValue(t *testing.T) {
	good := pcSD(t, denyCP("S-1-1-0"), denyCP("S-1-5-10"))
	check := func(r Raw) {
		got, err := ClassifyPasswordChange(r)
		if err != nil && got != PasswordChangeNotConfirmed {
			t.Fatalf("state %v with error %v", got, err)
		}
	}
	for i := 0; i <= len(good); i++ {
		check(good[:i])
	}
	for i := range good {
		for _, x := range []byte{0x01, 0x80, 0xff} {
			m := append(Raw(nil), good...)
			m[i] ^= x
			check(m)
		}
	}
}

// A DACL whose stored order lets an allow run before the explicit denies is not a clean "Blocked":
// Windows evaluates in stored order (SD-R11), so the user may be able to change the password.
func TestClassifyPasswordChangeNonCanonicalOrder(t *testing.T) {
	allowAllControl := pcACE{typ: TypeAccessAllowed, mask: MaskControlAccess, trustee: "S-1-1-0"}
	inhAllow := pcACE{typ: TypeAccessAllowedObject, flags: FlagInherited, mask: MaskControlAccess, obj: cpGUID, trustee: "S-1-1-0"}
	condAllow := pcACE{typ: TypeAllowedCallback, mask: MaskControlAccess, trustee: "S-1-1-0"}
	condAllowInheritOnly := pcACE{typ: TypeAllowedCallback, flags: FlagInheritOnly | FlagContainerInherit, mask: MaskControlAccess, trustee: "S-1-1-0"}
	cases := []struct {
		name     string
		aces     []pcACE
		wantCode string // "" = a real state is expected
		want     PasswordChange
	}{
		{"explicit allow for the right before both denies", []pcACE{allowCP("S-1-1-0"), denyCP("S-1-1-0"), denyCP("S-1-5-10")}, AnomalyOrderOutcome, PasswordChangeNotConfirmed},
		{"allow of all control rights before the denies", []pcACE{allowAllControl, denyCP("S-1-1-0"), denyCP("S-1-5-10")}, AnomalyOrderOutcome, PasswordChangeNotConfirmed},
		{"inherited allow before the explicit denies", []pcACE{inhAllow, denyCP("S-1-1-0"), denyCP("S-1-5-10")}, AnomalyOrderOutcome, PasswordChangeNotConfirmed},
		{"allow before a single deny", []pcACE{allowCP("S-1-5-11"), denyCP("S-1-5-10")}, AnomalyOrderOutcome, PasswordChangeNotConfirmed},
		{"conditional allow before the denies", []pcACE{condAllow, denyCP("S-1-1-0"), denyCP("S-1-5-10")}, AnomalyCallbackPresent, PasswordChangeNotConfirmed},
		{"conditional allow after the denies is harmless", []pcACE{denyCP("S-1-1-0"), denyCP("S-1-5-10"), condAllow}, "", PasswordChangeBlocked},
		{"inherit-only conditional allow does not apply", []pcACE{condAllowInheritOnly, denyCP("S-1-1-0"), denyCP("S-1-5-10")}, "", PasswordChangeBlocked},
		// Canonical order still classifies.
		{"canonical: denies then allows", []pcACE{denyCP("S-1-1-0"), denyCP("S-1-5-10"), allowCP("S-1-1-0"), inhAllow}, "", PasswordChangeBlocked},
		{"canonical: one deny then allows", []pcACE{denyCP("S-1-5-10"), allowCP("S-1-1-0")}, "", PasswordChangeBlockedOneACE},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ClassifyPasswordChange(pcSD(t, c.aces...))
			if c.wantCode != "" {
				if codec.Code(err) != c.wantCode || got != PasswordChangeNotConfirmed || got.Blocks() {
					t.Fatalf("got %v err=%v code=%q, want not_confirmed + %s", got, err, codec.Code(err), c.wantCode)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %v err=%v, want %v", got, err, c.want)
			}
		})
	}
}
