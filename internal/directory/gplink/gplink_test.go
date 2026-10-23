package gplink

import "testing"

const (
	g1 = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
	g2 = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
)

func TestParse(t *testing.T) {
	v := "[LDAP://cn=" + g1 + ",cn=policies,cn=system,DC=lab,DC=test;0][ldap://CN=" + g2 + ",CN=Policies,CN=System,DC=lab,DC=test;3]"
	ls, err := Parse(v)
	if err != nil || len(ls) != 2 {
		t.Fatalf("%v %v", ls, err)
	}
	if ls[0].Disabled() || ls[0].Enforced() || !ls[1].Disabled() || !ls[1].Enforced() {
		t.Errorf("options: %+v", ls)
	}
	if ls[1].GPOID.String() != "6ac1786c-016f-11d2-945f-00c04fb984f9" {
		t.Errorf("id %s", ls[1].GPOID)
	}
}

func TestEmpty(t *testing.T) {
	for _, v := range []string{"", " "} {
		if ls, err := Parse(v); err != nil || ls != nil {
			t.Errorf("%q: %v %v", v, ls, err)
		}
	}
}

func TestRejects(t *testing.T) {
	bad := []string{
		"[LDAP://cn=" + g1 + ",DC=lab;0",              // no close
		"LDAP://cn=" + g1 + ",DC=lab;0",               // no brackets
		"[LDAP://cn=" + g1 + ",DC=lab]",               // no options
		"[LDAP://cn=" + g1 + ",DC=lab;x]",             // options not digits
		"[LDAP://cn=" + g1 + ",DC=lab;99999999999]",   // options overflow
		"[LDAP://cn=notaguid,DC=lab;0]",               // first RDN not a GUID
		"[LDAP://ou=" + g1 + ",DC=lab;0]",             // first RDN not cn
		"[HTTP://cn=" + g1 + ",DC=lab;0]",             // scheme
		"[LDAP://cn=" + g1 + ",DC=lab;0]junk",         // trailing
		"[LDAP://cn=" + g1 + ",DC=lab;0][LDAP://x;1]", // second entry bad
		"[LDAP://cn=" + g1 + ",DC=lab;0]\x00",         // NUL
	}
	for _, v := range bad {
		if _, err := Parse(v); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
}
