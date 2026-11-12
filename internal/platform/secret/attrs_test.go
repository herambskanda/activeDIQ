package secret

import "testing"

func TestIsPlainAttrName(t *testing.T) {
	for _, ok := range []string{"mail", "msDS-ManagedPassword", "a1", "snake_case"} {
		if !IsPlainAttrName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "1.2.840.113556.1.4.90", "OID.1.2", "mail;binary", " mail", "mail ", "mail\x00", "9mail", "-mail", "a.b"} {
		if IsPlainAttrName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
