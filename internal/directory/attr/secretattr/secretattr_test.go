package secretattr

import (
	"slices"
	"testing"
)

func TestStaticListIsComplete(t *testing.T) {
	// §3.7's own examples: a list that loses one of these would let it into a general search.
	for _, a := range []string{"unicodePwd", "ms-Mcs-AdmPwd", "msLAPS-Password", "msFVE-RecoveryPassword", "msFVE-KeyPackage"} {
		if !slices.Contains(Static(), a) {
			t.Errorf("%s missing from the static SecretAttrs list", a)
		}
	}
	seen := map[string]bool{}
	for _, a := range Static() {
		if seen[a] {
			t.Errorf("%s listed twice", a)
		}
		seen[a] = true
	}
}

func TestStaticReturnsACopy(t *testing.T) {
	s := Static()
	s[0] = "tampered"
	if Static()[0] == "tampered" {
		t.Fatal("Static exposes the package's list")
	}
}
