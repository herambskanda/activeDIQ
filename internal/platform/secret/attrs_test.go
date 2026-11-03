package secret

import "testing"

func TestIsStaticAttrIgnoresCase(t *testing.T) {
	for _, a := range StaticAttrs() {
		if !IsStaticAttr(a) {
			t.Errorf("%s not recognised", a)
		}
	}
	if !IsStaticAttr("UNICODEPWD") || !IsStaticAttr("MS-MCS-ADMPWD") {
		t.Error("case-insensitive match failed")
	}
	if IsStaticAttr("mail") || IsStaticAttr("") {
		t.Error("false positive")
	}
}

func TestStaticAttrsReturnsACopy(t *testing.T) {
	s := StaticAttrs()
	s[0] = "tampered"
	if StaticAttrs()[0] == "tampered" {
		t.Fatal("StaticAttrs exposes the package's list")
	}
}
