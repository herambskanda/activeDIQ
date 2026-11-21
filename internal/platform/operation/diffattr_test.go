package operation

import "testing"

func TestDiffAttrNameStripsOnlyTheDigestPrefixes(t *testing.T) {
	for in, want := range map[string]string{
		"set:description": "description", "clear:mail": "mail", "add:member": "member", "remove:member": "member",
		"~class": "class", "description": "description", "set:1.2.840.113556.1.4.90": "1.2.840.113556.1.4.90",
		"set:unicodePwd;binary": "unicodePwd;binary",
	} {
		if got := diffAttrName(in); got != want {
			t.Errorf("diffAttrName(%q) = %q, want %q", in, got, want)
		}
	}
}
