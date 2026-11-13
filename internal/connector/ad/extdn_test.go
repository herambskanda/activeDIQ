package ad

import "testing"

func TestPlainDN(t *testing.T) { // T-1202: Samba applies the control to the entry name too
	for in, want := range map[string]string{
		"CN=a,DC=x": "CN=a,DC=x",
		"<GUID=0102030405060708090a0b0c0d0e0f10>;<SID=S-1-5-21-1-2-3-500>;CN=a\\, b,DC=x": "CN=a\\, b,DC=x",
		"<GUID=0102030405060708090a0b0c0d0e0f10>;CN=a,DC=x":                               "CN=a,DC=x",
		"<GUID=zz>;CN=a": "<GUID=zz>;CN=a", // unparsable: left for the caller to fail on, not guessed
		"":               "",
	} {
		if got := plainDN(in); got != want {
			t.Errorf("plainDN(%q) = %q, want %q", in, got, want)
		}
	}
}
