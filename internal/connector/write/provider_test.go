package write

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
)

// CC-WRITE-20 g: a GPO whose cn is not a GUID is tier0; ordinary objects are not touched by the rule.
func TestGPOCNMustBeAGUID(t *testing.T) {
	gpo := func(cn string) *ad.Entry {
		return ad.NewEntry("CN="+cn+",CN=Policies,CN=System,DC=lab,DC=test", map[string][][]byte{
			"objectClass": {[]byte("top"), []byte("container"), []byte("groupPolicyContainer")}, "cn": {[]byte(cn)}})
	}
	for cn, want := range map[string]bool{
		"{31B2F340-016D-11D2-945F-00C04FB984F9}": false, "31b2f340-016d-11d2-945f-00c04fb984f9": false,
		"Default Domain Policy": true, "{not-a-guid}": true, "": true,
	} {
		if got := gpoCNInvalid(gpo(cn)); got != want {
			t.Errorf("cn %q: %v want %v", cn, got, want)
		}
	}
	user := ad.NewEntry("CN=x,DC=lab,DC=test", map[string][][]byte{"objectClass": {[]byte("user")}, "cn": {[]byte("x")}})
	if gpoCNInvalid(user) {
		t.Error("a user is not subject to the GPO cn rule")
	}
}
