package operation

import "strings"

// testSecretNames stands in for the catalogue's static list (internal/directory/attr/secretattr), which
// the kernel's tests may not import: the composition root supplies the real predicate (AG-9).
var testSecretNames = []string{"unicodePwd", "ms-Mcs-AdmPwd", "msLAPS-Password", "msFVE-RecoveryPassword"}

func testSecretAttr(name string) bool {
	for _, n := range testSecretNames {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}
