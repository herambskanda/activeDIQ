// Package secretattr holds the static half of SecretAttrs (safe-primitives §3.7, X4): the directory
// attributes whose values are secrets whether or not an estate's schema flags them. The other half is
// schema-driven (searchFlags 0x80, 0x200 or 0x1000) and is computed at connect by the connector.
//
// The static list is the one source for everything that must recognise a secret attribute by name,
// the fitness-domain-keys check (no column named for one outside the sealed allow-list) among them.
// The operation runner may not import this package (the kernel imports nothing above it), so it takes
// IsStatic through operation.Config.SecretAttr, which the composition root supplies.
package secretattr

import (
	"slices"
	"strings"
)

// static is §3.7's static list, as the schema's ldapDisplayName spells each attribute.
var static = []string{
	"unicodePwd", "dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials",
	"userPassword", "unixUserPassword", "msDS-ManagedPassword",
	"ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
	"msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory",
	"msFVE-RecoveryPassword", "msFVE-KeyPackage", "msTPM-OwnerInformation",
	"msPKIAccountCredentials", "msPKIDPAPIMasterKeys",
}

// staticFold is static, lower-cased: AD attribute names are case-insensitive.
var staticFold = func() map[string]struct{} {
	m := make(map[string]struct{}, len(static))
	for _, a := range static {
		m[strings.ToLower(a)] = struct{}{}
	}
	return m
}()

// Static returns a copy of the static list.
func Static() []string { return slices.Clone(static) }

// IsStatic reports whether name is on the static list, ignoring case.
func IsStatic(name string) bool {
	_, ok := staticFold[strings.ToLower(name)]
	return ok
}
