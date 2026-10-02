// Package secretattr holds the static half of SecretAttrs (safe-primitives §3.7, X4): the directory
// attributes whose values are secrets whether or not an estate's schema flags them. The other half is
// schema-driven (searchFlags 0x80, 0x200 or 0x1000) and is computed at connect by the connector.
//
// The static list is the one source for everything that must recognise a secret attribute by name,
// the fitness-domain-keys check (no column named for one outside the sealed allow-list) among them.
package secretattr

import "slices"

// static is §3.7's static list, as the schema's ldapDisplayName spells each attribute.
var static = []string{
	"unicodePwd", "dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials",
	"userPassword", "unixUserPassword", "msDS-ManagedPassword",
	"ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
	"msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory",
	"msFVE-RecoveryPassword", "msFVE-KeyPackage", "msTPM-OwnerInformation",
	"msPKIAccountCredentials", "msPKIDPAPIMasterKeys",
}

// Static returns a copy of the static list.
func Static() []string { return slices.Clone(static) }
