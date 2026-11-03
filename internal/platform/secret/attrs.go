package secret

import (
	"slices"
	"strings"
)

// static is safe-primitives §3.7's static list of directory attributes whose values are secrets
// whether or not an estate's schema flags them, as the schema's ldapDisplayName spells each one. The
// schema-driven half (searchFlags 0x80, 0x200 or 0x1000) is computed at connect by the connector.
//
// It lives here, in the kernel, because the operation runner must recognise these names and the kernel
// imports nothing above it. internal/directory/attr/secretattr re-exports it; this is the one copy.
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

// StaticAttrs returns a copy of the static secret-attribute list.
func StaticAttrs() []string { return slices.Clone(static) }

// IsPlainAttrName reports whether name is a plain attribute descr: a letter, then letters, digits,
// hyphens or underscores (RFC 4512 §1.4 descr, without the ";option" suffix). A numericoid, an "OID."
// prefix, an ";binary" option, whitespace and control characters are all not plain. The directory
// accepts those as aliases of the same attribute, so a name-list check is only sound once every name
// is known to be a plain one.
func IsPlainAttrName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case i > 0 && (c >= '0' && c <= '9' || c == '-' || c == '_'):
		default:
			return false
		}
	}
	return true
}

// IsStaticAttr reports whether name is on the static list, ignoring case.
func IsStaticAttr(name string) bool {
	_, ok := staticFold[strings.ToLower(name)]
	return ok
}
