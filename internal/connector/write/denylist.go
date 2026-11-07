package write

import "strings"

// deniedAttrs is the §8.10.4 deny-list for OBJECT_UPDATE and OBJECT_CREATE.initial, in one place and
// shared by both kinds. Names are compared case-insensitively after the attribute's options and
// numeric OID have been resolved to the schema's ldapDisplayName. The list may grow without a
// contract change; it never shrinks.
var deniedAttrs = func() map[string]struct{} {
	m := map[string]struct{}{}
	for _, n := range []string{
		// credentials
		"unicodePwd", "userPassword", "dBCSPwd", "ntPwdHistory", "lmPwdHistory", "supplementalCredentials",
		"pwdLastSet", "lockoutTime", "msDS-KeyCredentialLink", "altSecurityIdentities",
		// identity and structure
		"userAccountControl", "nTSecurityDescriptor", "objectClass", "objectCategory", "objectGUID",
		"objectSid", "sIDHistory", "distinguishedName", "name", "cn", "ou", "isDeleted",
		"isCriticalSystemObject", "groupType", "sAMAccountType", "primaryGroupID", "member", "memberOf",
		// TM-D28 set_spn, signin_flags, signin_limits, map_credential
		"servicePrincipalName", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
		"msDS-SupportedEncryptionTypes", "accountExpires", "logonHours", "userWorkstations",
		// group policy
		"gPLink", "gPOptions",
		// system-only or DC-maintained attributes of the schema snapshot
		"whenCreated", "whenChanged", "uSNChanged", "uSNCreated", "instanceType", "adminCount",
		"dSHeuristics", "wellKnownObjects", "fSMORoleOwner", "schemaIDGUID", "attributeSecurityGUID",
		"rightsGuid", "lDAPDisplayName", "attributeID", "searchFlags", "serverReference",
		"operatingSystemVersion", "msDS-Behavior-Version", "msDS-SecondaryKrbTgtNumber",
		"tokenGroups", "allowedAttributesEffective", "allowedChildClassesEffective", "sDRightsEffective",
	} {
		m[strings.ToLower(n)] = struct{}{}
	}
	return m
}()

// Limits of OBJECT_UPDATE and OBJECT_CREATE.initial (contract §8.10.3). Constants, not settings.
const (
	maxEdits        = 64
	maxEditValues   = 1000
	maxTextBytes    = 32 << 10
	maxOctetsLength = 32 << 10
)

func isDenied(canonical string) bool {
	_, ok := deniedAttrs[strings.ToLower(canonical)]
	return ok
}

// attrBase is the attribute name without options (";binary", ";range=0-9"); the options themselves
// are never accepted on a write.
func attrBase(name string) (base string, hadOptions bool) {
	b, _, found := strings.Cut(name, ";")
	return b, found
}
