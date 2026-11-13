package ad

import (
	"sync"

	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// constructedReadOnly are attributes the DC computes on a base read. A search naming one is refused
// (connector-contract §5.1: tokenGroups returns nothing in a subtree search), Read serves them.
var constructedReadOnly = map[string]struct{}{
	"ntsecuritydescriptor":                {},
	"tokengroups":                         {},
	"allowedattributeseffective":          {},
	"allowedchildclasseseffective":        {},
	"sdrightseffective":                   {},
	"msds-user-account-control-computed":  {},
	"msds-userpasswordexpirytimecomputed": {},
}

var (
	defaultSchemaOnce sync.Once
	defaultSchema     *ldapfilter.Schema
)

// DefaultSchema is the built-in allowlist for the attributes the connector's first consumers read
// (tier-0 classifier, rights check). The full per-forest schema (DescribeSchema) replaces it later;
// until then an attribute outside this list is refused rather than passed through.
func DefaultSchema() *ldapfilter.Schema {
	defaultSchemaOnce.Do(func() {
		s, c := ldapfilter.SynString, true
		defaultSchema = ldapfilter.NewSchema(
			ldapfilter.AttrInfo{Name: "attributeID", OID: "1.2.840.113556.1.2.30", Syntax: s},
			ldapfilter.AttrInfo{Name: "objectClass", OID: "2.5.4.0", Syntax: s},
			ldapfilter.AttrInfo{Name: "objectCategory", OID: "1.2.840.113556.1.4.782", Syntax: ldapfilter.SynDN},
			ldapfilter.AttrInfo{Name: "objectGUID", OID: "1.2.840.113556.1.4.2", Syntax: ldapfilter.SynGUID},
			ldapfilter.AttrInfo{Name: "objectSid", OID: "1.2.840.113556.1.4.146", Syntax: ldapfilter.SynSID},
			ldapfilter.AttrInfo{Name: "cn", OID: "2.5.4.3", Syntax: s},
			ldapfilter.AttrInfo{Name: "ou", OID: "2.5.4.11", Syntax: s},
			ldapfilter.AttrInfo{Name: "name", OID: "1.2.840.113556.1.4.1", Syntax: s},
			ldapfilter.AttrInfo{Name: "distinguishedName", OID: "2.5.4.49", Syntax: ldapfilter.SynDN},
			ldapfilter.AttrInfo{Name: "sAMAccountName", OID: "1.2.840.113556.1.4.221", Syntax: s},
			ldapfilter.AttrInfo{Name: "userPrincipalName", OID: "1.2.840.113556.1.4.656", Syntax: s},
			ldapfilter.AttrInfo{Name: "displayName", OID: "1.2.840.113556.1.2.13", Syntax: s},
			ldapfilter.AttrInfo{Name: "description", OID: "2.5.4.13", Syntax: s},
			ldapfilter.AttrInfo{Name: "member", OID: "2.5.4.31", Syntax: ldapfilter.SynDN},
			ldapfilter.AttrInfo{Name: "memberOf", OID: "1.2.840.113556.1.2.102", Syntax: ldapfilter.SynDN},
			ldapfilter.AttrInfo{Name: "primaryGroupID", OID: "1.2.840.113556.1.4.98", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "userAccountControl", OID: "1.2.840.113556.1.4.8", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "instanceType", OID: "1.2.840.113556.1.2.1", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "groupType", OID: "1.2.840.113556.1.4.750", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "adminCount", OID: "1.2.840.113556.1.4.150", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "whenCreated", OID: "1.2.840.113556.1.2.2", Syntax: ldapfilter.SynGenTime},
			ldapfilter.AttrInfo{Name: "whenChanged", OID: "1.2.840.113556.1.2.3", Syntax: ldapfilter.SynGenTime},
			ldapfilter.AttrInfo{Name: "uSNChanged", OID: "1.2.840.113556.1.2.120", Syntax: ldapfilter.SynInt64},
			ldapfilter.AttrInfo{Name: "gPLink", OID: "1.2.840.113556.1.4.891", Syntax: s},
			ldapfilter.AttrInfo{Name: "sIDHistory", OID: "1.2.840.113556.1.4.609", Syntax: ldapfilter.SynSID},
			ldapfilter.AttrInfo{Name: "dSHeuristics", OID: "1.2.840.113556.1.2.212", Syntax: s},
			ldapfilter.AttrInfo{Name: "gPOptions", OID: "1.2.840.113556.1.4.892", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "wellKnownObjects", OID: "1.2.840.113556.1.4.618", Syntax: s},
			ldapfilter.AttrInfo{Name: "msDS-Behavior-Version", OID: "1.2.840.113556.1.4.1459", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "msDS-SecondaryKrbTgtNumber", OID: "1.2.840.113556.1.4.1929", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "msDS-AllowedToDelegateTo", OID: "1.2.840.113556.1.4.1787", Syntax: s},
			ldapfilter.AttrInfo{Name: "msDS-AllowedToActOnBehalfOfOtherIdentity", OID: "1.2.840.113556.1.4.2182", Syntax: ldapfilter.SynOctet},
			// Path-valued user attributes: read as inert strings only (TM-F-NTLM, T-0256) — the connector
			// never opens, resolves or dials them.
			ldapfilter.AttrInfo{Name: "homeDirectory", OID: "1.2.840.113556.1.4.44", Syntax: s},
			ldapfilter.AttrInfo{Name: "homeDrive", OID: "1.2.840.113556.1.4.45", Syntax: s},
			ldapfilter.AttrInfo{Name: "profilePath", OID: "1.2.840.113556.1.4.139", Syntax: s},
			ldapfilter.AttrInfo{Name: "scriptPath", OID: "1.2.840.113556.1.4.62", Syntax: s},
			// PDC emulator lookup for the Key Admins presence rule (T-0631, TM-R25).
			ldapfilter.AttrInfo{Name: "fSMORoleOwner", OID: "1.2.840.113556.1.4.369", Syntax: ldapfilter.SynDN},
			ldapfilter.AttrInfo{Name: "operatingSystemVersion", OID: "1.2.840.113556.1.4.364", Syntax: s},
			// Object restore (T-1624): deleted-object reads and the Recycle Bin feature check.
			ldapfilter.AttrInfo{Name: "isDeleted", OID: "1.2.840.113556.1.2.48", Syntax: ldapfilter.SynBool},
			ldapfilter.AttrInfo{Name: "lastKnownParent", OID: "1.2.840.113556.1.4.781", Syntax: ldapfilter.SynDN},
			ldapfilter.AttrInfo{Name: "isRecycled", Syntax: ldapfilter.SynBool},
			ldapfilter.AttrInfo{Name: "msDS-LastKnownRDN", Syntax: s},
			ldapfilter.AttrInfo{Name: "isCriticalSystemObject", Syntax: ldapfilter.SynBool},
			ldapfilter.AttrInfo{Name: "msDS-EnabledFeature", OID: "1.2.840.113556.1.4.2061", Syntax: ldapfilter.SynDN},
			ldapfilter.AttrInfo{Name: "serverReference", OID: "1.2.840.113556.1.4.515", Syntax: ldapfilter.SynDN},
			// dNSHostName: name-only. Its attributeID is also the lazy-commit control OID, which FF-SP2 lets
			// only scope name; an OID-form descriptor for it stays unknown and fails closed.
			ldapfilter.AttrInfo{Name: "dNSHostName", Syntax: s},
			// The change feed (T-1194): the deleted object's last parent (name-only, a DN) and the forest's
			// deletion lifetimes on CN=Directory Service.
			ldapfilter.AttrInfo{Name: "lastKnownParent", Syntax: ldapfilter.SynDN},
			ldapfilter.AttrInfo{Name: "tombstoneLifetime", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "msDS-DeletedObjectLifetime", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "servicePrincipalName", OID: "1.2.840.113556.1.4.771", Syntax: s},
			ldapfilter.AttrInfo{Name: "msDS-AdditionalDnsHostName", OID: "1.2.840.113556.1.4.1717", Syntax: s},
			// isDeleted: read with the show-deleted control for the OBJECT_DELETE retry check (T-1623); never writable (deny-list).
			ldapfilter.AttrInfo{Name: "isDeleted", OID: "1.2.840.113556.1.2.48", Syntax: ldapfilter.SynBool},
			ldapfilter.AttrInfo{Name: "lDAPDisplayName", OID: "1.2.840.113556.1.2.460", Syntax: s},
			ldapfilter.AttrInfo{Name: "schemaIDGUID", OID: "1.2.840.113556.1.4.148", Syntax: ldapfilter.SynOctet},
			ldapfilter.AttrInfo{Name: "attributeSecurityGUID", OID: "1.2.840.113556.1.4.149", Syntax: ldapfilter.SynOctet},
			ldapfilter.AttrInfo{Name: "rightsGuid", OID: "1.2.840.113556.1.4.340", Syntax: s},
			ldapfilter.AttrInfo{Name: "searchFlags", OID: "1.2.840.113556.1.2.334", Syntax: ldapfilter.SynInt32},
			// directReports: the manager back-link, read by OBJECT_DELETE to learn whether removing the object
			// clears other objects' manager (T-1632, contract §8.9 DELETE). Constructed: never filterable or writable.
			ldapfilter.AttrInfo{Name: "directReports", OID: "1.2.840.113556.1.2.436", Syntax: ldapfilter.SynDN, Constructed: c},
			ldapfilter.AttrInfo{Name: "nTSecurityDescriptor", OID: "1.2.840.113556.1.2.281", Syntax: ldapfilter.SynOctet, Constructed: c},
			ldapfilter.AttrInfo{Name: "tokenGroups", OID: "1.2.840.113556.1.4.1301", Syntax: ldapfilter.SynSID, Constructed: c},
			ldapfilter.AttrInfo{Name: "allowedAttributesEffective", OID: "1.2.840.113556.1.4.914", Syntax: s, Constructed: c},
			ldapfilter.AttrInfo{Name: "allowedChildClassesEffective", OID: "1.2.840.113556.1.4.912", Syntax: s, Constructed: c},
			ldapfilter.AttrInfo{Name: "sDRightsEffective", OID: "1.2.840.113556.1.4.1304", Syntax: ldapfilter.SynInt32, Constructed: c},
			// The directory sync's closed attribute list (directory/sync.Attributes(), T-1189) beyond what
			// is named above. Name-only like dNSHostName: an OID-form descriptor stays unknown and fails
			// closed until the per-forest schema supplies verified OIDs. Test_DefaultSchema_covers_sync_list
			// fails if a name is added to that list without an entry here.
			ldapfilter.AttrInfo{Name: "mail", Syntax: s},
			ldapfilter.AttrInfo{Name: "company", Syntax: s},
			ldapfilter.AttrInfo{Name: "operatingSystem", Syntax: s},
			ldapfilter.AttrInfo{Name: "managedBy", Syntax: ldapfilter.SynDN},
			ldapfilter.AttrInfo{Name: "mS-DS-ConsistencyGuid", Syntax: ldapfilter.SynOctet},
			// Integer8 (FILETIME): 0 and 0x7FFFFFFFFFFFFFFF are both "never" for accountExpires; pwdLastSet 0
			// means must-change; lockoutTime 0 means not locked. Decoded by directory/attr/filetime.
			ldapfilter.AttrInfo{Name: "lockoutTime", Syntax: ldapfilter.SynInt64},
			ldapfilter.AttrInfo{Name: "pwdLastSet", Syntax: ldapfilter.SynInt64},
			ldapfilter.AttrInfo{Name: "accountExpires", Syntax: ldapfilter.SynInt64},
			ldapfilter.AttrInfo{Name: "lastLogonTimestamp", Syntax: ldapfilter.SynInt64},
			// Deleted-object attributes: meaningful only on a search with the show-deleted control (the
			// deleted-objects search is a separate ticket); on a live object isDeleted/isRecycled are absent.
			ldapfilter.AttrInfo{Name: "isDeleted", Syntax: ldapfilter.SynBool},
			ldapfilter.AttrInfo{Name: "isRecycled", Syntax: ldapfilter.SynBool},
			ldapfilter.AttrInfo{Name: "lastKnownParent", Syntax: ldapfilter.SynDN},
		)
	})
	return defaultSchema
}
