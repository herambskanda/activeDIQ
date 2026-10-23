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
			ldapfilter.AttrInfo{Name: "groupType", OID: "1.2.840.113556.1.4.750", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "adminCount", OID: "1.2.840.113556.1.4.150", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "whenCreated", OID: "1.2.840.113556.1.2.2", Syntax: ldapfilter.SynGenTime},
			ldapfilter.AttrInfo{Name: "whenChanged", OID: "1.2.840.113556.1.2.3", Syntax: ldapfilter.SynGenTime},
			ldapfilter.AttrInfo{Name: "uSNChanged", OID: "1.2.840.113556.1.2.120", Syntax: ldapfilter.SynInt64},
			ldapfilter.AttrInfo{Name: "gPLink", OID: "1.2.840.113556.1.4.891", Syntax: s},
			ldapfilter.AttrInfo{Name: "gPOptions", OID: "1.2.840.113556.1.4.892", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "wellKnownObjects", OID: "1.2.840.113556.1.4.618", Syntax: s},
			ldapfilter.AttrInfo{Name: "msDS-SecondaryKrbTgtNumber", OID: "1.2.840.113556.1.4.1926", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "msDS-AllowedToDelegateTo", OID: "1.2.840.113556.1.4.1787", Syntax: s},
			ldapfilter.AttrInfo{Name: "msDS-AllowedToActOnBehalfOfOtherIdentity", OID: "1.2.840.113556.1.4.2182", Syntax: ldapfilter.SynOctet},
			ldapfilter.AttrInfo{Name: "serverReference", OID: "1.2.840.113556.1.4.515", Syntax: ldapfilter.SynDN},
			// dNSHostName: name-only. Its attributeID is also the lazy-commit control OID, which FF-SP2 lets
			// only scope name; an OID-form descriptor for it stays unknown and fails closed.
			ldapfilter.AttrInfo{Name: "dNSHostName", Syntax: s},
			ldapfilter.AttrInfo{Name: "servicePrincipalName", OID: "1.2.840.113556.1.4.771", Syntax: s},
			ldapfilter.AttrInfo{Name: "msDS-AdditionalDnsHostName", OID: "1.2.840.113556.1.4.1717", Syntax: s},
			ldapfilter.AttrInfo{Name: "lDAPDisplayName", OID: "1.2.840.113556.1.2.460", Syntax: s},
			ldapfilter.AttrInfo{Name: "schemaIDGUID", OID: "1.2.840.113556.1.4.148", Syntax: ldapfilter.SynOctet},
			ldapfilter.AttrInfo{Name: "searchFlags", OID: "1.2.840.113556.1.2.334", Syntax: ldapfilter.SynInt32},
			ldapfilter.AttrInfo{Name: "nTSecurityDescriptor", OID: "1.2.840.113556.1.4.151", Syntax: ldapfilter.SynOctet, Constructed: c},
			ldapfilter.AttrInfo{Name: "tokenGroups", OID: "1.2.840.113556.1.4.1301", Syntax: ldapfilter.SynSID, Constructed: c},
			ldapfilter.AttrInfo{Name: "allowedAttributesEffective", OID: "1.2.840.113556.1.4.914", Syntax: s, Constructed: c},
			ldapfilter.AttrInfo{Name: "allowedChildClassesEffective", OID: "1.2.840.113556.1.4.912", Syntax: s, Constructed: c},
			ldapfilter.AttrInfo{Name: "sDRightsEffective", OID: "1.2.840.113556.1.4.1304", Syntax: ldapfilter.SynInt32, Constructed: c},
		)
	})
	return defaultSchema
}
