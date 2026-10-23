package tier0

import (
	"fmt"
	"strings"
)

// RulePropsVersion names the closed mapping table below (threat-model §6.4 TM-D25 rule 7g).
const RulePropsVersion = "ruleprops v1"

// ruleProp is one row of ruleprops v1: a property a dynamic membership rule may name, the Graph
// PATCH keys that set it and the LDAP attributes whose Entra Connect sync reaches it. All names are
// compared case-insensitively. Unverified marks a mapping the lab has not confirmed; it stays in
// the table, so the write is refused (safe direction) until the lab says otherwise.
type ruleProp struct {
	Name       string // "user.department" / "device.displayName"
	Graph      []string
	AD         []string
	Unverified bool // documentation only: the table is applied as-is, so unverified rows already refuse
}

// userSimple are the user properties whose Graph key is the property's own name.
// https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership
var userSimple = []string{"department", "companyName", "givenName", "surname", "jobTitle", "city", "state",
	"streetAddress", "postalCode", "country", "displayName", "employeeId", "preferredLanguage", "usageLocation",
	"userPrincipalName", "userType", "accountEnabled", "mail", "mailNickName", "passwordPolicies", "employeeHireDate", "otherMails"}

// userAD is the AD attribute(s) of each simple property (Entra Connect default flows,
// https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-sync-attributes-synchronized).
var userAD = map[string][]string{
	"department": {"department"}, "companyName": {"company"}, "givenName": {"givenName"}, "surname": {"sn"},
	"jobTitle": {"title"}, "city": {"l"}, "state": {"st"}, "streetAddress": {"streetAddress"},
	"postalCode": {"postalCode"}, "country": {"co", "c", "countryCode"}, "displayName": {"displayName"}, "employeeId": {"employeeID"},
	"usageLocation":     {"c", "co", "countryCode"},
	"preferredLanguage": {"preferredLanguage"}, "userPrincipalName": {"userPrincipalName"}, "accountEnabled": {"userAccountControl"},
	"mail": {"mail"}, "mailNickName": {"mailNickname"},
}

// userUnverified are the simple rows whose AD flow is not confirmed (rule 7g).
var userUnverified = map[string]bool{"country": true, "usageLocation": true, "preferredLanguage": true}

// devicePropNames are the device properties a rule may use
// (https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership).
var deviceSimple = []string{"accountEnabled", "deviceCategory", "deviceId", "deviceManufacturer", "deviceModel",
	"deviceOSType", "deviceOSVersion", "devicePhysicalIds", "deviceOwnership", "displayName", "domainName",
	"enrollmentProfileName", "isRooted", "managementType", "organizationalUnit", "profileType", "systemLabels",
	"mdmAppId", "deviceTrustType"}

var deviceAD = map[string][]string{"displayName": {"displayName"}, "accountEnabled": {"userAccountControl"},
	"organizationalUnit": {"distinguishedName"}, "deviceOSType": {"operatingSystem"},
	"deviceOSVersion": {"operatingSystemVersion"}}

const (
	userExtContainer   = "onpremisesextensionattributes"
	deviceExtContainer = "extensionattributes"
)

// rulePropsV1 is built once. The table is data in code, closed and versioned.
var rulePropsV1 = buildRuleProps()

func buildRuleProps() map[string]ruleProp {
	m := map[string]ruleProp{}
	add := func(r ruleProp) { m[strings.ToLower(r.Name)] = r }
	for _, p := range userSimple {
		add(ruleProp{Name: "user." + p, Graph: []string{p}, AD: userAD[p], Unverified: userUnverified[p]})
	}
	add(ruleProp{Name: "user.mobile", Graph: []string{"mobilePhone"}, AD: []string{"mobile"}})
	add(ruleProp{Name: "user.telephoneNumber", Graph: []string{"businessPhones"}, AD: []string{"telephoneNumber"}})
	add(ruleProp{Name: "user.facsimileTelephoneNumber", Graph: []string{"faxNumber"}, AD: []string{"facsimileTelephoneNumber"}})
	add(ruleProp{Name: "user.physicalDeliveryOfficeName", Graph: []string{"officeLocation"}, AD: []string{"physicalDeliveryOfficeName"}})
	// Graph `mail` changes proxyAddresses ("Changes to the mail property update this collection").
	add(ruleProp{Name: "user.proxyAddresses", Graph: []string{"mail", "proxyAddresses"}, AD: []string{"proxyAddresses", "mail"}})
	add(ruleProp{Name: "user.sipProxyAddress", Graph: []string{"imAddresses"}, AD: []string{"msRTCSIP-PrimaryUserAddress"}, Unverified: true})
	add(ruleProp{Name: "user.objectId"})       // server-assigned on create (7d)
	add(ruleProp{Name: "user.assignedPlans"})  // assignLicense (7e)
	add(ruleProp{Name: "user.dirSyncEnabled"}) // read-only
	add(ruleProp{Name: "user.onPremisesSecurityIdentifier"})
	add(ruleProp{Name: "user.onPremisesDistinguishedName", AD: []string{"distinguishedName"}})
	add(ruleProp{Name: "user.manager", Graph: []string{"manager"}, AD: []string{"manager"}}) // Direct Reports for (7c)
	add(ruleProp{Name: "user.memberOf", AD: []string{"member"}})
	for i := 1; i <= 15; i++ {
		n := fmt.Sprintf("extensionAttribute%d", i)
		add(ruleProp{Name: "user." + n, Graph: []string{userExtContainer}, AD: []string{n}})
		add(ruleProp{Name: "device." + n, Graph: []string{deviceExtContainer}})
	}
	for _, p := range deviceSimple {
		add(ruleProp{Name: "device." + p, Graph: []string{p}, AD: deviceAD[p]})
	}
	add(ruleProp{Name: "device.objectId"})
	add(ruleProp{Name: "device.memberOf", AD: []string{"member"}})
	return m
}

// isDirectoryExtension reports whether name (lower case, no prefix) is extension_<appId>_<name>:
// 32 hex digits of the application id (no hyphens), an underscore and a non-empty name.
func isDirectoryExtension(name string) bool {
	rest, ok := strings.CutPrefix(name, "extension_")
	if !ok || len(rest) < 34 || rest[32] != '_' {
		return false
	}
	for _, c := range rest[:32] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// knownRuleProperty reports whether prop ("user.x", lower case) has a row in ruleprops v1. The
// extension_<appId>_<name> family is one pattern row on users.
func knownRuleProperty(prop string) bool {
	if _, ok := rulePropsV1[prop]; ok {
		return true
	}
	rest, ok := strings.CutPrefix(prop, "user.")
	return ok && isDirectoryExtension(rest)
}

// RulePropertyNames lists the properties of ruleprops v1 (lower case), for the drift test.
func RulePropertyNames() []string {
	out := make([]string, 0, len(rulePropsV1))
	for k := range rulePropsV1 {
		out = append(out, k)
	}
	return out
}

// reaches returns the lower-case rule properties of the given kind prefix ("user." or "device.")
// that a write key can change. plane is ENTRA (Graph keys) or AD (LDAP attributes). ext is the
// connector's map of customer-mapped directory-extension LDAP attributes to rule property names.
func reaches(plane Plane, prefix, key string, ext map[string]string) []string {
	k := strings.ToLower(key)
	head, _, _ := strings.Cut(k, ".") // dotted sub-keys of a container: onPremisesExtensionAttributes.extensionAttribute9
	var out []string
	for name, row := range rulePropsV1 {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		cols := row.Graph
		if plane == PlaneAD {
			cols = row.AD
		}
		for _, c := range cols {
			if strings.EqualFold(c, k) || strings.EqualFold(c, head) {
				out = append(out, name)
				break
			}
		}
	}
	if plane == PlaneEntra && prefix == "user." && isDirectoryExtension(head) {
		out = append(out, "user."+head)
	}
	if plane == PlaneAD && prefix == "user." {
		if p, ok := ext[k]; ok {
			out = append(out, strings.ToLower(p))
		}
	}
	return out
}
