package sync

import (
	"slices"
	"strings"
)

// attributes is the closed list of directory attributes a sync requests, as the schema's
// ldapDisplayName spells each. It is the union of
//
//   - what the inventory datasets read today (internal/directory/inventory/datasets*.go: the D7 time
//     inputs, userAccountControl, primaryGroupID, servicePrincipalName, groupType, member, managedBy,
//     and the JSON attributes mail, company, description, dNSHostName, operatingSystem,
//     operatingSystemVersion, msDS-AllowedToDelegateTo), and
//   - the identifiers universal search and correlation already serve (objectSid, sAMAccountName,
//     userPrincipalName, displayName, mS-DS-ConsistencyGuid, whenCreated, whenChanged),
//   - plus objectClass (kind and class) and the deleted-object trio isDeleted, isRecycled and
//     lastKnownParent.
//
// objectGUID is not here: a DirectoryEntry carries it as its identity. A later ticket that needs
// another attribute (T-1071, T-1111, T-1129) adds it here and to the mapping, in one change.
//
// No member of this list is a secret (secretattr.Static, or anything the connector's schema flags
// with searchFlags 0x80, 0x200 or 0x1000), and nTSecurityDescriptor, which the ScopedSearch handler
// refuses until T-0118, is not on it. Test_closed_list_* pin both.
var attributes = []string{
	"objectClass",
	"objectSid",
	"sAMAccountName",
	"userPrincipalName",
	"displayName",
	"mail",
	"company",
	"description",
	"managedBy",
	"mS-DS-ConsistencyGuid",
	"whenCreated",
	"whenChanged",
	"userAccountControl",
	"primaryGroupID",
	"lockoutTime",
	"pwdLastSet",
	"accountExpires",
	"lastLogonTimestamp",
	"servicePrincipalName",
	"msDS-AllowedToDelegateTo",
	"dNSHostName",
	"operatingSystem",
	"operatingSystemVersion",
	"groupType",
	"member",
	"isDeleted",
	"isRecycled",
	"lastKnownParent",
}

// Attributes returns a copy of the closed attribute list.
func Attributes() []string { return slices.Clone(attributes) }

// inClosed reports whether name is on the closed list, ignoring case.
func inClosed(name string) bool {
	return slices.ContainsFunc(attributes, func(a string) bool { return strings.EqualFold(a, name) })
}
