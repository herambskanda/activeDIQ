package rights

import (
	"strings"

	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// This file is the Entra policy of threat-model §6.6 as data: the allow rows per feature family and
// the deny list. Nothing else in the package names a permission. Change a row here and the table
// tests in entra_test.go pin the effect.
//
// Rows marked [UNVERIFIED — lab] in §6.6 belong to T-0075 (lab G1-G10); where a row is unverified
// the row below takes the documented conservative reading: require the broader documented
// permission, allow nothing beyond what the page documents.

// GraphResourceAppID is Microsoft Graph's application id. Allow rows count only permissions granted
// on this resource; a same-named role on another resource satisfies nothing.
const GraphResourceAppID = "00000003-0000-0000-c000-000000000000"

// Need is one thing a family requires. It is met when the app holds any of Any (the first entry is
// the one reported as missing).
type Need struct {
	Any []string
}

// Row is one allow-list row.
type Row struct {
	Family v1.RightsFamily
	Needs  []Need
	// MissingBlocks: a missing need blocks activation (EV4 block) instead of warning. §6.6 and the
	// contract (§8.4): the read rows the connection cannot work without.
	MissingBlocks bool
}

func one(p string) []Need { return []Need{{Any: []string{p}}} }

// baselineFamilies are enabled on every connection: the connection cannot sync or run the tier-0
// pre-flight without them. An empty enabled_families list means exactly these (contract §8.4).
var baselineFamilies = []v1.RightsFamily{
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_TENANT_READ,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_USER_READ_DELTA,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_GROUP_DELTA,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_ADMIN_PREFLIGHT,
}

var allowRows = []Row{
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_TENANT_READ, Needs: one("Organization.Read.All"), MissingBlocks: true},
	// Organization.Read.All also covers GET /subscribedSkus.
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_SKU_READ, Needs: []Need{{Any: []string{"LicenseAssignment.Read.All", "Organization.Read.All"}}}},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_LICENCE_ASSIGN, Needs: one("LicenseAssignment.ReadWrite.All")},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_USER_CREATE, Needs: one("User.Create")},
	// UPN coverage is UNVERIFIED (lab): no extra permission is allowed for it.
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_USER_UPDATE, Needs: one("User.ReadUpdate.All")},
	// Whether app-only reset also needs a role is UNVERIFIED (lab G1); the app never gets the role.
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_PASSWORD_RESET, Needs: one("User-PasswordProfile.ReadWrite.All")},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_BLOCK, Needs: []Need{{Any: []string{"User.EnableDisableAccount.All"}}, {Any: []string{"User.Read.All"}}}},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_HARD_DELETE_RESTORE, Needs: one("User.DeleteRestore.All")},
	// User.ReadWrite.All is the only documented permission for soft delete and manager; whether
	// User.DeleteRestore.All suffices is UNVERIFIED (lab), so the conservative reading requires it.
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_SOFT_DELETE_MANAGER, Needs: one("User.ReadWrite.All")},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_REVOKE_SESSIONS, Needs: one("User.RevokeSessions.All")},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_INVITE, Needs: one("User.Invite.All")},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_GROUP_CREATE, Needs: one("Group.Create")},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_GROUP_UPDATE, Needs: one("Group.ReadWrite.All")},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_GROUP_MEMBERSHIP, Needs: one("GroupMember.ReadWrite.All")},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_USER_READ_DELTA, Needs: one("User.Read.All"), MissingBlocks: true},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_GROUP_DELTA, Needs: one("GroupMember.Read.All"), MissingBlocks: true},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_SIGN_IN_ACTIVITY, Needs: []Need{{Any: []string{"AuditLog.Read.All"}}, {Any: []string{"User.Read.All"}}}},
	// Reading roles is not managing them.
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_ADMIN_PREFLIGHT, Needs: []Need{{Any: []string{"Directory.Read.All"}}, {Any: []string{"RoleManagement.Read.Directory"}}}, MissingBlocks: true},
	{Family: v1.RightsFamily_RIGHTS_FAMILY_ENTRA_HYBRID_MONITOR, Needs: one("AuditLog.Read.All")},
}

// pimGroupReadNeeds are required whenever any Entra write feature is enabled (TM-D25 rule 4, TM-F-RIGHTS):
// without them the tier-0 guard cannot see eligible-only members and owners of role-assignable
// groups. Both are read-only.
var pimGroupReadNeeds = []Need{
	{Any: []string{"PrivilegedEligibilitySchedule.Read.AzureADGroup"}},
	{Any: []string{"PrivilegedAssignmentSchedule.Read.AzureADGroup"}},
}

// optionalAllowed are permissions that no feature requires but §6.6 recommends; holding one is
// never reported as excess. Policy.Read.ConditionalAccess proposes CA-excluded designations
// (TM-D25 rule 9); it reads policy and does not change it.
var optionalAllowed = []string{"Policy.Read.ConditionalAccess"}

// writeFamilies are the Entra families that change the tenant. Enabling any of them requires
// pimGroupReadNeeds.
var writeFamilies = map[v1.RightsFamily]bool{
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_LICENCE_ASSIGN:      true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_USER_CREATE:         true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_USER_UPDATE:         true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_PASSWORD_RESET:      true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_BLOCK:               true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_HARD_DELETE_RESTORE: true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_SOFT_DELETE_MANAGER: true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_REVOKE_SESSIONS:     true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_INVITE:              true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_GROUP_CREATE:        true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_GROUP_UPDATE:        true,
	v1.RightsFamily_RIGHTS_FAMILY_ENTRA_GROUP_MEMBERSHIP:    true,
}

// denyPatterns is the §6.6 deny list. A pattern is an exact value, or contains one '*' standing for
// any run of characters. Matching is case-insensitive (Graph permission names are).
var denyPatterns = []string{
	"Directory.ReadWrite.All",
	"RoleManagement.ReadWrite.Directory",
	"RoleAssignmentSchedule.ReadWrite.Directory",
	"RoleEligibilitySchedule.ReadWrite.Directory",
	"PrivilegedAccess.ReadWrite.*",
	// The PIM-for-groups schedule write permissions (Microsoft's documented names).
	"PrivilegedAssignmentSchedule.ReadWrite.*",
	"PrivilegedEligibilitySchedule.ReadWrite.*",
	"Application.ReadWrite.All",
	"Application.ReadWrite.OwnedBy",
	// Can grant itself RoleManagement.ReadWrite.Directory.
	"AppRoleAssignment.ReadWrite.All",
	"DelegatedPermissionGrant.ReadWrite.All",
	"EntitlementManagement.ReadWrite.All",
	"UserAuthenticationMethod.ReadWrite.All",
	"Policy.ReadWrite.*",
	// Can remove the MFA, approval and justification rules on PIM activation (T-0111).
	"RoleManagementPolicy.ReadWrite.*",
	"Domain.ReadWrite.All",
	"AdministrativeUnit.ReadWrite.All",
	// SOA transfer: the user, group and contact counterparts. The contact name is not verified, so
	// the pattern covers every object kind.
	"*-OnPremisesSyncBehavior.ReadWrite.All",
	"OnPremDirectorySynchronization.ReadWrite.All",
	"Synchronization.ReadWrite.All",
	// SSPR contact data and sign-in identities.
	"User-Phone.ReadWrite.All",
	"User-Mail.ReadWrite.All",
	"User.ManageIdentities.All",
}

// DenyListed reports whether the permission value is on the §6.6 deny list.
func DenyListed(value string) bool {
	v := strings.ToLower(value)
	for _, p := range denyPatterns {
		if globMatch(strings.ToLower(p), v) {
			return true
		}
	}
	return false
}

// DenyPatterns returns a copy of the deny list for documentation and tests.
func DenyPatterns() []string { return append([]string(nil), denyPatterns...) }

func globMatch(pattern, s string) bool {
	i := strings.IndexByte(pattern, '*')
	if i < 0 {
		return pattern == s
	}
	pre, suf := pattern[:i], pattern[i+1:]
	return len(s) >= len(pre)+len(suf) && strings.HasPrefix(s, pre) && strings.HasSuffix(s, suf)
}
