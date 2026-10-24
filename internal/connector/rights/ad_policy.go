package rights

import (
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The AD half of the §6.3 policy as data, in one place so a new right (RT-4) is one reviewed edit.
// Attribute and class GUIDs are never hard-coded: they are resolved from the forest's schema at run
// time. The extended-right and property-set GUIDs below are fixed by the AD schema (MS-ADTS 5.1.3.2.1)
// and are the same in every forest.

func mustAD(s string) adguid.GUID {
	g, err := adguid.Parse(s)
	if err != nil {
		panic(err)
	}
	return g
}

var (
	rightResetPassword      = mustAD("00299570-246d-11d0-a768-00aa006e0529")
	rightReanimate          = mustAD("45ec5156-db7e-47bb-b53f-dbeb2d03c40f")
	rightGetChanges         = mustAD("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	rightGetChangesAll      = mustAD("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
	rightValidatedSPN       = mustAD("f3a64788-5306-11d1-a9c5-0000f80367c1")
	rightValidatedDNSHot    = mustAD("72e39547-7b18-11d1-adef-00c04fd8d5cd")
	rightGetChangesFiltered = mustAD("89e95b76-444d-4c62-991a-0facbeda640c")
	rightSelfMembership     = mustAD("bf9679c0-0de6-11d0-a285-00aa003049e2")
	// propSetUserAcctRestrictions includes msDS-AllowedToActOnBehalfOfOtherIdentity (R3).
	propSetUserAcctRestrictions = mustAD("4c164200-20c0-11d0-a768-00aa006e0529")
)

// neverDelegateAttrs are the attributes whose write is never delegated (R3, R7): RBCD, shadow
// credentials, SPNs and DNS host names.
var neverDelegateAttrs = []string{
	"msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink", "servicePrincipalName", "dNSHostName",
}

// neverDelegateRights are the fixed GUIDs of the never-delegate validated writes and property set.
var neverDelegateRights = map[adguid.GUID]bool{
	rightValidatedSPN: true, rightValidatedDNSHot: true, propSetUserAcctRestrictions: true,
}

// dsaClass is the WS2025 delegated managed service account class (BadSuccessor, R7).
const dsaClass = "msDS-DelegatedManagedServiceAccount"

// expectation is one right an enabled family needs. Exactly one of attr, class, ext names the
// object type: an attribute (WP), a child class (CC) or a fixed extended-right GUID (CA).
type expectation struct {
	kind  v1.AdRightKind
	bit   uint32
	attr  string
	class string
	ext   *adguid.GUID
	// onDomain: the right is held on the managed domain NC head, not on the managed OUs.
	onDomain bool
}

var expectations = map[v1.RightsFamily][]expectation{
	v1.RightsFamily_RIGHTS_FAMILY_AD_R3_USER_LIFECYCLE: {
		{kind: v1.AdRightKind_AD_RIGHT_KIND_CREATE_CHILD, bit: dsCreateChild, class: "user"},
		{kind: v1.AdRightKind_AD_RIGHT_KIND_DELETE_CHILD, bit: dsDeleteChild, class: "user"},
	},
	v1.RightsFamily_RIGHTS_FAMILY_AD_R4_ACCOUNT_STATE: {
		{kind: v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, bit: dsWriteProp, attr: "userAccountControl"},
		{kind: v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, bit: dsWriteProp, attr: "accountExpires"},
		{kind: v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, bit: dsWriteProp, attr: "lockoutTime"},
		{kind: v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, bit: dsWriteProp, attr: "pwdLastSet"},
	},
	v1.RightsFamily_RIGHTS_FAMILY_AD_R5_PASSWORD_RESET: {
		{kind: v1.AdRightKind_AD_RIGHT_KIND_CONTROL_ACCESS, bit: dsControlAccess, ext: &rightResetPassword},
	},
	v1.RightsFamily_RIGHTS_FAMILY_AD_R6_GROUPS: {
		{kind: v1.AdRightKind_AD_RIGHT_KIND_CREATE_CHILD, bit: dsCreateChild, class: "group"},
		{kind: v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, bit: dsWriteProp, attr: "member"},
	},
	v1.RightsFamily_RIGHTS_FAMILY_AD_R7_COMPUTERS: {
		{kind: v1.AdRightKind_AD_RIGHT_KIND_CREATE_CHILD, bit: dsCreateChild, class: "computer"},
		{kind: v1.AdRightKind_AD_RIGHT_KIND_CONTROL_ACCESS, bit: dsControlAccess, ext: &rightResetPassword},
	},
	v1.RightsFamily_RIGHTS_FAMILY_AD_R8_CONTACTS_OUS_MOVE: {
		{kind: v1.AdRightKind_AD_RIGHT_KIND_CREATE_CHILD, bit: dsCreateChild, class: "contact"},
		{kind: v1.AdRightKind_AD_RIGHT_KIND_CREATE_CHILD, bit: dsCreateChild, class: "organizationalUnit"},
	},
	v1.RightsFamily_RIGHTS_FAMILY_AD_R9_RECYCLE_BIN_RESTORE: {
		{kind: v1.AdRightKind_AD_RIGHT_KIND_CONTROL_ACCESS, bit: dsControlAccess, ext: &rightReanimate, onDomain: true},
	},
	v1.RightsFamily_RIGHTS_FAMILY_AD_R12_HOME_FOLDERS: {
		{kind: v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, bit: dsWriteProp, attr: "homeDirectory"},
		{kind: v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, bit: dsWriteProp, attr: "homeDrive"},
		{kind: v1.AdRightKind_AD_RIGHT_KIND_WRITE_PROPERTY, bit: dsWriteProp, attr: "profilePath"},
	},
}

// Families R10 (LAPS read) and R11 (BitLocker read) have no expectation yet: their rights are
// confidential-attribute reads on child objects whose classes vary by LAPS flavour (TM §6.3 R10,
// `[OPEN → ADM-060 spec]`). Their absence is not reported as missing, and the follow-up ticket
// named in T-0096's advance note adds them.

// benignBroadExtended are the typed extended rights a broad principal holds by default and that
// are not an exposure on a tier0 object. Default-deny: anything not listed is reported.
// Confirm further domainDNS defaults on Samba / the Windows lab (T-0231) before adding to it.
var benignBroadExtended = map[adguid.GUID]bool{
	mustAD("ab721a53-1e2f-11d0-9819-00aa0040529b"): true, // User-Change-Password (Everyone default)
	// Seen as Everyone/Authenticated Users defaults on Samba 4 tier0 objects in the T-0237 lab run
	// (schema default SDDL, copied from Windows). Windows-lab confirmation is T-0231 [UNVERIFIED].
	mustAD("ab721a55-1e2f-11d0-9819-00aa0040529b"): true, // Send-To (messaging only, no directory change)
	mustAD("edacfd8f-ffb3-11d1-b41d-00a0c968f939"): true, // Apply-Group-Policy (needs GPO read+apply, no write)
	mustAD("05c74c5e-4deb-43b4-bd9f-86664c2a7fd5"): true, // Enable-Per-User-Reversibly-Encrypted-Password (domainDNS default)
	mustAD("ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"): true, // Update-Password-Not-Required-Bit (domainDNS default)
	mustAD("280f369c-67c7-438e-ae98-1d46f3c6f541"): true, // Unexpire-Password (domainDNS default)
}
