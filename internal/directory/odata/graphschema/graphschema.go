// Package graphschema declares the Microsoft Graph properties the connector filters, selects and
// orders on, each with its Edm type. It is the only place outside package odata that may call the
// odata property constructors (FF-SP2 odataname). Types follow Graph $metadata; where the
// documentation is ambiguous the declaration says so and lab vector OD-L4 settles it.
package graphschema

import "github.com/skenzeriq/activediq/internal/directory/odata"

// Filterable properties.
var (
	// user.userPrincipalName, Edm.String.
	// https://learn.microsoft.com/graph/api/resources/user
	UserPrincipalName = odata.StringProp("userPrincipalName")

	// group.isAssignableToRole, Edm.Boolean.
	GroupIsAssignableToRole = odata.BoolProp("isAssignableToRole")

	// servicePrincipal.appId and application.appId: Edm.String carrying a GUID, addressed as the
	// alternate key servicePrincipals(appId='…'). https://learn.microsoft.com/graph/api/serviceprincipal-get
	ServicePrincipalAppID = odata.GUIDStringProp("appId")
	ApplicationAppID      = odata.GUIDStringProp("appId")

	// unifiedRoleAssignment.principalId, Edm.String. [UNVERIFIED — lab OD-L4]
	// https://learn.microsoft.com/graph/api/resources/unifiedroleassignment
	RoleAssignmentPrincipalID = odata.GUIDStringProp("principalId")

	// appRoleAssignment.principalId, Edm.Guid. [UNVERIFIED — lab OD-L4]
	// https://learn.microsoft.com/graph/api/resources/approleassignment
	AppRoleAssignmentPrincipalID = odata.GUIDProp("principalId")
)

// Selectable properties. Edm.String unless noted; the type only matters when a property becomes
// filterable.
var (
	ID                  = odata.GUIDStringProp("id")
	DisplayName         = odata.StringProp("displayName")         // Edm.String on user, group, application, servicePrincipal
	AppRoles            = odata.StringProp("appRoles")            // collection of appRole
	KeyCredentials      = odata.StringProp("keyCredentials")      // collection of keyCredential
	PasswordCredentials = odata.StringProp("passwordCredentials") // collection of passwordCredential
	TemplateID          = odata.StringProp("templateId")
	Mail                = odata.StringProp("mail")
)

// Navigation properties for $expand.
const (
	NavRoleDefinition odata.Name = "roleDefinition"
	NavPrincipal      odata.Name = "principal"
)

// Entity sets and segments.
const (
	SetServicePrincipals odata.Name = "servicePrincipals"
	SetApplications      odata.Name = "applications"
	SetGroups            odata.Name = "groups"
	SetUsers             odata.Name = "users"
	SetRoleManagement    odata.Name = "roleManagement"
	SegDirectory         odata.Name = "directory"
	SegRoleAssignments   odata.Name = "roleAssignments"
	SegRoleEligibility   odata.Name = "roleEligibilitySchedules"
	SegAppRoleAssignment odata.Name = "appRoleAssignments"
	SegAppRoleAssignedTo odata.Name = "appRoleAssignedTo"
	SegOwners            odata.Name = "owners"
	SegMembers           odata.Name = "members"
	SegMemberOf          odata.Name = "memberOf"
	CastGroup            odata.Name = "microsoft.graph.group"
)
