package graph

import (
	"context"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/odata"
	gs "github.com/skenzeriq/activediq/internal/directory/odata/graphschema"
)

// ---- models: only what the permission check and the Entra tier0 classifier need ----

type AppRole struct {
	ID                 string   `json:"id"`
	Value              string   `json:"value"`
	DisplayName        string   `json:"displayName"`
	AllowedMemberTypes []string `json:"allowedMemberTypes"`
}

type ServicePrincipal struct {
	ID          string    `json:"id"`
	AppID       string    `json:"appId"`
	DisplayName string    `json:"displayName"`
	AppRoles    []AppRole `json:"appRoles,omitempty"`
	// Credentials are read by OwnServicePrincipal only; a service principal can carry its own.
	KeyCredentials      []KeyCredential      `json:"keyCredentials,omitempty"`
	PasswordCredentials []PasswordCredential `json:"passwordCredentials,omitempty"`
}

// AppRoleAssignment is an application permission granted to a service principal on a resource
// (for example Microsoft Graph). Resolve AppRoleID to a permission name with ServicePrincipalByID(resource).
type AppRoleAssignment struct {
	ID                  string `json:"id"`
	AppRoleID           string `json:"appRoleId"`
	PrincipalID         string `json:"principalId"`
	ResourceID          string `json:"resourceId"`
	ResourceDisplayName string `json:"resourceDisplayName"`
	PrincipalType       string `json:"principalType,omitempty"` // "User", "Group", "ServicePrincipal"
}

type KeyCredential struct {
	KeyID string `json:"keyId"`
	// CustomKeyIdentifier is the certificate thumbprint (SHA-1) for certificates; Graph sends base64.
	CustomKeyIdentifier []byte `json:"customKeyIdentifier,omitempty"`
	// Key is the public certificate (DER). It is public material; customKeyIdentifier is a label the
	// caller chooses and must never decide whether a key is ours.
	Key           []byte    `json:"key,omitempty"`
	DisplayName   string    `json:"displayName"`
	Type          string    `json:"type"`
	Usage         string    `json:"usage"`
	StartDateTime time.Time `json:"startDateTime"`
	EndDateTime   time.Time `json:"endDateTime"`
}

// PasswordCredential is a client secret's metadata. secretText and hint are secret material and are
// deliberately not fields: the decoder drops them, so they cannot reach a log or a finding.
type PasswordCredential struct {
	KeyID         string    `json:"keyId"`
	StartDateTime time.Time `json:"startDateTime"`
	EndDateTime   time.Time `json:"endDateTime"`
}

type Application struct {
	ID                  string               `json:"id"`
	AppID               string               `json:"appId"`
	DisplayName         string               `json:"displayName"`
	KeyCredentials      []KeyCredential      `json:"keyCredentials"`
	PasswordCredentials []PasswordCredential `json:"passwordCredentials,omitempty"`
}

// DirectoryObject is an owner or member. Type is the Graph type without namespace ("user", "group",
// "servicePrincipal", …).
type DirectoryObject struct {
	ID                string `json:"id"`
	ODataType         string `json:"@odata.type"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
}

func (d DirectoryObject) Type() string {
	return strings.TrimPrefix(d.ODataType, "#microsoft.graph.")
}

type RoleDefinition struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	TemplateID  string `json:"templateId"`
}

// RoleAssignment is a directory role held by a principal, active or PIM-eligible, at any scope.
type RoleAssignment struct {
	ID               string
	PrincipalID      string
	RoleDefinitionID string
	DirectoryScopeID string
	Role             RoleDefinition
	Eligible         bool
	PrincipalType    string // Graph type without namespace ("user", "group", "servicePrincipal"); "" when Graph did not say
}

type rawRoleAssignment struct {
	ID               string          `json:"id"`
	PrincipalID      string          `json:"principalId"`
	RoleDefinitionID string          `json:"roleDefinitionId"`
	DirectoryScopeID string          `json:"directoryScopeId"`
	RoleDefinition   RoleDefinition  `json:"roleDefinition"`
	Principal        DirectoryObject `json:"principal"`
}

type Group struct {
	ID                 string `json:"id"`
	DisplayName        string `json:"displayName"`
	IsAssignableToRole bool   `json:"isAssignableToRole"`
	// GroupTypes and MembershipRule are read by GroupByID only. A dynamic group carries
	// "DynamicMembership" and a rule (TM-D25 rule 7).
	GroupTypes     []string `json:"groupTypes,omitempty"`
	MembershipRule string   `json:"membershipRule,omitempty"`
}

// q is a query selecting only sel; paged also asks for one page of the configured size.
func (c *Client) q(sel ...odata.AnyProp) odata.Query {
	q := odata.Query{}
	if len(sel) > 0 {
		q = q.Select(sel...)
	}
	return q
}

func (c *Client) paged(sel ...odata.AnyProp) odata.Query { return c.q(sel...).Top(c.cfg.PageSize) }

// Selections: only what the permission check and the tier0 classifier read.
var (
	selSP     = []odata.AnyProp{gs.ID, gs.ServicePrincipalAppID, gs.DisplayName, gs.AppRoles, gs.KeyCredentials, gs.PasswordCredentials}
	selOwnApp = []odata.AnyProp{gs.ID, gs.ApplicationAppID, gs.DisplayName, gs.KeyCredentials, gs.PasswordCredentials}
	selApp    = []odata.AnyProp{gs.ID, gs.ApplicationAppID, gs.DisplayName}
	selObject = []odata.AnyProp{gs.ID, gs.DisplayName, gs.UserPrincipalName}
)

// ---- own app registration ----

// OwnServicePrincipal reads the service principal of this client's app registration, with appRoles.
func (c *Client) OwnServicePrincipal(ctx context.Context) (ServicePrincipal, error) {
	return c.servicePrincipalByAppID(ctx, c.clientID)
}

// ServicePrincipalByID reads one service principal with its appRoles, to resolve AppRoleAssignment ids.
func (c *Client) ServicePrincipalByID(ctx context.Context, id guid.GUID) (ServicePrincipal, error) {
	var sp ServicePrincipal
	err := c.read(ctx, odata.Get(odata.Seg(gs.SetServicePrincipals), odata.Key(odata.GUIDOf(id))).With(c.q(selSP...)), &sp)
	return sp, err
}

// OwnApplication reads this client's application object with its key credentials.
func (c *Client) OwnApplication(ctx context.Context) (Application, error) {
	var app Application
	seg, err := odata.AltKey(gs.SetApplications, gs.ApplicationAppID, odata.GUIDTextOf(c.clientID))
	if err != nil {
		return app, invalidArg(err)
	}
	err = c.read(ctx, odata.Get(seg).With(c.q(selOwnApp...)), &app)
	if err == nil && app.KeyCredentials == nil {
		app.KeyCredentials = []KeyCredential{}
	}
	return app, err
}

// AppRoleAssignments lists the application permissions granted to the service principal spID.
func (c *Client) AppRoleAssignments(ctx context.Context, spID guid.GUID) ([]AppRoleAssignment, error) {
	return list[AppRoleAssignment](ctx, c, odata.Get(odata.Seg(gs.SetServicePrincipals), odata.Key(odata.GUIDOf(spID)),
		odata.Seg(gs.SegAppRoleAssignment)).With(c.paged()))
}

// ApplicationOwners lists the owners of the application object objectID.
func (c *Client) ApplicationOwners(ctx context.Context, objectID guid.GUID) ([]DirectoryObject, error) {
	return c.owners(ctx, gs.SetApplications, objectID)
}

// ServicePrincipalOwners lists the owners of the service principal objectID.
func (c *Client) ServicePrincipalOwners(ctx context.Context, objectID guid.GUID) ([]DirectoryObject, error) {
	return c.owners(ctx, gs.SetServicePrincipals, objectID)
}

// GroupOwners lists the owners of a group.
func (c *Client) GroupOwners(ctx context.Context, groupID guid.GUID) ([]DirectoryObject, error) {
	return c.owners(ctx, gs.SetGroups, groupID)
}

// GroupMembers lists direct members of a group (all pages).
func (c *Client) GroupMembers(ctx context.Context, groupID guid.GUID) ([]DirectoryObject, error) {
	return list[DirectoryObject](ctx, c, odata.Get(odata.Seg(gs.SetGroups), odata.Key(odata.GUIDOf(groupID)),
		odata.Seg(gs.SegMembers)).With(c.paged(selObject...)))
}

func (c *Client) owners(ctx context.Context, coll odata.Name, id guid.GUID) ([]DirectoryObject, error) {
	return list[DirectoryObject](ctx, c, odata.Get(odata.Seg(coll), odata.Key(odata.GUIDOf(id)),
		odata.Seg(gs.SegOwners)).With(c.paged(selObject...)))
}

// ---- directory roles and groups ----

// DirectoryRoleAssignments returns active and PIM-eligible directory role assignments at any scope
// for one principal (needs RoleManagement.Read.Directory). The zero principalID is refused with
// CodeInvalidArgument and no request is sent: unfiltered it would answer for every holder in the
// tenant, which a caller that ignored a guid.Parse error must never receive by accident. Use
// AllDirectoryRoleAssignments for the tenant-wide read.
func (c *Client) DirectoryRoleAssignments(ctx context.Context, principalID guid.GUID) ([]RoleAssignment, error) {
	if principalID == (guid.GUID{}) {
		return nil, newErr(CodeInvalidArgument, 0, "principal id must not be the zero GUID", nil)
	}
	return c.roleAssignments(ctx, odata.Query{}.Filter(odata.Eq(gs.RoleAssignmentPrincipalID, odata.GUIDTextOf(principalID))))
}

// AllDirectoryRoleAssignments lists every holder in the tenant, active and PIM-eligible.
func (c *Client) AllDirectoryRoleAssignments(ctx context.Context) ([]RoleAssignment, error) {
	return c.roleAssignments(ctx, odata.Query{})
}

// roleAssignments reads both lists. Eligibility reads are `[UNVERIFIED — lab G6]`: a failure on
// either list fails the whole call.
func (c *Client) roleAssignments(ctx context.Context, q odata.Query) ([]RoleAssignment, error) {
	q = q.Expand(gs.NavRoleDefinition, gs.ID, gs.DisplayName, gs.TemplateID).Expand(gs.NavPrincipal, gs.ID)
	var out []RoleAssignment
	for _, k := range []struct {
		seg      odata.Name
		eligible bool
	}{{gs.SegRoleAssignments, false}, {gs.SegRoleEligibility, true}} {
		raw, err := list[rawRoleAssignment](ctx, c, odata.Get(odata.Seg(gs.SetRoleManagement), odata.Seg(gs.SegDirectory), odata.Seg(k.seg)).With(q))
		if err != nil {
			return nil, err
		}
		for _, r := range raw {
			out = append(out, RoleAssignment{ID: r.ID, PrincipalID: r.PrincipalID, RoleDefinitionID: r.RoleDefinitionID,
				DirectoryScopeID: r.DirectoryScopeID, Role: r.RoleDefinition, Eligible: k.eligible, PrincipalType: r.Principal.Type()})
		}
	}
	return out, nil
}

// OwnDirectoryRoles is DirectoryRoleAssignments for this app's own service principal. The app is
// meant to hold none; any result is a finding for the permission check.
func (c *Client) OwnDirectoryRoles(ctx context.Context) ([]RoleAssignment, error) {
	sp, err := c.OwnServicePrincipal(ctx)
	if err != nil {
		return nil, err
	}
	id, err := guid.Parse(sp.ID)
	if err != nil {
		return nil, newErr(CodeProviderFailure, 0, "Graph returned a service principal id that is not a GUID", nil)
	}
	return c.DirectoryRoleAssignments(ctx, id)
}

// ServicePrincipalGroups lists the groups the service principal is a direct member of. Roles
// assigned to a role-assignable group pass to its members, so the permission check reads them too.
func (c *Client) ServicePrincipalGroups(ctx context.Context, spID guid.GUID) ([]Group, error) {
	return list[Group](ctx, c, odata.Get(odata.Seg(gs.SetServicePrincipals), odata.Key(odata.GUIDOf(spID)),
		odata.Seg(gs.SegMemberOf), odata.Cast(gs.CastGroup)).With(c.paged(gs.ID, gs.DisplayName, gs.GroupIsAssignableToRole)))
}

// RoleAssignableGroups lists groups with isAssignableToRole = true.
func (c *Client) RoleAssignableGroups(ctx context.Context) ([]Group, error) {
	q := c.paged(gs.ID, gs.DisplayName, gs.GroupIsAssignableToRole).
		Filter(odata.Eq(gs.GroupIsAssignableToRole, odata.BoolOf(true))).Count()
	return list[Group](ctx, c, odata.Get(odata.Seg(gs.SetGroups)).With(q))
}

// ServicePrincipalByAppID reads the service principal of the application appID, with appRoles.
func (c *Client) ServicePrincipalByAppID(ctx context.Context, appID guid.GUID) (ServicePrincipal, error) {
	return c.servicePrincipalByAppID(ctx, appID)
}

func (c *Client) servicePrincipalByAppID(ctx context.Context, appID guid.GUID) (ServicePrincipal, error) {
	var sp ServicePrincipal
	seg, err := odata.AltKey(gs.SetServicePrincipals, gs.ServicePrincipalAppID, odata.GUIDTextOf(appID))
	if err != nil {
		return sp, invalidArg(err)
	}
	err = c.read(ctx, odata.Get(seg).With(c.q(selSP...)), &sp)
	return sp, err
}

// ApplicationByAppID reads an application object by its appId. A service principal for an app
// registered in another tenant has none: the error then has CodeNotFound.
func (c *Client) ApplicationByAppID(ctx context.Context, appID guid.GUID) (Application, error) {
	var app Application
	seg, err := odata.AltKey(gs.SetApplications, gs.ApplicationAppID, odata.GUIDTextOf(appID))
	if err != nil {
		return app, invalidArg(err)
	}
	err = c.read(ctx, odata.Get(seg).With(c.q(selApp...)), &app)
	return app, err
}

// AppRoleAssignedTo lists every principal granted an application permission on the resource service
// principal resourceID (for example Microsoft Graph).
func (c *Client) AppRoleAssignedTo(ctx context.Context, resourceID guid.GUID) ([]AppRoleAssignment, error) {
	return list[AppRoleAssignment](ctx, c, odata.Get(odata.Seg(gs.SetServicePrincipals), odata.Key(odata.GUIDOf(resourceID)),
		odata.Seg(gs.SegAppRoleAssignedTo)).With(c.paged()))
}
