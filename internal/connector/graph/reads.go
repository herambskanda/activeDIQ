package graph

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"
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
}

// AppRoleAssignment is an application permission granted to a service principal on a resource
// (for example Microsoft Graph). Resolve AppRoleID to a permission name with ServicePrincipalByID(resource).
type AppRoleAssignment struct {
	ID                  string `json:"id"`
	AppRoleID           string `json:"appRoleId"`
	PrincipalID         string `json:"principalId"`
	ResourceID          string `json:"resourceId"`
	ResourceDisplayName string `json:"resourceDisplayName"`
}

type KeyCredential struct {
	KeyID         string    `json:"keyId"`
	DisplayName   string    `json:"displayName"`
	Type          string    `json:"type"`
	Usage         string    `json:"usage"`
	StartDateTime time.Time `json:"startDateTime"`
	EndDateTime   time.Time `json:"endDateTime"`
}

type Application struct {
	ID             string          `json:"id"`
	AppID          string          `json:"appId"`
	DisplayName    string          `json:"displayName"`
	KeyCredentials []KeyCredential `json:"keyCredentials"`
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
}

type rawRoleAssignment struct {
	ID               string         `json:"id"`
	PrincipalID      string         `json:"principalId"`
	RoleDefinitionID string         `json:"roleDefinitionId"`
	DirectoryScopeID string         `json:"directoryScopeId"`
	RoleDefinition   RoleDefinition `json:"roleDefinition"`
}

type Group struct {
	ID                 string `json:"id"`
	DisplayName        string `json:"displayName"`
	IsAssignableToRole bool   `json:"isAssignableToRole"`
}

func (c *Client) q(sel string) url.Values {
	v := url.Values{}
	if sel != "" {
		v.Set("$select", sel)
	}
	return v
}

func (c *Client) paged(sel string) url.Values {
	v := c.q(sel)
	v.Set("$top", strconv.Itoa(c.cfg.PageSize))
	return v
}

func needGUID(id string) error {
	if !guidRE.MatchString(id) {
		return newErr(CodeInvalidArgument, 0, "object id is not a GUID", nil)
	}
	return nil
}

// ---- own app registration ----

// OwnServicePrincipal reads the service principal of this client's app registration, with appRoles.
func (c *Client) OwnServicePrincipal(ctx context.Context) (ServicePrincipal, error) {
	var sp ServicePrincipal
	err := c.get(ctx, c.endpoint(c.q("id,appId,displayName,appRoles"), "servicePrincipals(appId='"+c.cfg.ClientID+"')"), &sp)
	return sp, err
}

// ServicePrincipalByID reads one service principal with its appRoles, to resolve AppRoleAssignment ids.
func (c *Client) ServicePrincipalByID(ctx context.Context, id string) (ServicePrincipal, error) {
	var sp ServicePrincipal
	if err := needGUID(id); err != nil {
		return sp, err
	}
	err := c.get(ctx, c.endpoint(c.q("id,appId,displayName,appRoles"), "servicePrincipals", id), &sp)
	return sp, err
}

// OwnApplication reads this client's application object with its key credentials.
func (c *Client) OwnApplication(ctx context.Context) (Application, error) {
	var app Application
	err := c.get(ctx, c.endpoint(c.q("id,appId,displayName,keyCredentials"), "applications(appId='"+c.cfg.ClientID+"')"), &app)
	if err == nil && app.KeyCredentials == nil {
		app.KeyCredentials = []KeyCredential{}
	}
	return app, err
}

// AppRoleAssignments lists the application permissions granted to the service principal spID.
func (c *Client) AppRoleAssignments(ctx context.Context, spID string) ([]AppRoleAssignment, error) {
	if err := needGUID(spID); err != nil {
		return nil, err
	}
	return list[AppRoleAssignment](ctx, c, c.endpoint(c.paged(""), "servicePrincipals", spID, "appRoleAssignments"))
}

// ApplicationOwners lists the owners of the application object objectID.
func (c *Client) ApplicationOwners(ctx context.Context, objectID string) ([]DirectoryObject, error) {
	return c.owners(ctx, "applications", objectID)
}

// ServicePrincipalOwners lists the owners of the service principal objectID.
func (c *Client) ServicePrincipalOwners(ctx context.Context, objectID string) ([]DirectoryObject, error) {
	return c.owners(ctx, "servicePrincipals", objectID)
}

// GroupOwners lists the owners of a group.
func (c *Client) GroupOwners(ctx context.Context, groupID string) ([]DirectoryObject, error) {
	return c.owners(ctx, "groups", groupID)
}

// GroupMembers lists direct members of a group (all pages).
func (c *Client) GroupMembers(ctx context.Context, groupID string) ([]DirectoryObject, error) {
	if err := needGUID(groupID); err != nil {
		return nil, err
	}
	return list[DirectoryObject](ctx, c, c.endpoint(c.paged("id,displayName,userPrincipalName"), "groups", groupID, "members"))
}

func (c *Client) owners(ctx context.Context, coll, id string) ([]DirectoryObject, error) {
	if err := needGUID(id); err != nil {
		return nil, err
	}
	return list[DirectoryObject](ctx, c, c.endpoint(c.paged("id,displayName,userPrincipalName"), coll, id, "owners"))
}

// ---- directory roles and groups ----

// DirectoryRoleAssignments returns active and PIM-eligible directory role assignments at any scope
// (needs RoleManagement.Read.Directory). principalID "" lists every holder in the tenant.
// Eligibility reads are `[UNVERIFIED — lab G6]`: a failure on either list fails the whole call.
func (c *Client) DirectoryRoleAssignments(ctx context.Context, principalID string) ([]RoleAssignment, error) {
	q := url.Values{}
	if principalID != "" {
		if err := needGUID(principalID); err != nil {
			return nil, err
		}
		q.Set("$filter", "principalId eq '"+principalID+"'")
	}
	q.Set("$expand", "roleDefinition($select=id,displayName,templateId)")
	var out []RoleAssignment
	for _, k := range []struct {
		path     string
		eligible bool
	}{{"roleAssignments", false}, {"roleEligibilitySchedules", true}} {
		raw, err := list[rawRoleAssignment](ctx, c, c.endpoint(q, "roleManagement", "directory", k.path))
		if err != nil {
			return nil, err
		}
		for _, r := range raw {
			out = append(out, RoleAssignment{ID: r.ID, PrincipalID: r.PrincipalID, RoleDefinitionID: r.RoleDefinitionID,
				DirectoryScopeID: r.DirectoryScopeID, Role: r.RoleDefinition, Eligible: k.eligible})
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
	return c.DirectoryRoleAssignments(ctx, sp.ID)
}

// RoleAssignableGroups lists groups with isAssignableToRole = true.
func (c *Client) RoleAssignableGroups(ctx context.Context) ([]Group, error) {
	q := c.paged("id,displayName,isAssignableToRole")
	q.Set("$filter", "isAssignableToRole eq true")
	q.Set("$count", "true")
	return list[Group](ctx, c, c.endpoint(q, "groups"))
}
