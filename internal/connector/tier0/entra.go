// Package tier0 computes the connector's own tier0 set (threat-model §6.4, TM-D2 check 2). This
// file is the Entra half, E1-E5 plus customer designations, over the read-only Graph client.
//
// Fail closed: any read error, unreadable PIM eligibility ([UNVERIFIED — lab G6]), an unknown
// principal type, or a missing correlation statement makes the answer "tier0, unknown" and returns
// the error. Nothing here can make an object less protected than the computed set.
package tier0

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Reader is the part of *graph.Client the classifier reads through.
type Reader interface {
	DirectoryRoleAssignments(ctx context.Context, principalID guid.GUID) ([]graph.RoleAssignment, error)
	RoleAssignableGroups(ctx context.Context) ([]graph.Group, error)
	GroupMembers(ctx context.Context, groupID guid.GUID) ([]graph.DirectoryObject, error)
	GroupOwners(ctx context.Context, groupID guid.GUID) ([]graph.DirectoryObject, error)
	ServicePrincipalByAppID(ctx context.Context, appID guid.GUID) (graph.ServicePrincipal, error)
	ServicePrincipalByID(ctx context.Context, id guid.GUID) (graph.ServicePrincipal, error)
	AppRoleAssignedTo(ctx context.Context, resourceID guid.GUID) ([]graph.AppRoleAssignment, error)
	ApplicationByAppID(ctx context.Context, appID guid.GUID) (graph.Application, error)
	ApplicationOwners(ctx context.Context, objectID guid.GUID) ([]graph.DirectoryObject, error)
	ServicePrincipalOwners(ctx context.Context, objectID guid.GUID) ([]graph.DirectoryObject, error)
}

var _ Reader = (*graph.Client)(nil)

// Basis is a row of threat-model §6.4 (the wire enum of tier0.proto).
type Basis = connectorv1.Tier0Basis

const (
	E1 = connectorv1.Tier0Basis_TIER0_BASIS_E1_DIRECTORY_ROLE_HOLDER
	E2 = connectorv1.Tier0Basis_TIER0_BASIS_E2_ROLE_ASSIGNABLE_GROUP
	E3 = connectorv1.Tier0Basis_TIER0_BASIS_E3_PRIVILEGED_APP_OWNER
	E4 = connectorv1.Tier0Basis_TIER0_BASIS_E4_HYBRID_CONTROL
	E5 = connectorv1.Tier0Basis_TIER0_BASIS_E5_CORRELATED_TO_AD_TIER0
	// Designated is a customer-designated object (break-glass, CA-excluded groups).
	Designated = connectorv1.Tier0Basis_TIER0_BASIS_CUSTOMER_DESIGNATED
)

// graphAppID is Microsoft Graph's well-known application id, the resource of every §6.6 permission.
// https://learn.microsoft.com/en-us/graph/permissions-reference
const graphAppID = "00000003-0000-0000-c000-000000000000"

// hybridRoleTemplates are the E4 directory roles by role template id (the id of a built-in role
// definition equals its template id). [UNVERIFIED — ids from the Entra built-in roles reference,
// https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference ;
// confirm in lab G6]. Display names are matched too, so a drifted id still hits.
var hybridRoleTemplates = map[string]bool{
	"8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": true, // Hybrid Identity Administrator
	"d29b2b05-8046-44ba-8758-1e26182fcf32": true, // Directory Synchronization Accounts
}

var hybridRoleNames = map[string]bool{
	"hybrid identity administrator":      true,
	"hybrid administrator":               true,
	"directory synchronization accounts": true,
}

// denyExact and denyPrefix are the §6.6 deny list. An app holding one of these makes its owners E3.
var denyExact = map[string]bool{
	"Directory.ReadWrite.All": true, "RoleManagement.ReadWrite.Directory": true,
	"RoleAssignmentSchedule.ReadWrite.Directory": true, "RoleEligibilitySchedule.ReadWrite.Directory": true,
	"Application.ReadWrite.All": true, "Application.ReadWrite.OwnedBy": true,
	"AppRoleAssignment.ReadWrite.All": true, "DelegatedPermissionGrant.ReadWrite.All": true,
	"EntitlementManagement.ReadWrite.All": true, "UserAuthenticationMethod.ReadWrite.All": true,
	"Domain.ReadWrite.All": true, "AdministrativeUnit.ReadWrite.All": true,
	"OnPremDirectorySynchronization.ReadWrite.All": true, "Synchronization.ReadWrite.All": true,
	"User-Phone.ReadWrite.All": true, "User-Mail.ReadWrite.All": true, "User.ManageIdentities.All": true,
}

var denyPrefix = []string{"PrivilegedAccess.ReadWrite.", "Policy.ReadWrite.", "PrivilegedEligibilitySchedule.ReadWrite.",
	"PrivilegedAssignmentSchedule.ReadWrite."}

func denied(perm string) bool {
	if denyExact[perm] {
		return true
	}
	for _, p := range denyPrefix {
		if strings.HasPrefix(perm, p) {
			return true
		}
	}
	// User-, Group- and OrgContact-OnPremisesSyncBehavior.ReadWrite.All (SOA transfer)
	return strings.Contains(perm, "-OnPremisesSyncBehavior.ReadWrite.")
}

// Set is one computed snapshot of the tenant's E1-E4 members, by lower-case object id.
type Set struct {
	bases map[string]map[Basis]bool
}

func (s *Set) add(id string, b Basis) {
	id = strings.ToLower(id)
	if s.bases[id] == nil {
		s.bases[id] = map[Basis]bool{}
	}
	s.bases[id][b] = true
}

// Len is the number of tier0 objects in the snapshot.
func (s *Set) Len() int { return len(s.bases) }

// Bases returns the sorted bases of id (empty when not in E1-E4).
func (s *Set) Bases(id string) []Basis { return sortedBases(s.bases[strings.ToLower(id)]) }

func sortedBases(m map[Basis]bool) []Basis {
	out := make([]Basis, 0, len(m))
	for b := range m {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Classifier computes the Entra tier0 set.
type Classifier struct {
	r Reader
	// SyncClientAppIDs are additional sync-client application ids (E4 "the sync clients' service
	// principals"), for example a Cloud Sync agent's app. Microsoft publishes no stable list the
	// connector can rely on [UNVERIFIED], so the onboarding check supplies what it finds.
	syncClientAppIDs []string
}

// New returns a Classifier over r. syncClientAppIDs may be nil.
func New(r Reader, syncClientAppIDs ...string) *Classifier {
	return &Classifier{r: r, syncClientAppIDs: syncClientAppIDs}
}

// Snapshot reads the tenant and computes E1-E4. Any read error fails the whole snapshot.
func (c *Classifier) Snapshot(ctx context.Context) (*Set, error) {
	s := &Set{bases: map[string]map[Basis]bool{}}

	// E1 (+E4 labelling): every active and PIM-eligible holder at any scope. The reader fails the
	// whole call when eligibility is unreadable, so partial answers never get here.
	roles, err := c.r.DirectoryRoleAssignments(ctx, guid.GUID{})
	if err != nil {
		return nil, fmt.Errorf("tier0: directory role assignments: %w", err)
	}
	holdingSP := map[string]bool{}
	for _, ra := range roles {
		if ra.PrincipalID == "" {
			return nil, errors.New("tier0: role assignment without a principal")
		}
		s.add(ra.PrincipalID, E1)
		if hybridRoleTemplates[strings.ToLower(ra.RoleDefinitionID)] || hybridRoleTemplates[strings.ToLower(ra.Role.TemplateID)] ||
			hybridRoleNames[strings.ToLower(ra.Role.DisplayName)] {
			s.add(ra.PrincipalID, E4)
		}
		switch ra.PrincipalType {
		case "user", "group":
		case "servicePrincipal":
			holdingSP[strings.ToLower(ra.PrincipalID)] = true
		default: // unknown kind of principal: cannot rule out an app, so refuse
			return nil, fmt.Errorf("tier0: role assignment principal has unknown type %q", ra.PrincipalType)
		}
	}

	// E2: role-assignable groups, their members and owners.
	groups, err := c.r.RoleAssignableGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("tier0: role-assignable groups: %w", err)
	}
	for _, g := range groups {
		s.add(g.ID, E2)
		gid, err := objectID(g.ID)
		if err != nil {
			return nil, fmt.Errorf("tier0: role-assignable group: %w", err)
		}
		mem, err := c.r.GroupMembers(ctx, gid)
		if err != nil {
			return nil, fmt.Errorf("tier0: members of role-assignable group: %w", err)
		}
		own, err := c.r.GroupOwners(ctx, gid)
		if err != nil {
			return nil, fmt.Errorf("tier0: owners of role-assignable group: %w", err)
		}
		for _, o := range append(mem, own...) {
			// A member or owner of a role-assignable group holds (or controls) its roles. A service
			// principal there is a privileged SP: its owners are E3.
			switch o.Type() {
			case "user":
			case "servicePrincipal":
				holdingSP[strings.ToLower(o.ID)] = true
			default: // empty or unknown kind: cannot rule out an app, so refuse
				return nil, fmt.Errorf("tier0: role-assignable group has a member or owner of unknown type %q", o.Type())
			}
			s.add(o.ID, E2)
		}
	}

	// E3: owners of apps and SPs that hold a directory role or a deny-listed Graph permission.
	graphApp, err := objectID(graphAppID)
	if err != nil {
		return nil, fmt.Errorf("tier0: Microsoft Graph app id: %w", err)
	}
	gsp, err := c.r.ServicePrincipalByAppID(ctx, graphApp)
	if err != nil {
		return nil, fmt.Errorf("tier0: Microsoft Graph service principal: %w", err)
	}
	roleName := map[string]string{}
	for _, ar := range gsp.AppRoles {
		roleName[strings.ToLower(ar.ID)] = ar.Value
	}
	gspID, err := objectID(gsp.ID)
	if err != nil {
		return nil, fmt.Errorf("tier0: Microsoft Graph service principal: %w", err)
	}
	granted, err := c.r.AppRoleAssignedTo(ctx, gspID)
	if err != nil {
		return nil, fmt.Errorf("tier0: grants on Microsoft Graph: %w", err)
	}
	for _, a := range granted {
		switch a.PrincipalType {
		case "ServicePrincipal":
		case "User", "Group":
			continue
		default: // unreported or unknown principal type: cannot rule out an app, so refuse
			return nil, fmt.Errorf("tier0: grant on Microsoft Graph has principal of unknown type %q", a.PrincipalType)
		}
		name, known := roleName[strings.ToLower(a.AppRoleID)]
		// An unresolvable permission id cannot be shown harmless: treat as deny-listed.
		if known && !denied(name) {
			continue
		}
		holdingSP[strings.ToLower(a.PrincipalID)] = true
	}
	// Sync clients: E4 on the SP itself and E3-style owner reach.
	syncSP := map[string]bool{}
	for _, appID := range c.syncClientAppIDs {
		aid, err := objectID(appID)
		if err != nil {
			return nil, fmt.Errorf("tier0: sync client app id: %w", err)
		}
		sp, err := c.r.ServicePrincipalByAppID(ctx, aid)
		if err != nil {
			return nil, fmt.Errorf("tier0: sync client service principal: %w", err)
		}
		s.add(sp.ID, E4)
		syncSP[strings.ToLower(sp.ID)] = true
	}
	for id := range holdingSP {
		syncSP[id] = true
	}
	return s, c.addOwnerClosure(ctx, s, syncSP)
}

// addOwnerClosure marks the owners of every privileged SP E3 and walks to a fixpoint: an owner that
// is itself a service principal can add a key to it and act as it, so it is privileged too and its
// own owners are E3 (§6.4 is transitive). The visited set also ends ownership cycles.
func (c *Classifier) addOwnerClosure(ctx context.Context, s *Set, start map[string]bool) error {
	visited := map[string]bool{}
	queue := make([]string, 0, len(start))
	for id := range start {
		queue = append(queue, id)
	}
	sort.Strings(queue)
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if visited[id] {
			continue
		}
		visited[id] = true
		owners, err := c.ownersOf(ctx, id)
		if err != nil {
			return err
		}
		for _, o := range owners {
			switch o.Type() {
			case "user":
			case "servicePrincipal":
				if oid := strings.ToLower(o.ID); !visited[oid] {
					queue = append(queue, oid)
				}
			default: // empty or unknown kind: cannot rule out an app, so refuse
				return fmt.Errorf("tier0: privileged service principal has an owner of unknown type %q", o.Type())
			}
			s.add(o.ID, E3)
		}
	}
	return nil
}

func (c *Classifier) ownersOf(ctx context.Context, spID string) ([]graph.DirectoryObject, error) {
	id, err := objectID(spID)
	if err != nil {
		return nil, fmt.Errorf("tier0: privileged service principal: %w", err)
	}
	sp, err := c.r.ServicePrincipalByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("tier0: privileged service principal: %w", err)
	}
	spObj, err := objectID(sp.ID)
	if err != nil {
		return nil, fmt.Errorf("tier0: privileged service principal: %w", err)
	}
	owners, err := c.r.ServicePrincipalOwners(ctx, spObj)
	if err != nil {
		return nil, fmt.Errorf("tier0: owners of privileged service principal: %w", err)
	}
	if sp.AppID != "" {
		// An app registered in another tenant has no application object here: not-found is fine.
		appID, err := objectID(sp.AppID)
		if err != nil {
			return nil, fmt.Errorf("tier0: privileged application: %w", err)
		}
		if app, err := c.r.ApplicationByAppID(ctx, appID); err == nil {
			appObj, err := objectID(app.ID)
			if err != nil {
				return nil, fmt.Errorf("tier0: privileged application: %w", err)
			}
			ao, err := c.r.ApplicationOwners(ctx, appObj)
			if err != nil {
				return nil, fmt.Errorf("tier0: owners of privileged application: %w", err)
			}
			owners = append(owners, ao...)
		} else if graph.CodeOf(err) != graph.CodeNotFound {
			return nil, fmt.Errorf("tier0: privileged application: %w", err)
		}
	}
	return owners, nil
}

// State is a DM-20 correlation state. Every state counts for protection (TM §6.4).
type State int

const (
	StateUnspecified State = iota
	StateCandidate
	StateMatched
	StateBroken
)

// Peer is one correlation of the target with an AD object.
type Peer struct {
	ADObject string // objectGUID of the AD peer
	State    State
}

// Input is the caller-supplied part of the answer: what only the server can know.
type Input struct {
	// CorrelationKnown must be true: it says the caller supplied Peers for this target (an empty list
	// means none). False is "absence" and never means "no correlation" (contract §8.3 F1).
	CorrelationKnown bool
	Peers            []Peer
	// ADTier0 is the set of AD tier0 object GUIDs the caller computed.
	ADTier0 map[string]bool
	// Designated are customer-designated Entra object ids (break-glass accounts, groups that
	// Conditional Access excludes).
	Designated []string
}

// Result is the classification of one target.
type Result struct {
	Tier0 bool
	// Unknown: the answer could not be computed, so Tier0 is true by fail-closed rule.
	Unknown bool
	Bases   []Basis
}

// Classify answers whether target (an Entra object id) is tier0, reading a fresh snapshot. On any
// error the result is {Tier0, Unknown} and the error is returned.
func (c *Classifier) Classify(ctx context.Context, target string, in Input) (Result, error) {
	set, err := c.Snapshot(ctx)
	if err != nil {
		return Result{Tier0: true, Unknown: true}, err
	}
	return set.Classify(target, in)
}

// Classify applies a snapshot, the caller's correlation facts and designations to target.
func (s *Set) Classify(target string, in Input) (Result, error) {
	if !in.CorrelationKnown {
		return Result{Tier0: true, Unknown: true}, errors.New("tier0: correlation statement not supplied")
	}
	t := strings.ToLower(target)
	if t == "" {
		return Result{Tier0: true, Unknown: true}, errors.New("tier0: empty target id")
	}
	b := map[Basis]bool{}
	for x := range s.bases[t] {
		b[x] = true
	}
	ad := make(map[string]bool, len(in.ADTier0))
	for k, v := range in.ADTier0 {
		if v { // a false entry in another case must not override a true one
			ad[strings.ToLower(k)] = true
		}
	}
	for _, p := range in.Peers {
		// Any state, including unspecified (inconsistent => tier0, F5), counts when the peer is tier0.
		if ad[strings.ToLower(p.ADObject)] {
			b[E5] = true
		}
	}
	for _, d := range in.Designated {
		if strings.EqualFold(d, t) {
			b[Designated] = true
		}
	}
	return Result{Tier0: len(b) > 0, Bases: sortedBases(b)}, nil
}

// objectID parses an id Graph (or configuration) gave us once, at the boundary (R1). Anything that
// is not a GUID is refused, so the snapshot fails closed.
func objectID(s string) (guid.GUID, error) {
	g, err := guid.Parse(s)
	if err != nil {
		return guid.GUID{}, errors.New("id is not a GUID")
	}
	return g, nil
}
