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
	"time"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Reader is the part of *graph.Client the classifier reads through.
type Reader interface {
	AllDirectoryRoleAssignments(ctx context.Context) ([]graph.RoleAssignment, error)
	RoleAssignableGroups(ctx context.Context) ([]graph.Group, error)
	GroupMembers(ctx context.Context, groupID guid.GUID) ([]graph.DirectoryObject, error)
	GroupOwners(ctx context.Context, groupID guid.GUID) ([]graph.DirectoryObject, error)
	ServicePrincipalByAppID(ctx context.Context, appID guid.GUID) (graph.ServicePrincipal, error)
	ServicePrincipalByID(ctx context.Context, id guid.GUID) (graph.ServicePrincipal, error)
	AppRoleAssignedTo(ctx context.Context, resourceID guid.GUID) ([]graph.AppRoleAssignment, error)
	ApplicationByAppID(ctx context.Context, appID guid.GUID) (graph.Application, error)
	ApplicationOwners(ctx context.Context, objectID guid.GUID) ([]graph.DirectoryObject, error)
	ServicePrincipalOwners(ctx context.Context, objectID guid.GUID) ([]graph.DirectoryObject, error)
	// TM-D25 reads.
	GroupTransitiveMembers(ctx context.Context, groupID guid.GUID) ([]graph.DirectoryObject, error)
	GroupByID(ctx context.Context, groupID guid.GUID) (graph.Group, error)
	GroupSchedules(ctx context.Context, groupID guid.GUID) ([]graph.GroupSchedule, error)
	PrincipalSchedules(ctx context.Context, principalID guid.GUID) ([]graph.GroupSchedule, error)
	SubscribedSKUs(ctx context.Context) ([]graph.SubscribedSKU, error)
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

// RoleManagementPolicy.ReadWrite.* can remove the MFA, approval and justification rules on PIM
// activation (§6.6, T-0111).
var denyPrefix = []string{"PrivilegedAccess.ReadWrite.", "Policy.ReadWrite.", "PrivilegedEligibilitySchedule.ReadWrite.",
	"PrivilegedAssignmentSchedule.ReadWrite.", "RoleManagementPolicy.ReadWrite."}

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
	// reach is the groups of the TM-D25 closure with the bases they carry, for the per-write live
	// schedule check.
	reach map[string]map[Basis]bool
	// designatedGroups are the group ids the snapshot was computed for.
	designatedGroups map[string]bool
	dynamic          RuleScope
	computedAt       time.Time
	pimNotLicensed   bool
}

// ComputedAt is the time the snapshot judged schedule expiry against.
func (s *Set) ComputedAt() time.Time { return s.computedAt }

// PIMNotLicensed reports the TM-D25 rule 5 assumption: the PIM-for-Groups reads were answered as
// "not licensed", corroborated by subscribedSkus, and schedules were treated as empty. Connection
// health states it so the customer sees the assumption.
func (s *Set) PIMNotLicensed() bool { return s.pimNotLicensed }

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
	unlicensed       PIMUnlicensed
	now              func() time.Time
}

// PIMUnlicensed is the exact signal lab G11 recorded for a tenant without the PIM licence, and the
// service plans that carry PIM (TM-D25 rule 5). Until G11 has run both are unknown
// [UNVERIFIED — lab G11], the zero value matches nothing, and every schedule read failure fails
// the snapshot.
type PIMUnlicensed struct {
	HTTPStatus int
	GraphCode  string   // error.code of the response
	PlanIDs    []string // service plan ids carrying PIM; a tenant is unlicensed when none is enabled
}

func (u PIMUnlicensed) pinned() bool {
	return u.HTTPStatus != 0 && u.GraphCode != "" && len(u.PlanIDs) > 0
}

// New returns a Classifier over r. syncClientAppIDs may be nil.
func New(r Reader, syncClientAppIDs ...string) *Classifier {
	return &Classifier{r: r, syncClientAppIDs: syncClientAppIDs, now: time.Now}
}

// WithPIMUnlicensed sets the lab-G11-pinned unlicensed signal and returns c.
func (c *Classifier) WithPIMUnlicensed(u PIMUnlicensed) *Classifier { c.unlicensed = u; return c }

// WithClock sets the clock for schedule expiry and returns c (tests).
func (c *Classifier) WithClock(now func() time.Time) *Classifier { c.now = now; return c }

// Kind is the type of a designated object. Only the caller can say what a designation is; the
// classifier does not guess (an unknown kind fails closed).
type Kind int

const (
	KindUnknown Kind = iota
	KindUser
	KindDevice
	KindServicePrincipal
	KindGroup
)

// Designation is one customer-designated Entra object (break-glass account, a group that Conditional
// Access excludes). A designated group designates its reach (TM-D25 rule 6).
type Designation struct {
	ID   string
	Kind Kind
}

// Snapshot reads the tenant and computes E1-E4 and the TM-D25 reach closure. designated names the
// customer-designated groups whose reach is walked. Any read error fails the whole snapshot.
func (c *Classifier) Snapshot(ctx context.Context, designated ...Designation) (*Set, error) {
	s := &Set{bases: map[string]map[Basis]bool{}, reach: map[string]map[Basis]bool{}, designatedGroups: map[string]bool{},
		dynamic: RuleScope{Properties: map[string]bool{}}, computedAt: c.now().UTC()}

	// E1 (+E4 labelling): every active and PIM-eligible holder at any scope. The reader fails the
	// whole call when eligibility is unreadable, so partial answers never get here.
	roles, err := c.r.AllDirectoryRoleAssignments(ctx)
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

	// E2 and designated groups: the TM-D25 reach closure.
	groups, err := c.r.RoleAssignableGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("tier0: role-assignable groups: %w", err)
	}
	w := &walk{c: c, ctx: ctx, s: s, holdingSP: holdingSP, seen: map[string]bool{}}
	for _, g := range groups {
		if _, err := objectID(g.ID); err != nil {
			return nil, fmt.Errorf("tier0: role-assignable group: %w", err)
		}
		w.enqueue(g.ID, E2, true)
	}
	for _, d := range designated {
		switch d.Kind {
		case KindGroup:
			gid, err := objectID(d.ID)
			if err != nil {
				return nil, fmt.Errorf("tier0: designated group: %w", err)
			}
			s.designatedGroups[strings.ToLower(d.ID)] = true
			w.enqueue(d.ID, Designated, false)
			g, err := c.r.GroupByID(ctx, gid)
			if err != nil {
				return nil, fmt.Errorf("tier0: designated group: %w", err)
			}
			if g.MembershipRule != "" || hasDynamic(g.GroupTypes) {
				s.dynamic.merge(ScopeOfRule(g.MembershipRule))
			}
		case KindUser, KindDevice, KindServicePrincipal:
			if _, err := objectID(d.ID); err != nil {
				return nil, fmt.Errorf("tier0: designated object: %w", err)
			}
			s.add(d.ID, Designated)
			if d.Kind == KindServicePrincipal {
				holdingSP[strings.ToLower(d.ID)] = true
			}
		default:
			return nil, errors.New("tier0: designated object has an unknown kind")
		}
	}
	if err := w.run(); err != nil {
		return nil, err
	}
	s.pimNotLicensed = w.pimEmpty

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
	if err := c.addOwnerClosure(ctx, s, syncSP); err != nil {
		return nil, err // never hand back a partial set: a caller ignoring err would under-protect
	}
	return s, nil
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
	// Designated are the customer-designated Entra objects (break-glass accounts, groups that
	// Conditional Access excludes), each with its kind: a designated group designates its reach.
	Designated []Designation
}

// Result is the classification of one target.
type Result struct {
	Tier0 bool
	// Unknown: the answer could not be computed, so Tier0 is true by fail-closed rule.
	Unknown bool
	Bases   []Basis
}

// Classify answers whether target (an Entra object id) is tier0, reading a fresh snapshot and, for
// the target, a live read of its own PIM-for-Groups schedules (TM-D25 rule 3). On any error the
// result is {Tier0, Unknown} and the error is returned.
func (c *Classifier) Classify(ctx context.Context, target string, in Input) (Result, error) {
	refuse := Result{Tier0: true, Unknown: true}
	set, err := c.Snapshot(ctx, in.Designated...)
	if err != nil {
		return refuse, err
	}
	tid, err := objectID(target)
	if err != nil {
		return refuse, fmt.Errorf("tier0: target: %w", err)
	}
	extra := map[Basis]bool{}
	if !set.pimNotLicensed {
		// A direct schedule created since the snapshot is still refused, as for direct C9 links.
		raw, err := c.r.PrincipalSchedules(ctx, tid)
		if err != nil {
			return refuse, fmt.Errorf("tier0: PIM for Groups schedules of the target: %w", err)
		}
		live, err := counted(raw, "", set.computedAt)
		if err != nil {
			return refuse, err
		}
		for _, sc := range live {
			if !strings.EqualFold(sc.PrincipalID, target) {
				return refuse, errors.New("tier0: PIM for Groups schedule belongs to another principal than the target")
			}
			for b := range set.reach[strings.ToLower(sc.GroupID)] {
				extra[b] = true
			}
		}
	}
	return set.classify(target, in, extra)
}

// Classify applies a snapshot, the caller's correlation facts and designations to target.
func (s *Set) Classify(target string, in Input) (Result, error) { return s.classify(target, in, nil) }

func (s *Set) classify(target string, in Input, extra map[Basis]bool) (Result, error) {
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
	for x := range extra {
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
		switch d.Kind {
		case KindGroup:
			// The snapshot must have walked this group's reach, or its members are not in the set.
			if !s.designatedGroups[strings.ToLower(d.ID)] {
				return Result{Tier0: true, Unknown: true}, errors.New("tier0: designated group was not part of the snapshot")
			}
		case KindUser, KindDevice, KindServicePrincipal:
		default:
			return Result{Tier0: true, Unknown: true}, errors.New("tier0: designated object has an unknown kind")
		}
		if strings.EqualFold(d.ID, t) {
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

func hasDynamic(types []string) bool {
	for _, t := range types {
		if strings.EqualFold(t, "DynamicMembership") {
			return true
		}
	}
	return false
}
