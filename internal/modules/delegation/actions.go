package delegation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

// The Actions, their permissions and the events the runner writes. All four permissions are in a
// control-plane family (authz.NeverCrosses): no group, token or automation policy ever exercises them.
const (
	RoleCreateID operation.ActionID = "delegation.role.create"
	RoleUpdateID operation.ActionID = "delegation.role.update"
	GrantID      operation.ActionID = "delegation.assignment.grant"
	RevokeID     operation.ActionID = "delegation.assignment.revoke"

	PermRoleCreate authz.Permission = "delegation.role.create"
	PermRoleUpdate authz.Permission = "delegation.role.update"
	PermGrant      authz.Permission = "delegation.assignment.grant"
	PermRevoke     authz.Permission = "delegation.assignment.revoke"

	AuditRoleCreated audit.Kind = "delegation.role.created"
	AuditRoleUpdated audit.Kind = "delegation.role.updated"
	AuditGranted     audit.Kind = "delegation.assignment.granted"
	AuditRevoked     audit.Kind = "delegation.assignment.revoked"

	// Target classes: the row in activeDIQ's own store, never a directory object.
	TargetClassRole       = rbac.TargetClassRole
	TargetClassAssignment = rbac.TargetClassAssignment
)

// Stable reasons for a refusal the caller can act on. None carries a stored value.
const (
	ReasonEscalation       = "no_escalation"
	ReasonControlPlane     = "control_plane_is_personal"
	ReasonBuiltInRole      = "built_in_role_read_only"
	ReasonOwnerRole        = "tenant_owner_has_its_own_path"
	ReasonDirectPersonOnly = "person_acting_directly_required"
	ReasonUnavailable      = "access_service_unavailable"
)

var errUnavailable = errors.New("delegation: the access service is not wired")

// RoleCreateInput creates a custom role. RoleID is chosen by the caller, so a retry is the same role.
type RoleCreateInput struct {
	RoleID      string   `json:"roleId"`
	Name        string   `json:"name"`
	Tier        int      `json:"tier"`
	Permissions []string `json:"permissions"`
}

// RoleUpdateInput replaces a custom role's permissions.
type RoleUpdateInput struct {
	RoleID      string   `json:"roleId"`
	Permissions []string `json:"permissions"`
}

// SubjectInput names the subject: exactly the fields of its kind.
type SubjectInput struct {
	Kind         string `json:"kind"` // account | group | automation
	AccountID    string `json:"accountId,omitempty"`
	ConnectionID string `json:"connectionId,omitempty"` // group
	GroupGUID    string `json:"groupGuid,omitempty"`    // group
	PolicyID     string `json:"policyId,omitempty"`     // automation
}

// RootInput is one scope root of an assignment (DM-35).
type RootInput struct {
	Kind         string `json:"kind"` // naming_context | ou_subtree | ou_one_level | entra_tenant | tier0_scope | tenant
	ConnectionID string `json:"connectionId"`
	GUID         string `json:"guid"`
	Exclude      bool   `json:"exclude,omitempty"`
}

// GrantInput creates one assignment. AssignmentID is chosen by the caller, so a retry is the same grant.
type GrantInput struct {
	AssignmentID string       `json:"assignmentId"`
	RoleID       string       `json:"roleId"`
	Subject      SubjectInput `json:"subject"`
	Roots        []RootInput  `json:"roots"`
	ValidFrom    *time.Time   `json:"validFrom,omitempty"`
	ValidUntil   *time.Time   `json:"validUntil,omitempty"`
}

// RevokeInput ends one assignment.
type RevokeInput struct {
	AssignmentID string `json:"assignmentId"`
}

// Outcome is what Apply did.
type Outcome struct {
	ID string `json:"id"`
}

// Actions builds the four Actions over the writer. A nil writer builds them anyway and every Plan and
// Apply refuses: the module never runs without the no-escalation proof.
func Actions(g *rbac.Grants) ([]operation.Action, error) {
	var out []operation.Action
	for _, build := range []func(*rbac.Grants) (operation.Action, error){roleCreate, roleUpdate, grant, revoke} {
		a, err := build(g)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// deny maps the writer's typed errors onto the pipeline's. The message is a stable reason, never a stored value.
func deny(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, rbac.ErrEscalation):
		return fmt.Errorf("%w: %s", operation.ErrDenied, ReasonEscalation)
	case errors.Is(err, rbac.ErrControlPlanePersonal):
		return fmt.Errorf("%w: %s", operation.ErrDenied, ReasonControlPlane)
	case errors.Is(err, rbac.ErrBuiltInRole):
		return fmt.Errorf("%w: %s", operation.ErrDenied, ReasonBuiltInRole)
	case errors.Is(err, rbac.ErrOwnerRole):
		return fmt.Errorf("%w: %s", operation.ErrDenied, ReasonOwnerRole)
	case errors.Is(err, rbac.ErrActorNotDirect):
		return fmt.Errorf("%w: %s", operation.ErrDenied, ReasonDirectPersonOnly)
	case errors.Is(err, rbac.ErrNotFound):
		return fmt.Errorf("%w: not found", operation.ErrInvalid)
	case errors.Is(err, rbac.ErrExists):
		return fmt.Errorf("%w: already exists", operation.ErrInvalid)
	case errors.Is(err, rbac.ErrInvalid):
		return fmt.Errorf("%w: the request is not a valid role or assignment", operation.ErrInvalid)
	}
	return err
}

func perms(in []string) []authz.Permission {
	out := make([]authz.Permission, len(in))
	for i, p := range in {
		out[i] = authz.Permission(p)
	}
	return out
}

func strs(in []authz.Permission) []string {
	out := make([]string, len(in))
	for i, p := range in {
		out[i] = string(p)
	}
	slices.Sort(out)
	return out
}

func sorted(in []string) []string { out := slices.Clone(in); slices.Sort(out); return out }

func ref(class, id string) authority.TargetRef { return authority.TargetRef{GUID: id, Class: class} }

// guard returns the writer and the transaction, or the reason there is none.
func guard(g *rbac.Grants, s step.Step) (*rbac.Grants, error) {
	if g == nil {
		return nil, errUnavailable
	}
	if s.Tx() == nil {
		return nil, errors.New("delegation: an access change needs the runner's transaction")
	}
	return g, nil
}

func roleCreate(g *rbac.Grants) (operation.Action, error) {
	return operation.Define(operation.Typed[RoleCreateInput, RoleCreateInput, Outcome]{
		Descriptor: operation.Descriptor{
			ID: RoleCreateID, Version: 1, Permission: PermRoleCreate,
			Input:  "#/components/schemas/RoleCreate",
			Target: operation.TargetStore, Reversibility: operation.Irreversible, AuditKind: AuditRoleCreated, StepUp: true, ControlPlane: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in RoleCreateInput) ([]operation.TypedStep[RoleCreateInput], error) {
			if g == nil {
				return nil, errUnavailable
			}
			if !rbac.ValidID(in.RoleID) || in.Name == "" || len(in.Permissions) == 0 {
				return nil, fmt.Errorf("%w: roleId, name and permissions are required", operation.ErrInvalid)
			}
			if _, err := g.Role(ctx, pc.Tx, in.RoleID); err == nil {
				return nil, fmt.Errorf("%w: already exists", operation.ErrInvalid)
			} else if !errors.Is(err, rbac.ErrNotFound) {
				return nil, deny(err)
			}
			return []operation.TypedStep[RoleCreateInput]{{
				Plan: operation.StepPlan{
					Target: ref(TargetClassRole, in.RoleID), Kind: "delegation.role.create",
					Diff: []operation.Change{
						{Attribute: "name", After: []string{in.Name}},
						{Attribute: "tier", After: []string{strconv.Itoa(in.Tier)}},
						{Attribute: "permissions", After: sorted(in.Permissions)},
					},
					Reversibility:       operation.Irreversible,
					ReversibilityReason: "a role is never deleted; empty it with delegation.role.update and stop assigning it",
				},
				Payload: in,
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[RoleCreateInput]) (Outcome, error) {
			w, err := guard(g, s)
			if err != nil {
				return Outcome{}, err
			}
			in := p.Payload
			return Outcome{ID: in.RoleID}, deny(w.CreateRole(ctx, s.Tx(), s.Actor(), in.RoleID, in.Name, rbac.Tier(in.Tier), perms(in.Permissions)))
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[RoleCreateInput], _ Outcome) (operation.Verdict, error) {
			r, err := g.Role(ctx, s.Tx(), p.Payload.RoleID)
			if err != nil {
				return operation.Verdict{}, deny(err)
			}
			if !slices.Equal(strs(r.Permissions), sorted(p.Payload.Permissions)) {
				return operation.Verdict{Reason: "role_not_as_applied"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[RoleCreateInput], Outcome) (RoleCreateInput, error) {
			return RoleCreateInput{}, operation.ErrIrreversible
		},
	})
}

type roleUpdatePayload struct {
	RoleID string   `json:"roleId"`
	Before []string `json:"before"`
	After  []string `json:"after"`
}

func roleUpdate(g *rbac.Grants) (operation.Action, error) {
	return operation.Define(operation.Typed[RoleUpdateInput, roleUpdatePayload, Outcome]{
		Descriptor: operation.Descriptor{
			ID: RoleUpdateID, Version: 1, Permission: PermRoleUpdate,
			Input:  "#/components/schemas/RoleUpdate",
			Target: operation.TargetStore, Reversibility: operation.Reversible, AuditKind: AuditRoleUpdated, StepUp: true, ControlPlane: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in RoleUpdateInput) ([]operation.TypedStep[roleUpdatePayload], error) {
			if g == nil {
				return nil, errUnavailable
			}
			if !rbac.ValidID(in.RoleID) || len(in.Permissions) == 0 {
				return nil, fmt.Errorf("%w: roleId and permissions are required", operation.ErrInvalid)
			}
			r, err := g.Role(ctx, pc.Tx, in.RoleID)
			if err != nil {
				return nil, deny(err)
			}
			if r.BuiltIn {
				return nil, deny(rbac.ErrBuiltInRole)
			}
			before := strs(r.Permissions)
			return []operation.TypedStep[roleUpdatePayload]{{
				Plan: operation.StepPlan{
					Target: ref(TargetClassRole, in.RoleID), Kind: "delegation.role.update",
					Diff:          []operation.Change{{Attribute: "permissions", Before: before, After: sorted(in.Permissions)}},
					Reversibility: operation.Reversible,
				},
				Payload: roleUpdatePayload{RoleID: in.RoleID, Before: before, After: sorted(in.Permissions)},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[roleUpdatePayload]) (Outcome, error) {
			w, err := guard(g, s)
			if err != nil {
				return Outcome{}, err
			}
			return Outcome{ID: p.Payload.RoleID}, deny(w.SetRolePermissions(ctx, s.Tx(), s.Actor(), p.Payload.RoleID, perms(p.Payload.After)))
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[roleUpdatePayload], _ Outcome) (operation.Verdict, error) {
			r, err := g.Role(ctx, s.Tx(), p.Payload.RoleID)
			if err != nil {
				return operation.Verdict{}, deny(err)
			}
			if !slices.Equal(strs(r.Permissions), p.Payload.After) {
				return operation.Verdict{Reason: "role_not_as_applied"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(p operation.TypedStep[roleUpdatePayload], _ Outcome) (RoleUpdateInput, error) {
			return RoleUpdateInput{RoleID: p.Payload.RoleID, Permissions: p.Payload.Before}, nil
		},
	})
}

func (s SubjectInput) ref() rbac.SubjectRef {
	return rbac.SubjectRef{Kind: rbac.SubjectKind(s.Kind), Account: s.AccountID, Connection: s.ConnectionID, Group: s.GroupGUID, Automation: s.PolicyID}
}

func (s SubjectInput) label() string {
	switch rbac.SubjectKind(s.Kind) {
	case rbac.SubjectGroup:
		return "group:" + s.ConnectionID + "/" + s.GroupGUID
	case rbac.SubjectAutomation:
		return "automation:" + s.PolicyID
	}
	return "account:" + s.AccountID
}

func rootLabels(rs []rbac.Root) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		sign := "+"
		if r.Exclude {
			sign = "-"
		}
		out[i] = sign + string(r.Kind) + ":" + r.Connection + "/" + r.GUID
	}
	return out
}

func (in GrantInput) roots() []rbac.Root {
	out := make([]rbac.Root, len(in.Roots))
	for i, r := range in.Roots {
		out[i] = rbac.Root{Kind: rbac.RootKind(r.Kind), Connection: r.ConnectionID, GUID: r.GUID, Exclude: r.Exclude}
	}
	return out
}

func grant(g *rbac.Grants) (operation.Action, error) {
	return operation.Define(operation.Typed[GrantInput, GrantInput, Outcome]{
		Descriptor: operation.Descriptor{
			ID: GrantID, Version: 1, Permission: PermGrant,
			Input:  "#/components/schemas/AssignmentGrant",
			Target: operation.TargetStore, Reversibility: operation.Irreversible, AuditKind: AuditGranted, StepUp: true, ControlPlane: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in GrantInput) ([]operation.TypedStep[GrantInput], error) {
			if g == nil {
				return nil, errUnavailable
			}
			if !rbac.ValidID(in.AssignmentID) || !rbac.ValidID(in.RoleID) || !in.Subject.ref().Valid() || len(in.Roots) == 0 {
				return nil, fmt.Errorf("%w: assignmentId, roleId, subject and roots are required", operation.ErrInvalid)
			}
			role, err := g.Role(ctx, pc.Tx, in.RoleID)
			if err != nil {
				return nil, deny(err)
			}
			if err := rbac.CheckGrantable(role, in.Subject.ref()); err != nil {
				return nil, deny(err)
			}
			if _, err := g.Assignment(ctx, pc.Tx, in.AssignmentID); err == nil {
				return nil, fmt.Errorf("%w: already exists", operation.ErrInvalid)
			} else if !errors.Is(err, rbac.ErrNotFound) {
				return nil, deny(err)
			}
			diff := []operation.Change{
				{Attribute: "role", After: []string{role.Name}},
				{Attribute: "subject", After: []string{in.Subject.label()}},
				{Attribute: "scope", After: rootLabels(in.roots())},
			}
			if in.ValidUntil != nil {
				diff = append(diff, operation.Change{Attribute: "valid_until", After: []string{in.ValidUntil.UTC().Format(time.RFC3339)}})
			}
			return []operation.TypedStep[GrantInput]{{
				Plan: operation.StepPlan{
					Target: ref(TargetClassAssignment, in.AssignmentID), Kind: "delegation.assignment.grant", Diff: diff,
					Reversibility:       operation.Irreversible,
					ReversibilityReason: "an assignment is ended with delegation.assignment.revoke; a revoked assignment is not restored, grant a new one",
				},
				Payload: in,
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[GrantInput]) (Outcome, error) {
			w, err := guard(g, s)
			if err != nil {
				return Outcome{}, err
			}
			in := p.Payload
			return Outcome{ID: in.AssignmentID}, deny(w.Grant(ctx, s.Tx(), s.Actor(), rbac.GrantInput{
				ID: in.AssignmentID, RoleID: in.RoleID, Subject: in.Subject.ref(), Roots: in.roots(), ValidFrom: in.ValidFrom, ValidUntil: in.ValidUntil,
			}))
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[GrantInput], _ Outcome) (operation.Verdict, error) {
			a, err := g.Assignment(ctx, s.Tx(), p.Payload.AssignmentID)
			if err != nil {
				return operation.Verdict{}, deny(err)
			}
			if !a.Active || a.RoleID != p.Payload.RoleID || !slices.Equal(rootLabels(a.Roots), rootLabels(p.Payload.roots())) {
				return operation.Verdict{Reason: "assignment_not_as_applied"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[GrantInput], Outcome) (GrantInput, error) {
			return GrantInput{}, operation.ErrIrreversible
		},
	})
}

func revoke(g *rbac.Grants) (operation.Action, error) {
	return operation.Define(operation.Typed[RevokeInput, RevokeInput, Outcome]{
		Descriptor: operation.Descriptor{
			ID: RevokeID, Version: 1, Permission: PermRevoke,
			Input:  "#/components/schemas/AssignmentRevoke",
			Target: operation.TargetStore, Reversibility: operation.Irreversible, AuditKind: AuditRevoked, StepUp: true, ControlPlane: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in RevokeInput) ([]operation.TypedStep[RevokeInput], error) {
			if g == nil {
				return nil, errUnavailable
			}
			a, err := g.Assignment(ctx, pc.Tx, in.AssignmentID)
			if err != nil {
				return nil, deny(err)
			}
			if !a.Active {
				return nil, fmt.Errorf("%w: the assignment is not active", operation.ErrInvalid)
			}
			if a.Owner {
				return nil, deny(rbac.ErrOwnerRole)
			}
			return []operation.TypedStep[RevokeInput]{{
				Plan: operation.StepPlan{
					Target: ref(TargetClassAssignment, in.AssignmentID), Kind: "delegation.assignment.revoke",
					Diff: []operation.Change{
						{Attribute: "role", Before: []string{a.RoleName}, After: []string{a.RoleName}},
						{Attribute: "subject", Before: []string{SubjectInput{Kind: string(a.Subject.Kind), AccountID: a.Subject.Account, ConnectionID: a.Subject.Connection, GroupGUID: a.Subject.Group, PolicyID: a.Subject.Automation}.label()}, After: []string{"revoked"}},
						{Attribute: "scope", Before: rootLabels(a.Roots), After: nil},
					},
					Reversibility:       operation.Irreversible,
					ReversibilityReason: "a revoked assignment is not restored; grant a new one",
				},
				Payload: in,
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[RevokeInput]) (Outcome, error) {
			w, err := guard(g, s)
			if err != nil {
				return Outcome{}, err
			}
			return Outcome{ID: p.Payload.AssignmentID}, deny(w.Revoke(ctx, s.Tx(), s.Actor(), p.Payload.AssignmentID))
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[RevokeInput], _ Outcome) (operation.Verdict, error) {
			a, err := g.Assignment(ctx, s.Tx(), p.Payload.AssignmentID)
			if err != nil {
				return operation.Verdict{}, deny(err)
			}
			if a.Active {
				return operation.Verdict{Reason: "assignment_still_active"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[RevokeInput], Outcome) (RevokeInput, error) {
			return RevokeInput{}, operation.ErrIrreversible
		},
	})
}
