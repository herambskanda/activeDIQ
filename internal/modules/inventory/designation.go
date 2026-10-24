package inventory

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	dirinv "github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

type operationAction = operation.Action

// The Actions of DM-16.I8. Adding or removing a designation changes what the Tier-0 guard protects
// (threat model §6.4, TM-D4), so both need the Tier-0 scope permission, a fresh step-up (TM §7.4)
// and leave an audit event with the actor, the object and the time.
const SetDesignationActionID operation.ActionID = "inventory.tier0_designation.set"

// DesignationPermission is held through a role allowed to change Tier-0 scope. Removal is the same
// permission: taking a designation off silently drops protection, so it is no weaker than adding one.
const DesignationPermission authz.Permission = "inventory.tier0_designation.manage"

// TargetClassScope is the class of the target the Action authorises against: a connection's Tier-0
// scope. A grant on an OU or on the object itself never covers it.
const TargetClassScope = "tier0_scope"

// AuditDesignationChanged is the event the runner writes; its change records before and after.
const AuditDesignationChanged audit.Kind = "inventory.tier0_designation.changed"

// ReasonHumanRequired is the stable reason for refusing a non-human requester.
const ReasonHumanRequired = "human_required"

// DesignationInput names the object and the wanted state. The connection is a DM-10 connection ID
// and the object its objectGUID (AD) or id (Entra), canonical lower-case UUID text. Designated true
// adds the designation, false removes it (a soft delete).
type DesignationInput struct {
	ConnectionID string `json:"connection_id"`
	ObjectGUID   string `json:"object_guid"`
	Designated   bool   `json:"designated"`
}

type designationPayload = DesignationInput

// DesignationOutcome is what Apply did.
type DesignationOutcome struct {
	Designated bool `json:"designated"` // the state after Apply
}

// SetDesignation builds the Action. It is its own inverse: the inverse of a step is the input that
// restores the previous state.
func SetDesignation() (operation.Action, error) {
	var w dirinv.Writer
	return operation.Define(operation.Typed[DesignationInput, designationPayload, DesignationOutcome]{
		Descriptor: operation.Descriptor{
			ID: SetDesignationActionID, Version: 1, Permission: DesignationPermission,
			Input:  "#/components/schemas/Tier0Designation",
			Target: operation.TargetStore, Reversibility: operation.Reversible, AuditKind: AuditDesignationChanged, StepUp: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in DesignationInput) ([]operation.TypedStep[designationPayload], error) {
			ref := dirinv.Ref{Connection: dirinv.ConnectionID(in.ConnectionID), Object: dirinv.GUID(in.ObjectGUID)}
			if !ref.Valid() {
				return nil, fmt.Errorf("%w: connection_id and object_guid must be canonical lower-case UUIDs", operation.ErrInvalid)
			}
			cur, err := w.IsDesignated(ctx, pc.Tx, ref.Connection, ref.Object)
			if err != nil {
				return nil, err
			}
			if cur == in.Designated {
				return nil, fmt.Errorf("%w: the object is already %s", operation.ErrInvalid, map[bool]string{true: "designated", false: "not designated"}[cur])
			}
			return []operation.TypedStep[designationPayload]{{
				Plan: operation.StepPlan{
					// The target is the connection's Tier-0 scope, not the designated object: the permission
					// is then checked at a scope only a Tier-0 role holds, and runner rule 7 (no role touches
					// a tier0 target) does not turn un-designation into a permanent denial. The object is
					// bound into the step digest and the audit event through the diff.
					Target: authority.TargetRef{Connection: in.ConnectionID, GUID: in.ConnectionID, Class: TargetClassScope},
					Kind:   "inventory.tier0_designation.set",
					Diff: []operation.Change{
						{Attribute: "object_guid", Before: []string{in.ObjectGUID}, After: []string{in.ObjectGUID}},
						{Attribute: "tier0_designated", Before: []string{strconv.FormatBool(cur)}, After: []string{strconv.FormatBool(in.Designated)}},
					},
					Reversibility: operation.Reversible,
				},
				Payload: in,
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[designationPayload]) (DesignationOutcome, error) {
			// A change to Tier-0 scope is a person's act, and step-up is a fresh MFA only a person can do.
			if s.Actor().Requester.Kind != authority.Human {
				return DesignationOutcome{}, fmt.Errorf("%w: %s", operation.ErrDenied, ReasonHumanRequired)
			}
			tx := s.Tx()
			if tx == nil {
				return DesignationOutcome{}, errors.New("inventory: a designation change needs the runner's transaction")
			}
			c, o, by := dirinv.ConnectionID(p.Payload.ConnectionID), dirinv.GUID(p.Payload.ObjectGUID), string(s.Actor().Requester.ID)
			if p.Payload.Designated {
				if _, err := w.Designate(ctx, tx, c, o, by); err != nil {
					return DesignationOutcome{}, err
				}
				return DesignationOutcome{Designated: true}, nil
			}
			if err := w.Undesignate(ctx, tx, c, o, by); err != nil {
				return DesignationOutcome{}, err
			}
			return DesignationOutcome{}, nil
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[designationPayload], o DesignationOutcome) (operation.Verdict, error) {
			now, err := w.IsDesignated(ctx, s.Tx(), dirinv.ConnectionID(p.Payload.ConnectionID), dirinv.GUID(p.Payload.ObjectGUID))
			if err != nil {
				return operation.Verdict{}, err
			}
			if now != p.Payload.Designated {
				return operation.Verdict{Reason: "designation_state_not_as_applied"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(p operation.TypedStep[designationPayload], _ DesignationOutcome) (DesignationInput, error) {
			return DesignationInput{ConnectionID: p.Payload.ConnectionID, ObjectGUID: p.Payload.ObjectGUID, Designated: !p.Payload.Designated}, nil
		},
	})
}
