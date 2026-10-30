package compliance

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/personal"
)

type operationAction = operation.Action

// Action IDs, permissions and audit kinds. Each permission is dedicated to compliance: no built-in role
// holds one (deny by default), so a tenant grants it deliberately, never through a help-desk role.
const (
	SetHoldActionID     operation.ActionID = "compliance.hold.set"
	ReleaseHoldActionID operation.ActionID = "compliance.hold.release"

	PermSetHold     authz.Permission = "compliance.hold.set"
	PermReleaseHold authz.Permission = "compliance.hold.release"

	AuditHoldSet      audit.Kind = "compliance.hold.set"
	AuditHoldReleased audit.Kind = "compliance.hold.released"
)

// TargetClassHold is the class of the target the permission is checked at: the tenant's hold register.
const TargetClassHold = "legal_hold"

// ReasonHumanRequired is the stable reason for refusing a non-human requester.
const ReasonHumanRequired = "human_required"

// HoldInput names the subject (dir:<connection>:<objectGUID> or acct:<id>, see personal.DirSubject).
type HoldInput struct {
	Subject string `json:"subject"`
}

type holdPayload struct {
	Subject string `json:"subject"`
	Tenant  string `json:"tenant"`
}

// HoldOutcome is the state of the hold after Apply.
type HoldOutcome struct {
	Held bool `json:"held"`
}

// SetHold builds the Action that places a hold.
func SetHold() (operation.Action, error) { return hold(true) }

// ReleaseHold builds the Action that lifts a hold. Lifting is what lets the next retention purge destroy
// evidence, and re-holding does not bring destroyed evidence back. Both Actions are Irreversible to the
// runner's undo: an undo never lifts or places a hold under another permission.
func ReleaseHold() (operation.Action, error) { return hold(false) }

// hold is the one shape of both Actions; set says which way it moves the hold.
func hold(set bool) (operation.Action, error) {
	id, perm, kind := ReleaseHoldActionID, PermReleaseHold, AuditHoldReleased
	if set {
		id, perm, kind = SetHoldActionID, PermSetHold, AuditHoldSet
	}
	rev := operation.Irreversible
	ps := personal.New()
	return operation.Define(operation.Typed[HoldInput, holdPayload, HoldOutcome]{
		Descriptor: operation.Descriptor{
			ID: id, Version: 1, Permission: perm,
			Input:  "#/components/schemas/LegalHold",
			Target: operation.TargetStore, Reversibility: rev, AuditKind: kind, StepUp: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in HoldInput) ([]operation.TypedStep[holdPayload], error) {
			var tid string
			if err := pc.Tx.QueryRow(ctx, `SELECT coalesce(current_setting('app.tenant_id', true), '')`).Scan(&tid); err != nil || tid == "" {
				return nil, errors.New("compliance: no tenant context")
			}
			t, err := tenantref.TenantFromText(tid)
			if err != nil {
				return nil, fmt.Errorf("%w: tenant", operation.ErrInvalid)
			}
			cur, err := ps.Held(ctx, pc.Tx, t, in.Subject)
			if errors.Is(err, personal.ErrInvalid) {
				return nil, fmt.Errorf("%w: subject must be dir:<connection>:<objectGUID> or acct:<id>", operation.ErrInvalid)
			}
			if err != nil {
				return nil, err
			}
			// A no-op is not refused: Plan runs before the permission check, so refusing would tell a
			// requester without the permission whether a subject is held. Apply is idempotent and the audit
			// event records before and after.
			return []operation.TypedStep[holdPayload]{{
				Plan: operation.StepPlan{
					Target: authority.TargetRef{GUID: tid, Class: TargetClassHold},
					Kind:   string(id),
					Diff: []operation.Change{
						{Attribute: "subject", Before: []string{in.Subject}, After: []string{in.Subject}},
						{Attribute: "legal_hold", Before: []string{strconv.FormatBool(cur)}, After: []string{strconv.FormatBool(set)}},
					},
					Reversibility:       rev,
					ReversibilityReason: "a hold change is undone only by the other compliance Action, under its own permission; an undo never lifts a hold",
				},
				Payload: holdPayload{Subject: in.Subject, Tenant: tid},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[holdPayload]) (HoldOutcome, error) {
			// A legal hold is a person's decision: the audit event must name the human who made it.
			if s.Actor().Requester.Kind != authority.Human {
				return HoldOutcome{}, fmt.Errorf("%w: %s", operation.ErrDenied, ReasonHumanRequired)
			}
			t, err := tenantref.TenantFromText(p.Payload.Tenant)
			if err != nil {
				return HoldOutcome{}, fmt.Errorf("%w: tenant", operation.ErrInvalid)
			}
			if set {
				return HoldOutcome{Held: true}, ps.SetHold(ctx, s, t, p.Payload.Subject)
			}
			return HoldOutcome{}, ps.ReleaseHold(ctx, s, t, p.Payload.Subject)
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[holdPayload], _ HoldOutcome) (operation.Verdict, error) {
			t, err := tenantref.TenantFromText(p.Payload.Tenant)
			if err != nil {
				return operation.Verdict{}, fmt.Errorf("%w: tenant", operation.ErrInvalid)
			}
			now, err := ps.Held(ctx, s.Tx(), t, p.Payload.Subject)
			if err != nil {
				return operation.Verdict{}, err
			}
			if now != set {
				return operation.Verdict{Reason: "hold_state_not_as_applied"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[holdPayload], HoldOutcome) (HoldInput, error) {
			return HoldInput{}, operation.ErrIrreversible
		},
	})
}
