package connections

import (
	"context"
	"errors"
	"fmt"
	"slices"

	dirinv "github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The re-confirmation of a candidate correlation (threat model §6.8 rule 4 (g), TM-D17). A correlation
// whose Entra object was ever seen cloud-only, or that first became eligible after the first
// attestation while it was open or stale, stays candidate (reason reconfirm_required) until a
// tenant-owner confirms it here. The install-time population never comes through this Action: it
// becomes matched on the first attestation (gate), so a review one by one never becomes a rubber stamp.
const (
	ReconfirmActionID operation.ActionID = "connections.correlation.reconfirm"
	// ReconfirmPermission is the privilege the Action asks the authorizer for, at the correlation's target.
	ReconfirmPermission authz.Permission = "connections.correlation.reconfirm"
	// TargetClassCorrelation is the class of the target: the correlation row, not either directory
	// object, so runner rule 7 (no role touches a tier0 target) does not turn the confirmation into a denial.
	TargetClassCorrelation = "correlation"
	// AuditCorrelationReconfirmed is the event the runner writes, for refusals as well.
	AuditCorrelationReconfirmed audit.Kind = "connections.correlation.reconfirmed"
	// ReasonOwnerRequired is the stable reason for refusing a requester who is not a tenant-owner.
	ReasonOwnerRequired = "tenant_owner_required"
)

// OwnerSource names who holds the tenant-owner role right now (rbac.Owners implements it; it takes the
// tenant's owner lock, held until the transaction ends).
type OwnerSource interface {
	TenantOwners(ctx context.Context, tx store.Tx, t tenant.ID) ([]string, error)
}

// ReconfirmInput names the correlation (DM-20 ID, canonical UUID text).
type ReconfirmInput struct {
	CorrelationID string `json:"correlation_id"`
}

type reconfirmPayload struct {
	CorrelationID string `json:"correlation_id"`
	Tenant        string `json:"tenant"`
}

// ReconfirmOutcome is what Apply did.
type ReconfirmOutcome struct {
	Matched bool `json:"matched"`
}

// ReconfirmCorrelation builds the Action. Beyond the permission and the fresh step-up the runner
// enforces, Apply refuses anyone who is not a human holding the tenant-owner role right now (read in
// the same transaction, under the owner lock), whatever else the authorizer was told they hold.
func ReconfirmCorrelation(owners OwnerSource) (operation.Action, error) {
	if owners == nil {
		return nil, errors.New("connections: re-confirmation needs the tenant-owner source")
	}
	var w dirinv.Writer
	return operation.Define(operation.Typed[ReconfirmInput, reconfirmPayload, ReconfirmOutcome]{
		Descriptor: operation.Descriptor{
			ID: ReconfirmActionID, Version: 1, Permission: ReconfirmPermission,
			Input:  "#/components/schemas/CorrelationReconfirm",
			Target: operation.TargetStore, Reversibility: operation.Irreversible, AuditKind: AuditCorrelationReconfirmed, StepUp: true, ControlPlane: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in ReconfirmInput) ([]operation.TypedStep[reconfirmPayload], error) {
			p, err := w.PendingReconfirmation(ctx, pc.Tx, in.CorrelationID)
			switch {
			case errors.Is(err, dirinv.ErrInvalid):
				return nil, fmt.Errorf("%w: correlation_id must be a UUID", operation.ErrInvalid)
			case errors.Is(err, dirinv.ErrNotFound):
				return nil, fmt.Errorf("%w: unknown correlation", operation.ErrInvalid)
			case errors.Is(err, dirinv.ErrNotReconfirmable):
				return nil, fmt.Errorf("%w: the correlation is not waiting for a re-confirmation", operation.ErrInvalid)
			case err != nil:
				return nil, err
			}
			var tid string
			if err := pc.Tx.QueryRow(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&tid); err != nil || tid == "" {
				return nil, errors.New("connections: no tenant context")
			}
			return []operation.TypedStep[reconfirmPayload]{{
				Plan: operation.StepPlan{
					Target: authority.TargetRef{Connection: string(p.Entra.Connection), GUID: p.ID, Class: TargetClassCorrelation},
					Kind:   "connections.correlation.reconfirm",
					Diff: []operation.Change{
						{Attribute: "ad_object_guid", Before: []string{string(p.AD.Object)}, After: []string{string(p.AD.Object)}},
						{Attribute: "entra_object_guid", Before: []string{string(p.Entra.Object)}, After: []string{string(p.Entra.Object)}},
						{Attribute: "eligibility_class", Before: []string{p.EligibilityClass}, After: []string{p.EligibilityClass}},
						{Attribute: "state", Before: []string{"candidate"}, After: []string{"matched"}},
					},
					Reversibility: operation.Irreversible, ReversibilityReason: "a confirmation is evidence of a person's decision; a later cloud observation, not an undo, returns the correlation to candidate",
				},
				Payload: reconfirmPayload{CorrelationID: p.ID, Tenant: tid},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[reconfirmPayload]) (ReconfirmOutcome, error) {
			who := s.Actor().Requester
			if who.Kind != authority.Human {
				return ReconfirmOutcome{}, fmt.Errorf("%w: %s", operation.ErrDenied, ReasonHumanRequired)
			}
			tx := s.Tx()
			if tx == nil {
				return ReconfirmOutcome{}, errors.New("connections: a re-confirmation needs the runner's transaction")
			}
			tid, err := tenantref.TenantFromText(p.Payload.Tenant)
			if err != nil {
				return ReconfirmOutcome{}, fmt.Errorf("%w: tenant", operation.ErrInvalid)
			}
			owners, err := owners.TenantOwners(ctx, tx, tid)
			if err != nil {
				return ReconfirmOutcome{}, err
			}
			if !slices.Contains(owners, string(who.ID)) {
				return ReconfirmOutcome{}, fmt.Errorf("%w: %s", operation.ErrDenied, ReasonOwnerRequired)
			}
			switch err := w.Reconfirm(ctx, tx, p.Payload.CorrelationID, string(who.ID)); {
			case errors.Is(err, dirinv.ErrNotReconfirmable):
				return ReconfirmOutcome{}, fmt.Errorf("%w: the correlation is no longer waiting for a re-confirmation", operation.ErrInvalid)
			case err != nil:
				return ReconfirmOutcome{}, err
			}
			return ReconfirmOutcome{Matched: true}, nil
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[reconfirmPayload], _ ReconfirmOutcome) (operation.Verdict, error) {
			// The row is matched and carries this confirmation: it stopped waiting.
			if _, err := w.PendingReconfirmation(ctx, s.Tx(), p.Payload.CorrelationID); !errors.Is(err, dirinv.ErrNotReconfirmable) {
				return operation.Verdict{Reason: "correlation_still_waiting"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[reconfirmPayload], ReconfirmOutcome) (ReconfirmInput, error) {
			return ReconfirmInput{}, operation.ErrIrreversible
		},
	})
}
