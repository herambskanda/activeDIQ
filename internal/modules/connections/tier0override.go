package connections

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// Tier0OverrideActionID is the configuration Action of DM-25.I1 (ADR-0005 rule 10).
const Tier0OverrideActionID operation.ActionID = "connections.tier0_override.acknowledge"

// Tier0OverridePermission is the platform-scope Tier-0-override permission (TM-D1, spec FR-13). It
// is meant to be held only through a role assigned at platform scope; the authz kernel has no scope
// class on permissions yet, so that is enforced by T-0250, not here. The Descriptor also demands a
// fresh step-up (TM §7.4), which the runner refuses without before anything else.
const Tier0OverridePermission authz.Permission = "connections.tier0_override.acknowledge"

// AuditTier0OverrideAcknowledged is the event the runner writes for a recorded override.
const AuditTier0OverrideAcknowledged = "connection.tier0_override.acknowledged"

// TypedAcknowledgement is the text the operator must type (spec FR-13). The Action checks it, not
// the UI: a client that skips the prompt gets no override.
const TypedAcknowledgement = "activeDIQ will be Tier 0 in this forest"

// Tier0OverrideInput is the Action's input. The findings are not in it: the override acknowledges
// the named run's whole set of over-privilege findings, read server side (DM-25.I1).
type Tier0OverrideInput struct {
	ConnectionID   string `json:"connection_id"`
	VerificationID string `json:"verification_id"`
	Acknowledgment string `json:"acknowledgement"`
}

type overridePayload struct {
	ConnectionID   string `json:"connection_id"`
	VerificationID string `json:"verification_id"`
	Count          int    `json:"acknowledged_count"`
	Digest         []byte `json:"override_digest"` // adq-override-digest/1 (DM-25.I7); Apply re-checks it against the stored row
}

// Tier0OverrideOutcome is what Apply did.
type Tier0OverrideOutcome struct {
	OverrideID string `json:"override_id"`
	Activated  bool   `json:"activated"` // the connection was a draft and became active in the same transaction
}

// Tier0OverrideAcknowledge builds the Action. Permission and step-up are checked by the runner at
// Plan and again at Apply; the connection store re-checks the data's facts (the run is the newest,
// fresh, over-privilege alone) inside Apply's transaction.
func Tier0OverrideAcknowledge() (operation.Action, error) {
	var store connection.Store
	return operation.Define(operation.Typed[Tier0OverrideInput, overridePayload, Tier0OverrideOutcome]{
		Descriptor: operation.Descriptor{
			ID: Tier0OverrideActionID, Version: 1, Permission: Tier0OverridePermission,
			Input: "#/components/schemas/Tier0OverrideAcknowledge", Target: operation.TargetStore,
			Reversibility: operation.Irreversible, // an acknowledgement is evidence: no undo (DM-25.I5)
			AuditKind:     AuditTier0OverrideAcknowledged, StepUp: true, ControlPlane: true,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in Tier0OverrideInput) ([]operation.TypedStep[overridePayload], error) {
			if in.Acknowledgment != TypedAcknowledgement {
				return nil, fmt.Errorf("%w: the typed acknowledgement does not match", operation.ErrInvalid)
			}
			cid, err := connection.ParseID(in.ConnectionID)
			if err != nil {
				return nil, err
			}
			vid, err := connection.ParseVerificationID(in.VerificationID)
			if err != nil {
				return nil, err
			}
			c, err := store.Get(ctx, pc.Tx, cid)
			if err != nil {
				return nil, err
			}
			if string(vid) != c.LastVerificationID {
				return nil, &connection.OverrideError{Code: connection.ReasonNotLatestRun}
			}
			// DM-25.I7: the event commits to the acknowledged set by count and salted digest, never by
			// fingerprint. The plan carries it, so the plan hash binds it.
			ev, err := store.OverrideEvidenceFor(ctx, pc.Tx, cid, vid)
			if err != nil {
				return nil, err
			}
			return []operation.TypedStep[overridePayload]{{
				Plan: operation.StepPlan{
					Target: authority.TargetRef{Connection: string(cid), GUID: string(cid), Class: "connection"},
					Kind:   "connection.tier0_override.acknowledge",
					Diff: []operation.Change{{Attribute: "tier0_installation", Before: []string{"false"}, After: []string{"true"}}, {Attribute: "verification_id", After: []string{string(vid)}},
						{Attribute: "acknowledged_count", After: []string{strconv.Itoa(ev.Count)}},
						{Attribute: "override_digest", After: []string{hex.EncodeToString(ev.Digest)}}},
					Reversibility:       operation.Irreversible,
					ReversibilityReason: "an acknowledgement is evidence; the next passing run clears it",
				},
				Payload: overridePayload{ConnectionID: string(cid), VerificationID: string(vid), Count: ev.Count, Digest: ev.Digest},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[overridePayload]) (Tier0OverrideOutcome, error) {
			if err := requireHuman(s.Actor()); err != nil {
				return Tier0OverrideOutcome{}, err
			}
			tx := s.Tx()
			if tx == nil {
				return Tier0OverrideOutcome{}, errors.New("connections: override needs the runner's transaction")
			}
			cid, err := connection.ParseID(p.Payload.ConnectionID)
			if err != nil {
				return Tier0OverrideOutcome{}, err
			}
			vid, err := connection.ParseVerificationID(p.Payload.VerificationID)
			if err != nil {
				return Tier0OverrideOutcome{}, err
			}
			// The human behind the request, never the token or automation that carried it.
			o, err := store.AcknowledgeTier0Override(ctx, tx, connection.AcknowledgeInput{
				ConnectionID: cid, VerificationID: vid, By: string(s.Actor().Requester.ID),
			})
			if err != nil {
				return Tier0OverrideOutcome{}, err
			}
			if err := store.VerifyOverrideEvidence(ctx, tx, o, connection.OverrideEvidence{Count: p.Payload.Count, Digest: p.Payload.Digest}); err != nil {
				return Tier0OverrideOutcome{}, err
			}
			out := Tier0OverrideOutcome{OverrideID: string(o.ID)}
			c, err := store.Get(ctx, tx, cid)
			if err != nil {
				return Tier0OverrideOutcome{}, err
			}
			if c.State == connection.StateDraft {
				if _, err := store.Activate(ctx, tx, cid); err != nil {
					return Tier0OverrideOutcome{}, err
				}
				out.Activated = true
			}
			return out, nil
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[overridePayload], o Tier0OverrideOutcome) (operation.Verdict, error) {
			cid, err := connection.ParseID(p.Payload.ConnectionID)
			if err != nil {
				return operation.Verdict{}, err
			}
			ov, err := store.Tier0OverrideInForce(ctx, s.Tx(), cid)
			if err != nil {
				return operation.Verdict{}, err
			}
			if ov == nil || string(ov.ID) != o.OverrideID {
				return operation.Verdict{Reason: "override_not_in_force"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[overridePayload], Tier0OverrideOutcome) (Tier0OverrideInput, error) {
			return Tier0OverrideInput{}, operation.ErrIrreversible
		},
	})
}

// ReasonHumanRequired is the stable reason for refusing an override from a non-human requester.
const ReasonHumanRequired = "human_required"

// requireHuman refuses unless the requester is a human: an override is the installation operator's
// acknowledgement, and step-up is a fresh MFA, which only a person can do (TM-D1, TM §7.4).
func requireHuman(c authority.Chain) error {
	if c.Requester.Kind != authority.Human {
		return fmt.Errorf("%w: %s", operation.ErrDenied, ReasonHumanRequired)
	}
	return nil
}
