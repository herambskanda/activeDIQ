package connections

import (
	"context"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// HybridLinkPermission is the privilege DM-21.I2 names. It must be held over BOTH sides of a link:
// the AD domain's naming context and the Entra tenant. Confirming or declaring switches cross-directory
// authority on; removing switches it off for the write gate (no_hybrid_link) and the connector's
// Tier-0 peer checks, which lowers protection, so removal needs the same privilege (T-0168).
const HybridLinkPermission authz.Permission = "connections.hybrid_link.confirm"

// The three Actions that move a HybridLink. They share one shape and one permission (DM-21.I2).
const (
	HybridLinkConfirmActionID operation.ActionID = "connections.hybrid_link.confirm"
	HybridLinkDeclareActionID operation.ActionID = "connections.hybrid_link.declare"
	HybridLinkRemoveActionID  operation.ActionID = "connections.hybrid_link.remove"
)

// Audit kinds the runner writes, one per transition target.
const (
	AuditHybridLinkConfirmed = "connection.hybrid_link.confirmed"
	AuditHybridLinkDeclared  = "connection.hybrid_link.declared"
	AuditHybridLinkRemoved   = "connection.hybrid_link.removed"
)

// Classes of the two authorisation targets of a link operation.
const (
	classNamingContext = "naming_context"
	classEntraTenant   = "entra_tenant"
)

// HybridLinkInput is the input of the three Actions. Confirm and remove use LinkID; declare uses the
// three side fields. Fields an Action does not use must be empty.
type HybridLinkInput struct {
	LinkID            string `json:"link_id,omitempty"`
	ADConnectionID    string `json:"ad_connection_id,omitempty"`
	NCGUID            string `json:"nc_guid,omitempty"`
	EntraConnectionID string `json:"entra_connection_id,omitempty"`
}

type linkSide string

const (
	sideAD    linkSide = "ad"
	sideEntra linkSide = "entra"
)

type linkPayload struct {
	Side              linkSide             `json:"side"`
	LinkID            string               `json:"link_id,omitempty"`
	ADConnectionID    string               `json:"ad_connection_id"`
	NCGUID            string               `json:"nc_guid"`
	EntraConnectionID string               `json:"entra_connection_id"`
	From              connection.LinkState `json:"from,omitempty"`
	To                connection.LinkState `json:"to"`
}

// HybridLinkOutcome is what Apply did.
type HybridLinkOutcome struct {
	LinkID string               `json:"link_id,omitempty"`
	State  connection.LinkState `json:"state"`
}

type linkMode struct {
	id    operation.ActionID
	audit string
	to    connection.LinkState
	from  connection.LinkState // required current state; empty for declare (creates) and remove (proposed or confirmed)
	input string
	// stepUp: the transition opens or widens a cross-directory authority path (TM §7.4).
	stepUp bool
}

var (
	modeConfirm = linkMode{HybridLinkConfirmActionID, AuditHybridLinkConfirmed, connection.LinkConfirmed, connection.LinkProposed, "#/components/schemas/HybridLinkConfirm", true}
	modeDeclare = linkMode{HybridLinkDeclareActionID, AuditHybridLinkDeclared, connection.LinkConfirmed, "", "#/components/schemas/HybridLinkDeclare", true}
	modeRemove  = linkMode{HybridLinkRemoveActionID, AuditHybridLinkRemoved, connection.LinkRemoved, "", "#/components/schemas/HybridLinkRemove", false}
)

// HybridLinkActions builds the confirm, declare and remove Actions.
func HybridLinkActions() ([]operation.Action, error) {
	var out []operation.Action
	for _, m := range []linkMode{modeConfirm, modeDeclare, modeRemove} {
		a, err := hybridLinkAction(m)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// hybridLinkAction plans two steps, one per side, so the runner authorises HybridLinkPermission over
// the domain's naming context and over the tenant, at Plan and again at Apply, and the whole run
// fails with nothing changed if either is refused. The AD-side step writes; the Entra-side step is
// the witness for the second scope and only verifies.
func hybridLinkAction(m linkMode) (operation.Action, error) {
	var st connection.Store
	return operation.Define(operation.Typed[HybridLinkInput, linkPayload, HybridLinkOutcome]{
		Descriptor: operation.Descriptor{
			ID: m.id, Version: 1, Permission: HybridLinkPermission, Input: operation.SchemaRef(m.input),
			Target: operation.TargetStore, Reversibility: operation.Irreversible, AuditKind: audit.Kind(m.audit), StepUp: m.stepUp,
		},
		Plan: func(ctx context.Context, pc operation.PlanContext, in HybridLinkInput) ([]operation.TypedStep[linkPayload], error) {
			p, err := planLink(ctx, pc, st, m, in)
			if err != nil {
				return nil, err
			}
			diff := []operation.Change{
				{Attribute: "state", Before: beforeState(p.From), After: []string{string(p.To)}},
				{Attribute: "ad_connection_id", After: []string{p.ADConnectionID}},
				{Attribute: "nc_guid", After: []string{p.NCGUID}},
				{Attribute: "entra_connection_id", After: []string{p.EntraConnectionID}},
			}
			if p.LinkID != "" {
				diff = append(diff, operation.Change{Attribute: "link_id", After: []string{p.LinkID}})
			}
			reason := "a link change is audited evidence; a removed link is never revived"
			ad, en := p, p
			ad.Side, en.Side = sideAD, sideEntra
			return []operation.TypedStep[linkPayload]{
				{Plan: stepPlan(m, authority.TargetRef{Connection: p.ADConnectionID, GUID: p.NCGUID, Class: classNamingContext}, diff, reason), Payload: ad},
				{Plan: stepPlan(m, authority.TargetRef{Connection: p.EntraConnectionID, GUID: p.EntraConnectionID, Class: classEntraTenant}, diff, reason), Payload: en},
			}, nil
		},
		Apply: func(ctx context.Context, s step.Step, p operation.TypedStep[linkPayload]) (HybridLinkOutcome, error) {
			// Trust is a person's decision (DM-21.I2): discovery or automation cannot confirm its own link.
			if err := requireHuman(s.Actor()); err != nil {
				return HybridLinkOutcome{}, err
			}
			tx := s.Tx()
			if tx == nil {
				return HybridLinkOutcome{}, errors.New("connections: hybrid link needs the runner's transaction")
			}
			if p.Payload.Side != sideAD {
				return HybridLinkOutcome{State: p.Payload.To, LinkID: p.Payload.LinkID}, nil
			}
			var l connection.HybridLink
			var err error
			if m.id == HybridLinkDeclareActionID {
				l, err = st.DeclareHybridLink(ctx, tx, connection.NewHybridLink{
					ADConnectionID: connection.ID(p.Payload.ADConnectionID), NCGUID: connection.NCGUID(p.Payload.NCGUID),
					EntraConnectionID: connection.ID(p.Payload.EntraConnectionID)})
			} else {
				l, err = st.TransitionHybridLink(ctx, tx, connection.HybridLinkID(p.Payload.LinkID), p.Payload.From, p.Payload.To)
			}
			if err != nil {
				return HybridLinkOutcome{}, err
			}
			return HybridLinkOutcome{LinkID: string(l.ID), State: l.State}, nil
		},
		Verify: func(ctx context.Context, s step.Step, p operation.TypedStep[linkPayload], o HybridLinkOutcome) (operation.Verdict, error) {
			if o.State != p.Payload.To {
				return operation.Verdict{Reason: "link_state_mismatch"}, nil
			}
			if p.Payload.Side != sideAD {
				return operation.Verdict{OK: true}, nil
			}
			l, err := st.GetHybridLink(ctx, s.Tx(), connection.HybridLinkID(o.LinkID))
			if err != nil {
				return operation.Verdict{}, err
			}
			if l.State != p.Payload.To {
				return operation.Verdict{Reason: "link_state_mismatch"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[linkPayload], HybridLinkOutcome) (HybridLinkInput, error) {
			return HybridLinkInput{}, operation.ErrIrreversible
		},
	})
}

func beforeState(s connection.LinkState) []string {
	if s == "" {
		return nil
	}
	return []string{string(s)}
}

func stepPlan(m linkMode, t authority.TargetRef, diff []operation.Change, reason string) operation.StepPlan {
	return operation.StepPlan{Target: t, Kind: string(m.id), Diff: diff,
		Reversibility: operation.Irreversible, ReversibilityReason: reason}
}

// planLink validates the input and reads the current link (read-only), producing the payload both
// steps share.
func planLink(ctx context.Context, pc operation.PlanContext, st connection.Store, m linkMode, in HybridLinkInput) (linkPayload, error) {
	if m.id == HybridLinkDeclareActionID {
		if in.LinkID != "" {
			return linkPayload{}, fmt.Errorf("%w: declare takes the two connections and the domain, not a link", operation.ErrInvalid)
		}
		n, err := connection.NewHybridLink{ADConnectionID: connection.ID(in.ADConnectionID), NCGUID: connection.NCGUID(in.NCGUID),
			EntraConnectionID: connection.ID(in.EntraConnectionID)}.Validate()
		if err != nil {
			return linkPayload{}, err
		}
		return linkPayload{ADConnectionID: string(n.ADConnectionID), NCGUID: string(n.NCGUID),
			EntraConnectionID: string(n.EntraConnectionID), To: m.to}, nil
	}
	if in.ADConnectionID != "" || in.NCGUID != "" || in.EntraConnectionID != "" {
		return linkPayload{}, fmt.Errorf("%w: %s takes a link ID only", operation.ErrInvalid, m.id)
	}
	id, err := connection.ParseHybridLinkID(in.LinkID)
	if err != nil {
		return linkPayload{}, err
	}
	l, err := st.GetHybridLink(ctx, pc.Tx, id)
	if err != nil {
		return linkPayload{}, err
	}
	if m.from != "" && l.State != m.from {
		return linkPayload{}, fmt.Errorf("%w: %s → %s", connection.ErrIllegalLinkTransition, l.State, m.to)
	}
	if !connection.CanTransitionLink(l.State, m.to) {
		return linkPayload{}, fmt.Errorf("%w: %s → %s", connection.ErrIllegalLinkTransition, l.State, m.to)
	}
	return linkPayload{LinkID: string(l.ID), ADConnectionID: string(l.ADConnectionID), NCGUID: string(l.NCGUID),
		EntraConnectionID: string(l.EntraConnectionID), From: l.State, To: m.to}, nil
}
