package operation

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// inChain reports whether p is the requester or any delegated principal of the initiator chain.
func inChain(c authority.Chain, p authority.PrincipalID) bool {
	if c.Requester.ID == p {
		return true
	}
	for _, v := range c.Via {
		if v.ID == p {
			return true
		}
	}
	return false
}

// checkApprover applies the approver rules of ADR-0005 rule 8 that do not depend on the plan.
func (r *Runner) checkApprover(ctx context.Context, op opRecord, ap Approval, needStepUp bool) error {
	switch {
	case !ap.Interactive || ap.Principal.Kind != authority.Human:
		return ErrNotHuman
	case inChain(op.Chain, ap.Principal.ID):
		return ErrSelfApproval
	case needStepUp && !ap.FreshStepUp:
		return ErrStepUpRequired
	}
	if r.cfg.Provenance == nil {
		// Fail closed: without the provenance source the sock-puppet rule cannot be evaluated.
		r.alert(ctx, Alert{Severity: "high", Reason: "provenance_unavailable", Operation: op.ID, Principal: ap.Principal.ID})
		return fmt.Errorf("%w: sock-puppet check unavailable", ErrSockPuppet)
	}
	since := r.cfg.Now().Add(-sockPuppetWindow)
	members := []authority.PrincipalID{op.Chain.Requester.ID}
	for _, v := range op.Chain.Via {
		members = append(members, v.ID)
	}
	for _, m := range members {
		for _, dir := range [2][2]authority.PrincipalID{{ap.Principal.ID, m}, {m, ap.Principal.ID}} {
			tied, err := r.cfg.Provenance.Tied(ctx, dir[0], dir[1], since)
			if err != nil {
				r.alert(ctx, Alert{Severity: "high", Reason: "provenance_error", Operation: op.ID, Principal: ap.Principal.ID})
				return fmt.Errorf("%w: sock-puppet check failed: %w", ErrSockPuppet, err)
			}
			if tied {
				r.alert(ctx, Alert{Severity: "critical", Reason: "sock_puppet_approval", Operation: op.ID, Principal: ap.Principal.ID})
				return ErrSockPuppet
			}
		}
	}
	return nil
}

// Approve records the kernel's single approval of an operation awaiting it and queues the operation
// (rule 8). The approval is for the plan hash the approver saw; the approver must be an interactive
// human outside the initiator chain, with a fresh step-up for an Irreversible or StepUp operation,
// not tied to the initiator, and hold operation.approve over every item.
func (r *Runner) Approve(ctx context.Context, t tenant.ID, opID, planHash string, ap Approval) (Submission, error) {
	var op opRecord
	var rows []stepRow
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) (err error) {
		if op, err = loadOp(ctx, tx, t, opID, false); err != nil {
			return err
		}
		rows, err = loadSteps(ctx, tx, t, opID)
		return err
	})
	if err != nil {
		return Submission{}, err
	}
	if op.State != OpAwaitingApproval {
		return Submission{}, ErrNotAwaiting
	}
	if planHash == "" || planHash != op.PlanHash {
		return Submission{}, ErrStalePlanHash
	}
	act, _ := r.cfg.Registry.Lookup(op.Action)
	d := act.Describe()
	steps := make([]StepPlan, len(rows))
	for i, sr := range rows {
		steps[i] = sr.Plan
	}
	if err := r.checkApprover(ctx, op, ap, d.StepUp || worst(steps) == Irreversible); err != nil {
		return Submission{}, err
	}
	approver := authority.Chain{Requester: ap.Principal}
	for _, sp := range steps {
		if reason := r.authoriseTarget(ctx, approver, PermApprove, sp.Target, op.Pins); reason != "" {
			return Submission{}, fmt.Errorf("%w: %s", ErrNotApprover, reason)
		}
	}
	sub := Submission{Operation: step.OperationID(opID), PlanHash: op.PlanHash}
	err = r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		cur, err := loadOp(ctx, tx, t, opID, true)
		if err != nil {
			return err
		}
		if cur.State != OpAwaitingApproval {
			return ErrNotAwaiting
		}
		if cur.PlanHash != planHash || cur.Revision != op.Revision {
			return ErrStalePlanHash // re-planned meanwhile: the approval is for another plan
		}
		if _, err := tx.Exec(ctx, `UPDATE public.operations SET approved_by = $3, approved_plan_hash = $4, approved_at = now()
WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), opID, string(ap.Principal.ID), planHash); err != nil {
			return fmt.Errorf("operation: recording approval: %w", err)
		}
		if err := setOperationState(ctx, tx, t, opID, OpAwaitingApproval, OpApproved); err != nil {
			return err
		}
		sub.State = OpApproved
		return r.emit(ctx, tx, audit.Event{ID: "op-" + opID + "-approved-" + planHash[:12], Kind: KindOperationApproved,
			Actor: authority.Chain{Requester: ap.Principal}, Key: step.Key{Operation: step.OperationID(opID)},
			Outcome: audit.Success, PlanHash: planHash, Details: detail("hold_reason", string(cur.Hold), "initiator", string(cur.Chain.Requester.ID))})
	})
	if err != nil {
		return sub, err
	}
	return r.queue(ctx, t, opID, sub)
}

// Reject refuses an operation awaiting approval. The same approver rules apply, except that a rejection
// needs no step-up and no operation.approve over the items beyond being a human outside the chain.
func (r *Runner) Reject(ctx context.Context, t tenant.ID, opID string, ap Approval) error {
	var op opRecord
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) (err error) {
		op, err = loadOp(ctx, tx, t, opID, false)
		return err
	})
	if err != nil {
		return err
	}
	if op.State != OpAwaitingApproval {
		return ErrNotAwaiting
	}
	if err := r.checkApprover(ctx, op, ap, false); err != nil {
		return err
	}
	return r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		if err := setOperationState(ctx, tx, t, opID, OpAwaitingApproval, OpRejected); err != nil {
			return err
		}
		if err := r.cancelPlanned(ctx, tx, t, opID); err != nil {
			return err
		}
		if err := deleteOperationSecrets(ctx, tx, t, opID); err != nil {
			return err
		}
		return r.emit(ctx, tx, audit.Event{ID: "op-" + opID + "-rejected", Kind: KindOperationRejected,
			Actor: authority.Chain{Requester: ap.Principal}, Key: step.Key{Operation: step.OperationID(opID)},
			Outcome: audit.Denied, Reason: "rejected_by_approver", PlanHash: op.PlanHash})
	})
}
