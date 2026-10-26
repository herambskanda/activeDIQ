package operation

import (
	"context"
	"encoding/json"
	"errors"
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

// ErrApprovalByRequest is returned when the kernel's single approval is attempted on an operation
// whose hold was claimed by a workflow Request (rule 8): only the gate's callback may decide it.
var ErrApprovalByRequest = errors.New("operation: held by a workflow request")

// loadItemTargets returns the target of every item of the operation, blocked and skipped included:
// an approval covers the whole scope the plan hash binds, not only the runnable rows.
func loadItemTargets(ctx context.Context, tx store.Tx, t tenant.ID, opID string) ([]authority.TargetRef, error) {
	rows, err := tx.Query(ctx, `SELECT target FROM public.operation_items
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid ORDER BY item_no`, t.String(), opID)
	if err != nil {
		return nil, fmt.Errorf("operation: loading item targets: %w", err)
	}
	defer rows.Close()
	var out []authority.TargetRef
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var tr authority.TargetRef
		if err := json.Unmarshal(raw, &tr); err != nil {
			return nil, fmt.Errorf("operation: decoding item target: %w", err)
		}
		out = append(out, tr)
	}
	return out, rows.Err()
}

// requireApproverScope demands operation.approve over every item of the operation.
func (r *Runner) requireApproverScope(ctx context.Context, op opRecord, targets []authority.TargetRef, p authority.Principal) error {
	approver := authority.Chain{Requester: p}
	for _, tr := range targets {
		if reason := r.authoriseTarget(ctx, op.Tenant, approver, PermApprove, tr, op.Pins); reason != "" {
			return fmt.Errorf("%w: %s", ErrNotApprover, reason)
		}
	}
	return nil
}

// Approve records the kernel's single approval of an operation awaiting it and queues the operation
// (rule 8). The approval is for the plan hash the approver saw; the approver must be an interactive
// human outside the initiator chain, with a fresh step-up for an Irreversible or StepUp operation,
// not tied to the initiator, and hold operation.approve over every item.
func (r *Runner) Approve(ctx context.Context, t tenant.ID, opID, planHash string, ap Approval) (Submission, error) {
	return r.approve(ctx, t, opID, planHash, "", ap)
}

// ApproveRequest is the gate's callback: a workflow Request that claimed the hold has completed its
// stages and approves the operation. It needs the Request's reference; the approver rules still apply.
func (r *Runner) ApproveRequest(ctx context.Context, t tenant.ID, opID, planHash, requestRef string, ap Approval) (Submission, error) {
	if requestRef == "" {
		return Submission{}, ErrApprovalByRequest
	}
	return r.approve(ctx, t, opID, planHash, requestRef, ap)
}

func (r *Runner) approve(ctx context.Context, t tenant.ID, opID, planHash, viaRequest string, ap Approval) (Submission, error) {
	var op opRecord
	var rows []stepRow
	var targets []authority.TargetRef
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) (err error) {
		if op, err = loadOp(ctx, tx, t, opID, false); err != nil {
			return err
		}
		if rows, err = loadSteps(ctx, tx, t, opID); err != nil {
			return err
		}
		targets, err = loadItemTargets(ctx, tx, t, opID)
		return err
	})
	if err != nil {
		return Submission{}, err
	}
	if op.State != OpAwaitingApproval {
		return Submission{}, ErrNotAwaiting
	}
	if op.RequestRef != viaRequest {
		return Submission{}, ErrApprovalByRequest
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
	if err := r.requireApproverScope(ctx, op, targets, ap.Principal); err != nil {
		return Submission{}, err
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

// Reject refuses an operation awaiting approval. The approver rules apply, including operation.approve
// over every item, except that a rejection needs no step-up. An operation held by a workflow Request
// is rejected only through RejectRequest.
func (r *Runner) Reject(ctx context.Context, t tenant.ID, opID string, ap Approval) error {
	return r.reject(ctx, t, opID, "", ap)
}

// RejectRequest is the gate's callback for a Request that ended without approval.
func (r *Runner) RejectRequest(ctx context.Context, t tenant.ID, opID, requestRef string, ap Approval) error {
	if requestRef == "" {
		return ErrApprovalByRequest
	}
	return r.reject(ctx, t, opID, requestRef, ap)
}

func (r *Runner) reject(ctx context.Context, t tenant.ID, opID, viaRequest string, ap Approval) error {
	var op opRecord
	var targets []authority.TargetRef
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) (err error) {
		if op, err = loadOp(ctx, tx, t, opID, false); err != nil {
			return err
		}
		targets, err = loadItemTargets(ctx, tx, t, opID)
		return err
	})
	if err != nil {
		return err
	}
	if op.State != OpAwaitingApproval {
		return ErrNotAwaiting
	}
	if op.RequestRef != viaRequest {
		return ErrApprovalByRequest
	}
	if err := r.checkApprover(ctx, op, ap, false); err != nil {
		return err
	}
	if err := r.requireApproverScope(ctx, op, targets, ap.Principal); err != nil {
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
