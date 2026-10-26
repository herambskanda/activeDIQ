package operation

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Reconcile takes over steps whose claim lapsed (the worker died, or lost its lease) and decides, by
// reading the target on the pin, what became of them (ADR-0005 rule 6):
//
//	after-state in place   -> applied, recovered: true
//	before-state in place  -> applied again with a new attempt; not_run if the operation is cancelling
//	anything else          -> failed, stale_state
//
// A credential step is never re-applied: applied if the credential was set after the claim, otherwise
// failed with outcome_unknown. A takeover is a compare-and-set on the previous attempt, so a revived
// original writer's late result changes nothing.
func (r *Runner) Reconcile(ctx context.Context, t tenant.ID, tx txFunc, limit int) (int, error) {
	var taken []*claimed
	err := tx(ctx, func(ctx context.Context, q store.Tx) error {
		taken = nil
		rows, err := q.Query(ctx, `SELECT operation_id::text, item_no, step_no, attempt, claimed_at, plan, connection_id, COALESCE(dc_host, ''), credential
FROM public.operation_steps WHERE tenant_id = $1::uuid AND state = 'applying' AND claimed_until < now()
ORDER BY claimed_until LIMIT $2 FOR UPDATE SKIP LOCKED`, t.String(), limit)
		if err != nil {
			return fmt.Errorf("operation: finding lapsed claims: %w", err)
		}
		type lapsed struct {
			c    claimed
			prev int
			plan []byte
		}
		var ls []lapsed
		for rows.Next() {
			var l lapsed
			var op string
			if err := rows.Scan(&op, &l.c.key.Item, &l.c.key.Step, &l.prev, &l.c.claimedAt, &l.plan, &l.c.conn, &l.c.dc, &l.c.cred); err != nil {
				rows.Close()
				return err
			}
			l.c.key.Operation = step.OperationID(op)
			ls = append(ls, l)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, l := range ls {
			c := l.c
			if err := json.Unmarshal(l.plan, &c.plan); err != nil {
				return fmt.Errorf("operation: corrupt plan: %w", err)
			}
			if c.op, err = loadOp(ctx, q, t, string(c.key.Operation), false); err != nil {
				return err
			}
			act, ok := r.cfg.Registry.Lookup(c.op.Action)
			if !ok {
				return fmt.Errorf("%w: %q", ErrUnknown, c.op.Action)
			}
			c.act, c.d = act, act.Describe()
			if c.attempt, err = takeoverStep(ctx, q, t, c.key, l.prev, r.cfg.Lease, true); err != nil {
				if errors.Is(err, ErrConflict) {
					continue
				}
				return err
			}
			taken = append(taken, &c)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	for _, c := range taken {
		if err := r.reconcileOne(ctx, t, tx, c); err != nil {
			return 0, err
		}
	}
	return len(taken), nil
}

func (r *Runner) reconcileOne(ctx context.Context, t tenant.ID, tx txFunc, c *claimed) error {
	obs, err := c.act.(Observer).Observe(ctx, c.op.Pins, c.plan, c.claimedAt)
	if err != nil {
		return nil // unreadable: the new lease lapses and the next pass tries again
	}
	switch {
	case obs == ObservedAfter:
		return r.verifyAndRecord(ctx, t, tx, c, Outcome{AlreadyApplied: true}, true)
	case c.cred:
		return r.record(ctx, t, tx, c, recordSpec{failed: "outcome_unknown"})
	case obs == ObservedBefore && c.op.State == OpCancelling:
		return r.record(ctx, t, tx, c, recordSpec{notRun: true})
	case obs == ObservedBefore:
		return r.execute(ctx, t, tx, c)
	}
	return r.record(ctx, t, tx, c, recordSpec{failed: "stale_state"})
}

// Verify runs the deferred read-back of steps that are applied but not yet verified (Entra, or a DC that
// was unreachable at the time). It is the body of operation.verify.
func (r *Runner) Verify(ctx context.Context, t tenant.ID, tx txFunc, opID string) error {
	var ps []*claimed
	err := tx(ctx, func(ctx context.Context, q store.Tx) error {
		ps = nil
		op, err := loadOp(ctx, q, t, opID, false)
		if err != nil {
			return err
		}
		act, ok := r.cfg.Registry.Lookup(op.Action)
		if !ok {
			return fmt.Errorf("%w: %q", ErrUnknown, op.Action)
		}
		rows, err := q.Query(ctx, `SELECT item_no, step_no, attempt, plan, connection_id, COALESCE(dc_host, ''), credential
FROM public.operation_steps WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND state = 'applied' ORDER BY item_no, step_no`, t.String(), opID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c := &claimed{op: op, act: act, d: act.Describe()}
			var plan []byte
			c.key.Operation = step.OperationID(opID)
			if err := rows.Scan(&c.key.Item, &c.key.Step, &c.attempt, &plan, &c.conn, &c.dc, &c.cred); err != nil {
				return err
			}
			if err := json.Unmarshal(plan, &c.plan); err != nil {
				return fmt.Errorf("operation: corrupt plan: %w", err)
			}
			ps = append(ps, c)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	for _, c := range ps {
		// A step recorded `applied` (applying -> applied) leaves its item running; verifyAndRecord's
		// record call would find the step in `applied`, so verify records the applied -> verified edge.
		if err := r.verifyApplied(ctx, t, tx, c); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) verifyApplied(ctx context.Context, t tenant.ID, tx txFunc, c *claimed) error {
	stp, revoke, err := r.mintFor(c, c.attempt, secret.Secret{})
	if err != nil {
		return err
	}
	v, verr := c.act.Verify(ctx, stp, c.plan, Outcome{})
	revoke()
	if errors.Is(verr, ErrDeferVerify) {
		return nil
	}
	to, reason := StepVerified, ""
	switch {
	case verr != nil:
		to, reason = StepVerifyFailed, "verify_error"
	case !v.OK:
		to, reason = StepVerifyFailed, v.Reason
		if reason == "" {
			reason = "verify_failed"
		}
	}
	return tx(context.WithoutCancel(ctx), func(ctx context.Context, q store.Tx) error {
		ok, err := recordStep(ctx, q, t, c.key, c.attempt, StepApplied, to, reason, false, nil)
		if err != nil || !ok {
			return err
		}
		item, o := ItemSucceeded, audit.Success
		if to != StepVerified {
			item, o = ItemFailed, audit.Failure
		}
		if err := setItemState(ctx, q, t, string(c.key.Operation), c.key.Item, ItemRunning, item, reason); err != nil {
			return err
		}
		ev := c.event(r, o, "verified_later", false)
		if reason != "" {
			ev.Reason = reason
		}
		if err := r.emit(ctx, q, ev); err != nil {
			return err
		}
		return r.settle(ctx, q, t, string(c.key.Operation))
	})
}

// Sweep is the backstop for everything a lost job or a crash can leave behind, for one tenant:
// operations that stopped making progress are re-driven, a finished operation that was never settled is
// settled, lapsed claims are reconciled, deferred read-backs are re-queued, stale plans are abandoned
// and expired secrets are deleted. It is the body of operation.sweep, and every action is idempotent.
func (r *Runner) Sweep(ctx context.Context, t tenant.ID, tx txFunc) error {
	if _, err := r.Reconcile(ctx, t, tx, 50); err != nil {
		return err
	}
	return tx(ctx, func(ctx context.Context, q store.Tx) error {
		// Settle running operations with nothing in flight (the terminal detection of a lost recording).
		ids, err := scanIDs(q.Query(ctx, `SELECT id::text FROM public.operations WHERE tenant_id = $1::uuid AND state IN ('running', 'cancelling')
AND NOT EXISTS (SELECT 1 FROM public.operation_items i WHERE i.tenant_id = operations.tenant_id AND i.operation_id = operations.id AND i.state = 'running')`, t.String()))
		if err != nil {
			return err
		}
		for _, id := range ids {
			if err := r.settle(ctx, q, t, id); err != nil {
				return err
			}
		}
		// Re-drive queued/running operations with planned work and no recent progress.
		ids, err = scanIDs(q.Query(ctx, `SELECT o.id::text FROM public.operations o WHERE o.tenant_id = $1::uuid AND o.state IN ('queued', 'running')
AND o.updated_at < now() - $2 * interval '1 millisecond'
AND EXISTS (SELECT 1 FROM public.operation_items i WHERE i.tenant_id = o.tenant_id AND i.operation_id = o.id AND i.state = 'planned')
AND NOT EXISTS (SELECT 1 FROM public.operation_steps s WHERE s.tenant_id = o.tenant_id AND s.operation_id = o.id
  AND (s.state = 'applying' OR s.updated_at >= now() - $2 * interval '1 millisecond'))`, t.String(), r.cfg.StallWindow.Milliseconds()))
		if err != nil {
			return err
		}
		for _, id := range ids {
			op, err := loadOp(ctx, q, t, id, false)
			if err != nil {
				return err
			}
			if err := r.enqueueNextPhase(ctx, q, t, op); err != nil {
				return err
			}
		}
		// Deferred read-backs.
		ids, err = scanIDs(q.Query(ctx, `SELECT DISTINCT operation_id::text FROM public.operation_steps WHERE tenant_id = $1::uuid AND state = 'applied'`, t.String()))
		if err != nil {
			return err
		}
		for _, id := range ids {
			if r.cfg.Jobs != nil {
				if _, err := r.cfg.Jobs.Enqueue(ctx, q, jobs.Job{Kind: JobVerify, Tenant: t, Args: verifyArgs{Operation: id}, UniqueKey: id}); err != nil {
					return err
				}
			}
		}
		// Abandon plans nobody submitted or approved.
		ids, err = scanIDs(q.Query(ctx, `SELECT id::text FROM public.operations WHERE tenant_id = $1::uuid AND state IN ('planned', 'awaiting_approval', 'approved')
AND updated_at < now() - $2 * interval '1 millisecond'`, t.String(), r.cfg.AbandonAfter.Milliseconds()))
		if err != nil {
			return err
		}
		for _, id := range ids {
			op, err := loadOp(ctx, q, t, id, true)
			if err != nil {
				return err
			}
			if err := r.cancelPlanned(ctx, q, t, id); err != nil {
				return err
			}
			if err := setOperationState(ctx, q, t, id, op.State, OpCancelled); err != nil {
				return err
			}
			if err := r.emit(ctx, q, audit.Event{ID: "op-" + id + "-abandoned", Kind: KindOperationCancelled, Actor: op.Chain,
				Key: step.Key{Operation: step.OperationID(id)}, Outcome: audit.Success, Reason: "abandoned", PlanHash: op.PlanHash}); err != nil {
				return err
			}
		}
		// Expired secrets and secrets of finished operations.
		_, err = q.Exec(ctx, `DELETE FROM public.operation_secrets s WHERE s.tenant_id = $1::uuid AND (s.expires_at <= now() OR EXISTS (
SELECT 1 FROM public.operations o WHERE o.tenant_id = s.tenant_id AND o.id = s.operation_id
AND o.state IN ('no_change', 'plan_failed', 'rejected', 'succeeded', 'partially_succeeded', 'failed', 'cancelled')))`, t.String())
		return err
	})
}

// scanIDs reads the first column of every row as text; the caller passes the constant query's result.
type idRows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
	Err() error
}

func scanIDs(rows idRows, err error) ([]string, error) {
	if err != nil {
		return nil, fmt.Errorf("operation: sweep query: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
