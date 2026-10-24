package operation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The life of a directory step (ADR-0005 rule 6): claim in one short transaction and commit; re-check
// and write through the Action with no transaction open; record the result, with its audit event, in a
// second short transaction fenced by the attempt number.

// txFunc opens one short tenant transaction. A job body passes its TenantTx.Run, which fences on the
// job's own claim; other callers pass a closure over the database.
type txFunc func(ctx context.Context, fn func(ctx context.Context, tx store.Tx) error) error

func (r *Runner) txFor(t tenant.ID) txFunc {
	return func(ctx context.Context, fn func(ctx context.Context, tx store.Tx) error) error {
		return r.cfg.DB.WithTenant(ctx, t, fn)
	}
}

var (
	errBusy       = errors.New("operation: all write slots on the pinned DC are in use")
	errSuperseded = errors.New("operation: this attempt no longer owns the step")
)

// claimed is a step this process holds the claim of.
type claimed struct {
	op        opRecord
	act       Action
	d         Descriptor
	key       step.Key
	attempt   int
	claimedAt time.Time
	plan      StepPlan
	conn, dc  string
	cred      bool
}

func (c *claimed) event(r *Runner, o audit.Outcome, reason string, recovered bool) audit.Event {
	ev := audit.Event{ID: fmt.Sprintf("op-%s-i%d-s%d", c.key.Operation, c.key.Item, c.key.Step), Kind: c.d.AuditKind,
		Actor: c.op.Chain, Target: c.plan.Target, Key: c.key, Outcome: o, Reason: reason, PlanHash: c.op.PlanHash,
		Changes: changesOf(c.plan.Diff)}
	if recovered {
		ev.Details = detail("recovered", true)
	}
	return ev
}

// claimNext claims the next planned step of one chunk of one phase, or returns nil when none is left.
// The operation row is locked first, so a cancel and a claim serialise; SKIP LOCKED keeps two workers
// from taking the same step; the advisory lock plus the count keep the writes per (connection, DC)
// within the slot limit (rule 5).
func (r *Runner) claimNext(ctx context.Context, tx store.Tx, t tenant.ID, opID string, phase, chunk int) (*claimed, error) {
	op, err := loadOp(ctx, tx, t, opID, true)
	if err != nil {
		return nil, err
	}
	if op.State != OpQueued && op.State != OpRunning {
		return nil, nil // cancelled, cancelling or finished: nothing to claim
	}
	var item, stp int
	var plan []byte
	var conn, dc string
	var cred bool
	err = tx.QueryRow(ctx, `SELECT s.item_no, s.step_no, s.plan, s.connection_id, COALESCE(s.dc_host, ''), s.credential
FROM public.operation_steps s
JOIN public.operation_items i ON i.tenant_id = s.tenant_id AND i.operation_id = s.operation_id AND i.item_no = s.item_no
WHERE s.tenant_id = $1::uuid AND s.operation_id = $2::uuid AND s.state = 'planned' AND i.phase = $3 AND s.item_no / $4 = $5
ORDER BY s.item_no, s.step_no LIMIT 1 FOR UPDATE OF s SKIP LOCKED`, t.String(), opID, phase, op.ChunkSize, chunk).
		Scan(&item, &stp, &plan, &conn, &dc, &cred)
	if err != nil {
		if store.IsNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("operation: finding a step to claim: %w", err)
	}
	if dc != "" {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, t.String()+"|"+conn+"|"+dc); err != nil {
			return nil, fmt.Errorf("operation: slot lock: %w", err)
		}
		var busy int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.operation_steps WHERE tenant_id = $1::uuid AND state = 'applying'
AND connection_id = $2 AND dc_host = $3 AND claimed_until > now()`, t.String(), conn, dc).Scan(&busy); err != nil {
			return nil, fmt.Errorf("operation: counting slots: %w", err)
		}
		if busy >= r.cfg.Slots {
			return nil, errBusy
		}
	}
	c := &claimed{op: op, key: step.Key{Operation: step.OperationID(opID), Item: item, Step: stp}, conn: conn, dc: dc, cred: cred}
	if err := json.Unmarshal(plan, &c.plan); err != nil {
		return nil, fmt.Errorf("operation: corrupt plan: %w", err)
	}
	act, ok := r.cfg.Registry.Lookup(op.Action)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknown, op.Action)
	}
	c.act, c.d = act, act.Describe()
	if op.State == OpQueued {
		if err := setOperationState(ctx, tx, t, opID, OpQueued, OpRunning); err != nil {
			return nil, err
		}
		if err := r.emit(ctx, tx, audit.Event{ID: "op-" + opID + "-started", Kind: KindOperationStarted, Actor: op.Chain,
			Key: step.Key{Operation: step.OperationID(opID)}, Outcome: audit.Success, PlanHash: op.PlanHash}); err != nil {
			return nil, err
		}
	}
	if c.attempt, c.claimedAt, err = claimStep(ctx, tx, t, c.key, r.cfg.Lease); err != nil {
		return nil, err
	}
	if err := setItemState(ctx, tx, t, opID, item, ItemPlanned, ItemRunning, ""); err != nil {
		return nil, err
	}
	return c, nil
}

// RunChunk drives one chunk of one phase of an operation: it claims, writes and records its steps one
// after another until the chunk has none left. It is the body of operation.apply.
func (r *Runner) RunChunk(ctx context.Context, t tenant.ID, tx txFunc, a chunkArgs) error {
	idle := 0
	for ctx.Err() == nil {
		var c *claimed
		err := tx(ctx, func(ctx context.Context, q store.Tx) (err error) {
			c, err = r.claimNext(ctx, q, t, a.Operation, a.Phase, a.Chunk)
			return err
		})
		switch {
		case errors.Is(err, errBusy):
			idle++
			if idle > 600 {
				return err
			}
			r.sleep(r.cfg.Backoff)
			continue
		case err != nil:
			return err
		case c == nil:
			return tx(ctx, func(ctx context.Context, q store.Tx) error { return r.settle(ctx, q, t, a.Operation) })
		}
		idle = 0
		if err := r.execute(ctx, t, tx, c); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (r *Runner) mintFor(c *claimed, attempt int, sec secret.Secret) (step.Step, func(), error) {
	q := r.cfg.Authz.FactsQuery(c.op.Chain, c.d.Permission, c.plan.Target)
	return minter.Mint(step.Spec{
		Key: c.key, Attempt: attempt, Actor: c.op.Chain, NC: c.plan.Target.NC, Pins: c.op.Pins, Query: q, Digest: stepDigest(c.plan), Secret: sec,
		Recheck: func(ctx context.Context, f authority.Facts) error {
			return r.recheck(ctx, c.op.Chain, c.d.Permission, c.plan.Target, f)
		},
	})
}

// execute writes one claimed step and records the outcome.
func (r *Runner) execute(ctx context.Context, t tenant.ID, tx txFunc, c *claimed) error {
	var sec secret.Secret
	if c.d.SecretInput {
		err := tx(ctx, func(ctx context.Context, q store.Tx) (err error) {
			sec, err = r.takeSecret(ctx, q, t, c.key)
			return err
		})
		if errors.Is(err, ErrSecretExpired) {
			return r.record(ctx, t, tx, c, recordSpec{failed: "secret_expired"})
		}
		defer sec.Destroy()
		if err != nil {
			return err
		}
	}
	wctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	r.renewLoop(wctx, cancel, t, tx, c)
	tries := 1
	for {
		stp, revoke, err := r.mintFor(c, c.attempt, sec)
		if err != nil {
			return r.record(ctx, t, tx, c, recordSpec{failed: "mint_failed"})
		}
		out, aerr := c.act.Apply(wctx, stp, c.plan)
		revoke()
		if context.Cause(wctx) == errSuperseded {
			return nil // another attempt owns the step; this result changes nothing
		}
		switch {
		case aerr == nil:
			return r.verifyAndRecord(ctx, t, tx, c, out, false)
		case errors.Is(aerr, ErrTransient) && tries < r.cfg.Attempts:
			tries++
			r.sleep(r.backoffFor(tries))
			err := tx(ctx, func(ctx context.Context, q store.Tx) (err error) {
				c.attempt, err = takeoverStep(ctx, q, t, c.key, c.attempt, r.cfg.Lease, false)
				return err
			})
			if errors.Is(err, ErrConflict) {
				return nil
			}
			if err != nil {
				return err
			}
			continue
		case errors.Is(aerr, ErrTransient):
			return r.afterRetries(ctx, t, tx, c)
		case errors.Is(aerr, step.ErrDenied), errors.Is(aerr, ErrDenied):
			return r.record(ctx, t, tx, c, recordSpec{failed: "denied", outcome: audit.Denied})
		case errors.Is(aerr, ErrStaleState):
			return r.record(ctx, t, tx, c, recordSpec{failed: "stale_state"})
		case errors.Is(aerr, ErrOutcomeUnknown):
			return r.record(ctx, t, tx, c, recordSpec{failed: "outcome_unknown"})
		case errors.Is(aerr, ErrSecretExpired):
			return r.record(ctx, t, tx, c, recordSpec{failed: "secret_expired"})
		}
		return r.record(ctx, t, tx, c, recordSpec{failed: "apply_failed"})
	}
}

func (r *Runner) backoffFor(try int) time.Duration {
	d := r.cfg.Backoff << min(try-1, 6)
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

// renewLoop extends the claim while the write runs. If the claim was superseded it cancels the write's
// context with errSuperseded, so the attempt stops and its result is dropped.
func (r *Runner) renewLoop(ctx context.Context, cancel context.CancelCauseFunc, t tenant.ID, tx txFunc, c *claimed) {
	go func() {
		tick := time.NewTicker(r.cfg.Lease / 3)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			var owned bool
			err := tx(ctx, func(ctx context.Context, q store.Tx) (err error) {
				owned, err = renewStep(ctx, q, t, c.key, c.attempt, r.cfg.Lease)
				return err
			})
			if err == nil && !owned {
				cancel(errSuperseded)
				return
			}
		}
	}()
}

// afterRetries reads the target on the pin once the transient-error limit is spent (rule 6): the
// after-state in place means the write landed and the step is applied, not failed; the before-state
// means it did not; anything unreadable leaves the step claimed for the reconciler.
func (r *Runner) afterRetries(ctx context.Context, t tenant.ID, tx txFunc, c *claimed) error {
	obs, err := c.act.(Observer).Observe(ctx, c.op.Pins, c.plan, c.claimedAt)
	switch {
	case err != nil:
		return nil // stays applying; the lease lapses and the reconciler decides
	case obs == ObservedAfter && !c.cred:
		return r.verifyAndRecord(ctx, t, tx, c, Outcome{AlreadyApplied: true}, true)
	case obs == ObservedAfter:
		return r.verifyAndRecord(ctx, t, tx, c, Outcome{}, true)
	case obs == ObservedBefore:
		return r.record(ctx, t, tx, c, recordSpec{failed: "retries_exhausted"})
	}
	return r.record(ctx, t, tx, c, recordSpec{failed: "stale_state"})
}

// verifyAndRecord runs Verify and records applied -> verified / verify_failed, or applied alone when
// the read-back must wait (Entra, a lost DC).
func (r *Runner) verifyAndRecord(ctx context.Context, t tenant.ID, tx txFunc, c *claimed, out Outcome, recovered bool) error {
	stp, revoke, err := r.mintFor(c, c.attempt, secret.Secret{})
	if err != nil {
		return r.record(ctx, t, tx, c, recordSpec{applied: true, recovered: recovered, out: out, verifyFailed: "mint_failed"})
	}
	v, verr := c.act.Verify(ctx, stp, c.plan, out)
	revoke()
	switch {
	case errors.Is(verr, ErrDeferVerify):
		return r.record(ctx, t, tx, c, recordSpec{applied: true, recovered: recovered, out: out, deferred: true})
	case verr != nil:
		return r.record(ctx, t, tx, c, recordSpec{applied: true, recovered: recovered, out: out, verifyFailed: "verify_error"})
	case !v.OK:
		reason := v.Reason
		if reason == "" {
			reason = "verify_failed"
		}
		return r.record(ctx, t, tx, c, recordSpec{applied: true, recovered: recovered, out: out, verifyFailed: reason})
	}
	return r.record(ctx, t, tx, c, recordSpec{applied: true, recovered: recovered, out: out, verified: true})
}

// recordSpec says what to record for a step.
type recordSpec struct {
	failed       string // applying -> failed, with this reason
	outcome      audit.Outcome
	notRun       bool // applying -> not_run (a cancelled operation's step that never wrote)
	applied      bool // applying -> applied, then onward below
	verified     bool
	verifyFailed string
	deferred     bool
	recovered    bool
	out          Outcome
}

// record is the second short transaction: state, item, event and secret deletion commit together,
// fenced by the attempt. A superseded attempt records nothing.
func (r *Runner) record(ctx context.Context, t tenant.ID, tx txFunc, c *claimed, s recordSpec) error {
	rctx := context.WithoutCancel(ctx) // a recorded outcome is never lost to a shutdown
	err := tx(rctx, func(ctx context.Context, q store.Tx) error {
		return r.recordIn(ctx, q, t, c, s)
	})
	if errors.Is(err, errSuperseded) {
		return nil
	}
	return err
}

func (r *Runner) recordIn(ctx context.Context, q store.Tx, t tenant.ID, c *claimed, s recordSpec) error {
	opID := string(c.key.Operation)
	var outJSON []byte
	if s.applied {
		outJSON, _ = json.Marshal(struct{ AlreadyApplied bool }{s.out.AlreadyApplied})
	}
	own := func(from, to StepState, reason string, recovered bool, out []byte) error {
		ok, err := recordStep(ctx, q, t, c.key, c.attempt, from, to, reason, recovered, out)
		if err != nil {
			return err
		}
		if !ok {
			return errSuperseded
		}
		return nil
	}
	var item ItemState
	var ev audit.Event
	switch {
	case s.failed != "":
		if err := own(StepApplying, StepFailed, s.failed, false, nil); err != nil {
			return err
		}
		o := s.outcome
		if o == "" {
			o = audit.Failure
		}
		item, ev = ItemFailed, c.event(r, o, s.failed, false)
	case s.notRun:
		if err := own(StepApplying, StepNotRun, "cancelled", false, nil); err != nil {
			return err
		}
		item = ItemCancelled
	case s.applied:
		if err := own(StepApplying, StepApplied, "", s.recovered, outJSON); err != nil {
			return err
		}
		switch {
		case s.verified:
			if err := own(StepApplied, StepVerified, "", false, nil); err != nil {
				return err
			}
			item, ev = ItemSucceeded, c.event(r, audit.Success, "applied", s.recovered)
		case s.verifyFailed != "":
			if err := own(StepApplied, StepVerifyFailed, s.verifyFailed, false, nil); err != nil {
				return err
			}
			item, ev = ItemFailed, c.event(r, audit.Failure, s.verifyFailed, s.recovered)
		default: // deferred: the write is done; the read-back is driven later
			ev = c.event(r, audit.Success, "applied_verification_pending", s.recovered)
			ev.ID += "-pending"
		}
	}
	if item != "" {
		if err := setItemState(ctx, q, t, opID, c.key.Item, ItemRunning, item, s.failed+s.verifyFailed); err != nil {
			return err
		}
	}
	if ev.ID != "" {
		if err := r.emit(ctx, q, ev); err != nil {
			return err
		}
	}
	if item != "" {
		if err := deleteSecret(ctx, q, t, c.key); err != nil {
			return err
		}
	}
	return r.settle(ctx, q, t, opID)
}

// settle looks at the whole operation in the recording transaction and, when nothing is left to do,
// moves it to its terminal state; when a phase is done it enqueues the next one in the same
// transaction (rule 6). The sweeper calls it too, as the backstop for a lost job.
func (r *Runner) settle(ctx context.Context, q store.Tx, t tenant.ID, opID string) error {
	op, err := loadOp(ctx, q, t, opID, true)
	if err != nil {
		return err
	}
	if op.State != OpRunning && op.State != OpCancelling {
		return nil
	}
	counts := map[ItemState]int{}
	rows, err := q.Query(ctx, `SELECT state, count(*) FROM public.operation_items WHERE tenant_id = $1::uuid AND operation_id = $2::uuid GROUP BY state`, t.String(), opID)
	if err != nil {
		return fmt.Errorf("operation: counting items: %w", err)
	}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			rows.Close()
			return err
		}
		counts[ItemState(s)] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if counts[ItemRunning] > 0 {
		return nil // a step is still in flight or waiting for its read-back
	}
	ev := audit.Event{Actor: op.Chain, Key: step.Key{Operation: step.OperationID(opID)}, PlanHash: op.PlanHash}
	if op.State == OpCancelling {
		if err := r.cancelPlanned(ctx, q, t, opID); err != nil {
			return err
		}
		if err := setOperationState(ctx, q, t, opID, OpCancelling, OpCancelled); err != nil {
			return err
		}
		if err := deleteOperationSecrets(ctx, q, t, opID); err != nil {
			return err
		}
		ev.ID, ev.Kind, ev.Outcome, ev.Reason = "op-"+opID+"-cancelled", KindOperationCancelled, audit.Success, "cancelled"
		return r.emit(ctx, q, ev)
	}
	if counts[ItemPlanned] > 0 {
		return r.enqueueNextPhase(ctx, q, t, op)
	}
	bad := counts[ItemFailed] + counts[ItemBlocked]
	next := OpSucceeded
	switch {
	case bad > 0 && counts[ItemSucceeded] == 0:
		next = OpFailed
	case bad > 0:
		next = OpPartiallySucceeded
	}
	if err := setOperationState(ctx, q, t, opID, OpRunning, next); err != nil {
		return err
	}
	if err := deleteOperationSecrets(ctx, q, t, opID); err != nil {
		return err
	}
	ev.ID, ev.Kind, ev.Reason = "op-"+opID+"-completed", KindOperationCompleted, string(next)
	ev.Outcome = audit.Success
	if next != OpSucceeded {
		ev.Outcome = audit.Failure
	}
	ev.Details = detail("blocked", counts[ItemBlocked], "failed", counts[ItemFailed], "skipped", counts[ItemSkipped], "succeeded", counts[ItemSucceeded])
	return r.emit(ctx, q, ev)
}

// cancelPlanned moves every still-planned item and step of an operation to cancelled / not_run.
func (r *Runner) cancelPlanned(ctx context.Context, q store.Tx, t tenant.ID, opID string) error {
	rows, err := q.Query(ctx, `SELECT item_no FROM public.operation_items WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND state = 'planned' ORDER BY item_no`, t.String(), opID)
	if err != nil {
		return err
	}
	var items []int
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		items = append(items, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, n := range items {
		if err := setItemState(ctx, q, t, opID, n, ItemPlanned, ItemCancelled, "cancelled"); err != nil {
			return err
		}
	}
	return setStepNotRun(ctx, q, t, opID, -1)
}

// Cancel cancels an operation. Before it runs it goes straight to cancelled; while it runs it goes to
// cancelling, in-flight steps finish and are recorded, nothing new is claimed, and the last recording
// transaction completes the cancel. Only the requester may cancel.
func (r *Runner) Cancel(ctx context.Context, t tenant.ID, actor authority.Chain, opID string) (OperationState, error) {
	var final OperationState
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, q store.Tx) error {
		op, err := loadOp(ctx, q, t, opID, true)
		if err != nil {
			return err
		}
		if op.Chain.Requester.ID != actor.Requester.ID {
			return fmt.Errorf("%w: only the requester cancels an operation", ErrDenied)
		}
		ev := audit.Event{ID: "op-" + opID + "-cancel-requested", Kind: KindOperationCancelled, Actor: actor,
			Key: step.Key{Operation: step.OperationID(opID)}, Outcome: audit.Success, Reason: "cancel_requested", PlanHash: op.PlanHash}
		switch op.State {
		case OpRunning:
			if err := setOperationState(ctx, q, t, opID, OpRunning, OpCancelling); err != nil {
				return err
			}
			if err := r.emit(ctx, q, ev); err != nil {
				return err
			}
			if err := r.settle(ctx, q, t, opID); err != nil {
				return err
			}
			final = OpCancelling
			if cur, err := loadOp(ctx, q, t, opID, false); err == nil {
				final = cur.State
			}
			return nil
		case OpDraft, OpPlanning, OpPlanned, OpAwaitingApproval, OpApproved, OpQueued:
			if err := r.cancelPlanned(ctx, q, t, opID); err != nil {
				return err
			}
			if err := setOperationState(ctx, q, t, opID, op.State, OpCancelled); err != nil {
				return err
			}
			if err := deleteOperationSecrets(ctx, q, t, opID); err != nil {
				return err
			}
			ev.Reason = "cancelled"
			final = OpCancelled
			return r.emit(ctx, q, ev)
		}
		return fmt.Errorf("%w: operation is %s", ErrConflict, op.State)
	})
	return final, err
}
