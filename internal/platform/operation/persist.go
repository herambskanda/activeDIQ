package operation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// This file is the only place that writes the state columns of the pipeline's tables (ADR-0005 rule 3:
// "only the transition function writes a state"). Every state change names its kind and edge, is
// checked against the table in transitions.go first, and is a compare-and-set on the current state
// (and, for a step, on the fencing attempt), so a late or superseded writer changes nothing.

// Audit kinds of the pipeline's own events. The operation package owns them (ADR-0005 rule 1).
const (
	KindOperationStarted   audit.Kind = "operation.started"
	KindOperationCompleted audit.Kind = "operation.completed"
	KindOperationHeld      audit.Kind = "operation.held"
	KindOperationApproved  audit.Kind = "operation.approved"
	KindOperationRejected  audit.Kind = "operation.rejected"
	KindOperationCancelled audit.Kind = "operation.cancelled"
)

// Errors of persistence.
var (
	// ErrConflict is returned when a compare-and-set found the row in another state than expected.
	ErrConflict = errors.New("operation: state changed concurrently")
	// ErrNotFound is returned for an operation that does not exist in the tenant.
	ErrNotFound = errors.New("operation: not found")
)

// opRecord is one row of operations.
type opRecord struct {
	ID           string
	Action       ActionID
	Version      int
	Origin       string
	Chain        authority.Chain
	State        OperationState
	PlanHash     string
	Revision     int
	ValidUntil   *time.Time
	Pins         authority.Pins
	Input        []byte
	Hold         HoldReason
	RequestRef   string
	MaxObjects   int
	StepUpFresh  bool
	ApprovedBy   string
	ApprovedHash string
	ChunkSize    int
}

type chainJSON struct {
	Via []authority.Principal `json:"via"`
}

const opColumns = `id::text, action_id, action_version, origin, requester_id, requester_kind, via, state,
  COALESCE(plan_hash, ''), plan_revision, plan_valid_until, pins, input, COALESCE(hold_reason, ''),
  COALESCE(request_ref, ''), COALESCE(max_objects, 0), step_up_fresh, COALESCE(approved_by, ''),
  COALESCE(approved_plan_hash, ''), chunk_size`

const selectOp = `SELECT ` + opColumns + ` FROM public.operations WHERE tenant_id = $1::uuid AND id = $2::uuid`
const selectOpLocked = selectOp + ` FOR UPDATE`

func scanOp(row interface{ Scan(...any) error }) (opRecord, error) {
	var o opRecord
	var via, pins []byte
	var kind, state, action, hold string
	err := row.Scan(&o.ID, &action, &o.Version, &o.Origin, &o.Chain.Requester.ID, &kind, &via, &state,
		&o.PlanHash, &o.Revision, &o.ValidUntil, &pins, &o.Input, &hold, &o.RequestRef, &o.MaxObjects,
		&o.StepUpFresh, &o.ApprovedBy, &o.ApprovedHash, &o.ChunkSize)
	if err != nil {
		if store.IsNoRows(err) {
			return opRecord{}, ErrNotFound
		}
		return opRecord{}, fmt.Errorf("operation: reading operation: %w", err)
	}
	o.Action, o.State, o.Hold = ActionID(action), OperationState(state), HoldReason(hold)
	o.Chain.Requester.Kind = authority.PrincipalKind(kind)
	if err := json.Unmarshal(via, &o.Chain.Via); err != nil {
		return opRecord{}, fmt.Errorf("operation: corrupt initiator chain: %w", err)
	}
	if err := json.Unmarshal(pins, &o.Pins); err != nil {
		return opRecord{}, fmt.Errorf("operation: corrupt pins: %w", err)
	}
	return o, nil
}

func loadOp(ctx context.Context, tx store.Tx, t tenant.ID, id string, lock bool) (opRecord, error) {
	if lock {
		return scanOp(tx.QueryRow(ctx, selectOpLocked, t.String(), id))
	}
	return scanOp(tx.QueryRow(ctx, selectOp, t.String(), id))
}

// setOperationState is the transition function of the Operation machine: it checks the edge, then
// compare-and-sets the state. Extra columns that belong to the edge are written by the same statement
// through the caller's SET clause (a fixed fragment, never caller text).
func setOperationState(ctx context.Context, tx store.Tx, t tenant.ID, id string, from, to OperationState) error {
	if err := Transition(KindOperation, string(from), string(to)); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.operations SET state = $4, updated_at = now()
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = $3`, t.String(), id, string(from), string(to))
	if err != nil {
		return fmt.Errorf("operation: transition: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// setItemState is the transition function of the OperationItem machine.
func setItemState(ctx context.Context, tx store.Tx, t tenant.ID, op string, item int, from, to ItemState, reason string) error {
	if err := Transition(KindItem, string(from), string(to)); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.operation_items SET state = $5, reason = NULLIF($6, ''), updated_at = now()
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND item_no = $3 AND state = $4`,
		t.String(), op, item, string(from), string(to), reason)
	if err != nil {
		return fmt.Errorf("operation: item transition: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// recordStep is the transition function of the Step machine for every edge that leaves `applying`
// (and `applied`): predicated on the state and the fencing attempt, so a late result from a
// superseded attempt changes nothing. It reports whether this attempt still owned the step.
func recordStep(ctx context.Context, tx store.Tx, t tenant.ID, k step.Key, attempt int, from, to StepState, reason string, recovered bool, outcome []byte) (bool, error) {
	if err := Transition(KindStep, string(from), string(to)); err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.operation_steps SET state = $7, reason = NULLIF($8, ''),
  recovered = recovered OR $9, outcome = COALESCE($10::jsonb, outcome), claimed_until = NULL, updated_at = now()
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND item_no = $3 AND step_no = $4
  AND state = $5 AND attempt = $6`,
		t.String(), string(k.Operation), k.Item, k.Step, string(from), attempt, string(to), reason, recovered, nullJSON(outcome))
	if err != nil {
		return false, fmt.Errorf("operation: recording step: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// setStepNotRun moves the still-planned steps of an item (or of the operation, item < 0) to not_run.
func setStepNotRun(ctx context.Context, tx store.Tx, t tenant.ID, op string, item int) error {
	if err := Transition(KindStep, string(StepPlanned), string(StepNotRun)); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE public.operation_steps SET state = 'not_run', updated_at = now()
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND state = 'planned' AND ($3 < 0 OR item_no = $3)`,
		t.String(), op, item)
	if err != nil {
		return fmt.Errorf("operation: not_run: %w", err)
	}
	return nil
}

func nullJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

// emit appends a pipeline event inside tx.
func (r *Runner) emit(ctx context.Context, tx store.Tx, ev audit.Event) error {
	ev.At = r.cfg.Now()
	ev.Component = r.cfg.Component
	return r.cfg.Audit.Append(ctx, tx, ev)
}

func detail(kv ...any) []audit.Detail {
	// kv is key, value pairs in strictly increasing key order.
	var out []audit.Detail
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, audit.Detail{Key: kv[i].(string), Value: fmt.Sprint(kv[i+1])})
	}
	return out
}

// claimStep is the planned -> applying edge: attempt + 1 and a lease on the database clock (rule 6).
// It returns the new attempt and the claim time.
func claimStep(ctx context.Context, tx store.Tx, t tenant.ID, k step.Key, lease time.Duration) (int, time.Time, error) {
	if err := Transition(KindStep, string(StepPlanned), string(StepApplying)); err != nil {
		return 0, time.Time{}, err
	}
	var attempt int
	var at time.Time
	err := tx.QueryRow(ctx, `UPDATE public.operation_steps SET state = 'applying', attempt = attempt + 1, claimed_at = now(),
  claimed_until = now() + $5 * interval '1 millisecond', updated_at = now()
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND item_no = $3 AND step_no = $4 AND state = 'planned'
RETURNING attempt, claimed_at`, t.String(), string(k.Operation), k.Item, k.Step, lease.Milliseconds()).Scan(&attempt, &at)
	if err != nil {
		if store.IsNoRows(err) {
			return 0, time.Time{}, ErrConflict
		}
		return 0, time.Time{}, fmt.Errorf("operation: claiming step: %w", err)
	}
	return attempt, at, nil
}

// takeoverStep gives a step that stays `applying` a new attempt: a retry after a transient error, or a
// takeover of a lapsed claim by the reconciler. It is a compare-and-set on the previous attempt, so
// only one taker wins and the superseded attempt's late result changes nothing. lapsedOnly demands the
// previous lease to have run out on the database clock. claimed_at keeps the first claim's time.
func takeoverStep(ctx context.Context, tx store.Tx, t tenant.ID, k step.Key, prev int, lease time.Duration, lapsedOnly bool) (int, error) {
	var attempt int
	err := tx.QueryRow(ctx, `UPDATE public.operation_steps SET attempt = attempt + 1,
  claimed_until = now() + $6 * interval '1 millisecond', updated_at = now()
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND item_no = $3 AND step_no = $4
  AND state = 'applying' AND attempt = $5 AND (NOT $7 OR claimed_until < now())
RETURNING attempt`, t.String(), string(k.Operation), k.Item, k.Step, prev, lease.Milliseconds(), lapsedOnly).Scan(&attempt)
	if err != nil {
		if store.IsNoRows(err) {
			return 0, ErrConflict
		}
		return 0, fmt.Errorf("operation: taking over step: %w", err)
	}
	return attempt, nil
}

// renewStep extends the lease of the attempt that still owns the step; false means it was superseded.
func renewStep(ctx context.Context, tx store.Tx, t tenant.ID, k step.Key, attempt int, lease time.Duration) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE public.operation_steps SET claimed_until = now() + $6 * interval '1 millisecond'
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND item_no = $3 AND step_no = $4
  AND state = 'applying' AND attempt = $5`, t.String(), string(k.Operation), k.Item, k.Step, attempt, lease.Milliseconds())
	if err != nil {
		return false, fmt.Errorf("operation: renewing claim: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
