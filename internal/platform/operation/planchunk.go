package operation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Chunked planning (ADR-0005 rule 6, job kind operation.plan; T-2073).
//
// An Action that implements ChunkPlanner and names more items than the operation's chunk size does not
// plan in one pass. startChunkedPlan records the item count and enqueues one operation.plan job per
// chunk. Each job plans its slice, authorises it, and commits the slice's items, steps and a row in
// operation_plan_chunks in ONE short transaction; no transaction ever holds more than one chunk. The
// record's primary key (operation, plan_revision, chunk_no) makes a re-driven chunk a no-op. The job that
// records the last chunk finalises the plan in that same transaction: it chains the chunk hashes into
// the plan hash, counts the items, moves planning -> planned | no_change | plan_failed, and then routes
// the plan like an inline one.
//
// Memory per job is the chunk plus the operation's input; the plan itself is never held whole while
// planning. A chunked re-plan never keeps an earlier approval: the blocked-set comparison an inline
// re-plan uses would need every item, so it is refused as the safe default (least privilege).

// Plan chunk job args: typed references only.
type planArgs struct {
	Operation string `json:"operation"`
	Revision  int    `json:"revision"`
	Chunk     int    `json:"chunk"`
}

// chunkCount is the number of chunks of a plan of n items.
func chunkCount(n, size int) int { return (n + size - 1) / size }

// startChunkedPlan prepares operation op (state planning) for chunked planning and enqueues its chunk
// jobs in the same transaction, so a planning operation cannot lack its jobs.
func (r *Runner) startChunkedPlan(ctx context.Context, t tenant.ID, op opRecord, n int) (Submission, error) {
	if r.cfg.Jobs == nil {
		return r.failPlan(ctx, t, op, fmt.Errorf("%w: no job registry wired", ErrInvalid))
	}
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		cur, err := loadOp(ctx, tx, t, op.ID, true)
		if err != nil {
			return err
		}
		if cur.State != OpPlanning || cur.Revision != op.Revision {
			return ErrConflict
		}
		for _, q := range []string{
			`DELETE FROM public.operation_steps WHERE tenant_id = $1::uuid AND operation_id = $2::uuid`,
			`DELETE FROM public.operation_items WHERE tenant_id = $1::uuid AND operation_id = $2::uuid`,
			`DELETE FROM public.operation_plan_chunks WHERE tenant_id = $1::uuid AND operation_id = $2::uuid`,
		} {
			if _, err := tx.Exec(ctx, q, t.String(), op.ID); err != nil {
				return fmt.Errorf("operation: clearing the plan: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE public.operations SET plan_items = $3, approved_by = NULL, approved_plan_hash = NULL, approved_at = NULL
WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), op.ID, n); err != nil {
			return fmt.Errorf("operation: starting a chunked plan: %w", err)
		}
		return r.enqueuePlanChunks(ctx, tx, t, cur, n)
	})
	if err != nil {
		return Submission{}, err
	}
	return Submission{Operation: step.OperationID(op.ID), State: OpPlanning, Items: n}, nil
}

// enqueuePlanChunks enqueues a plan job for every chunk of the revision that is not recorded yet. The
// unique key (operation, revision, phase, chunk) only de-duplicates; the chunk record is what makes a
// repeat a no-op.
func (r *Runner) enqueuePlanChunks(ctx context.Context, tx store.Tx, t tenant.ID, op opRecord, total int) error {
	rows, err := tx.Query(ctx, `SELECT chunk_no FROM public.operation_plan_chunks
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND plan_revision = $3`, t.String(), op.ID, op.Revision)
	if err != nil {
		return fmt.Errorf("operation: reading recorded chunks: %w", err)
	}
	done := map[int]bool{}
	for rows.Next() {
		var c int
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return err
		}
		done[c] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for c := 0; c < chunkCount(total, op.ChunkSize); c++ {
		if done[c] {
			continue
		}
		if _, err := r.cfg.Jobs.Enqueue(ctx, tx, jobs.Job{Kind: JobPlan, Tenant: t,
			Args:      planArgs{Operation: op.ID, Revision: op.Revision, Chunk: c},
			UniqueKey: fmt.Sprintf("%s:%d:%d:%d", op.ID, op.Revision, 0, c)}); err != nil {
			return fmt.Errorf("operation: enqueueing plan chunk: %w", err)
		}
	}
	return nil
}

// PlanChunk is the body of operation.plan: it plans, authorises and records one chunk, and finalises the
// plan when it records the last one. It is safe to run twice for the same chunk, in any order with its
// siblings, and after a crash at any point: nothing lands until the one recording transaction commits.
func (r *Runner) PlanChunk(ctx context.Context, t tenant.ID, tx txFunc, a planArgs) error {
	var op opRecord
	var total *int
	err := tx(ctx, func(ctx context.Context, q store.Tx) (err error) {
		if op, err = loadOp(ctx, q, t, a.Operation, false); err != nil {
			return err
		}
		return q.QueryRow(ctx, `SELECT plan_items FROM public.operations WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), a.Operation).Scan(&total)
	})
	if err != nil {
		return err
	}
	if total == nil || op.Revision != a.Revision {
		return nil // not a chunked plan, or a re-plan superseded this one
	}
	if op.State == OpPlanned {
		// The last chunk finalised the plan but the job that did it died before routing: route it now.
		_, err := r.route(ctx, t, op.ID)
		return err
	}
	if op.State != OpPlanning {
		return nil
	}
	n := min(op.ChunkSize, *total-a.Chunk*op.ChunkSize)
	if a.Chunk < 0 || n <= 0 {
		return &jobs.Failure{Code: "bad_chunk", Permanent: true, Err: fmt.Errorf("chunk %d of %d items", a.Chunk, *total)}
	}
	first := a.Chunk * op.ChunkSize
	act, ok := r.cfg.Registry.Lookup(op.Action)
	cp, isCP := act.(ChunkPlanner)
	if !ok || !isCP {
		return &jobs.Failure{Code: "bad_action", Permanent: true, Err: fmt.Errorf("%w: %q does not plan in chunks", ErrUnknown, op.Action)}
	}
	d := act.Describe()
	failed := func(cause error) error {
		sub, err := r.failPlan(ctx, t, op, cause)
		if sub.State == OpPlanFailed || errors.Is(err, ErrConflict) {
			return nil // the plan is failed (or no longer ours): the job has done its part
		}
		return err
	}

	var steps []StepPlan
	perr := tx(ctx, func(ctx context.Context, q store.Tx) error {
		if _, err := q.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
			return fmt.Errorf("plan transaction: %w", err)
		}
		var err error
		steps, err = cp.PlanChunk(ctx, PlanContext{Tx: q, Facts: pinnedReader{port: r.cfg.Facts, ad: d.Target == TargetAD, store: d.Target == TargetStore,
			pins: maps.Clone(op.Pins), dsas: maps.Clone(op.DSAs), tenant: t}, Pins: op.Pins}, Input(op.Input), first, n)
		return err
	})
	if perr == nil && len(steps) > n {
		perr = fmt.Errorf("%w: chunk %d of %q returned %d steps for %d items", ErrInvalid, a.Chunk, d.ID, len(steps), n)
	}
	u := &run{r: r, req: Request{Tenant: t, Actor: op.Chain, Action: op.Action, Operation: step.OperationID(op.ID)}, act: act, d: d, eventID: r.cfg.NewID()}
	if perr == nil {
		perr = u.checkPlan(steps)
	}
	if perr != nil {
		return failed(perr)
	}
	items, pins, dsas, err := r.evaluateItems(ctx, t, op, act, d, steps)
	if err != nil {
		return failed(err)
	}
	chunkHash := u.planHash

	var finalised bool
	err = tx(ctx, func(ctx context.Context, q store.Tx) error {
		finalised = false
		cur, err := loadOp(ctx, q, t, op.ID, true)
		if err != nil {
			return err
		}
		if cur.State != OpPlanning || cur.Revision != a.Revision {
			return nil // cancelled or re-planned meanwhile: the chunk does not land (rule 6)
		}
		var one int
		err = q.QueryRow(ctx, `INSERT INTO public.operation_plan_chunks (tenant_id, operation_id, plan_revision, chunk_no, items, chunk_hash)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6) ON CONFLICT DO NOTHING RETURNING 1`, t.String(), op.ID, a.Revision, a.Chunk, len(items), chunkHash).Scan(&one)
		if store.IsNoRows(err) {
			return nil // already recorded: a re-driven chunk changes nothing
		}
		if err != nil {
			return fmt.Errorf("operation: recording plan chunk: %w", err)
		}
		// One DC per naming context for the whole operation: a sibling chunk that pinned another host
		// first makes this chunk's authorisation stale, so it plans again against the stored pin.
		for nc, host := range pins {
			if prev := cur.Pins[nc]; prev != "" && prev != host {
				return &jobs.Failure{Code: "pin_changed", Err: fmt.Errorf("naming context %q pinned to another DC by a sibling chunk", nc)}
			}
		}
		merged, mergedDSA := maps.Clone(cur.Pins), maps.Clone(cur.DSAs)
		if merged == nil {
			merged, mergedDSA = authority.Pins{}, authority.DSAPins{}
		}
		maps.Copy(merged, pins)
		maps.Copy(mergedDSA, dsas)
		pinsJSON, _ := json.Marshal(merged, json.Deterministic(true))
		dsasJSON, _ := json.Marshal(mergedDSA, json.Deterministic(true))
		if _, err := q.Exec(ctx, `UPDATE public.operations SET pins = $3::jsonb, dsa_guids = $4::jsonb, updated_at = now()
WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), op.ID, string(pinsJSON), string(dsasJSON)); err != nil {
			return fmt.Errorf("operation: recording chunk pins: %w", err)
		}
		if _, err := r.insertItems(ctx, q, t, op.ID, first, items, merged, nil, 0); err != nil {
			return err
		}
		if err := r.emitRefused(ctx, q, cur, first, items, chunkHash, authority.TargetRef{}); err != nil {
			return err
		}
		var recorded int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM public.operation_plan_chunks
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND plan_revision = $3`, t.String(), op.ID, a.Revision).Scan(&recorded); err != nil {
			return err
		}
		if recorded < chunkCount(*total, cur.ChunkSize) {
			return nil
		}
		finalised = true
		return r.finalisePlan(ctx, q, t, cur, d)
	})
	if err != nil {
		return err
	}
	if finalised {
		_, err := r.route(ctx, t, op.ID) // a no_change or plan_failed plan is not planned and route leaves it
		return err
	}
	return nil
}

// finalisePlan completes a chunked plan once every chunk is recorded, in the recording transaction of
// the last one: the plan hash is the chunk hashes chained in chunk order, the counts come from the items.
func (r *Runner) finalisePlan(ctx context.Context, tx store.Tx, t tenant.ID, cur opRecord, d Descriptor) error {
	rows, err := tx.Query(ctx, `SELECT chunk_hash FROM public.operation_plan_chunks
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND plan_revision = $3 ORDER BY chunk_no`, t.String(), cur.ID, cur.Revision)
	if err != nil {
		return fmt.Errorf("operation: reading chunk hashes: %w", err)
	}
	chain := ""
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		sum := sha256.Sum256([]byte(chain + h))
		chain = hex.EncodeToString(sum[:])
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var c itemCounts
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'planned'), count(*) FILTER (WHERE state = 'skipped'),
  count(*) FILTER (WHERE state = 'blocked') FROM public.operation_items WHERE tenant_id = $1::uuid AND operation_id = $2::uuid`,
		t.String(), cur.ID).Scan(&c.planned, &c.skipped, &c.blocked); err != nil {
		return fmt.Errorf("operation: counting items: %w", err)
	}
	next, result := nextPlanState(c.planned, c.blocked)
	if _, err := tx.Exec(ctx, `UPDATE public.operations SET plan_hash = $3,
  plan_valid_until = now() + CASE WHEN $4 THEN interval '1 hour' ELSE interval '24 hours' END
WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), cur.ID, chain, d.Target != TargetStore); err != nil {
		return fmt.Errorf("operation: recording plan: %w", err)
	}
	if err := setOperationState(ctx, tx, t, cur.ID, OpPlanning, next); err != nil {
		return err
	}
	if result == "" {
		return nil
	}
	out, reason, tgt := audit.Success, result, authority.TargetRef{}
	if result == "plan_failed" {
		var f refusalFold
		brows, err := tx.Query(ctx, `SELECT COALESCE(reason, ''), target FROM public.operation_items
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND state = 'blocked' ORDER BY item_no`, t.String(), cur.ID)
		if err != nil {
			return fmt.Errorf("operation: reading blocked items: %w", err)
		}
		for brows.Next() {
			var why string
			var raw []byte
			if err := brows.Scan(&why, &raw); err != nil {
				brows.Close()
				return err
			}
			var tr authority.TargetRef
			if err := json.Unmarshal(raw, &tr); err != nil {
				brows.Close()
				return fmt.Errorf("operation: corrupt item target: %w", err)
			}
			f.add(why, tr)
		}
		brows.Close()
		if err := brows.Err(); err != nil {
			return err
		}
		out, reason, tgt = f.result()
	}
	return r.completePlan(ctx, tx, t, cur, chain, result, out, reason, tgt, c.blocked, c.skipped)
}

// redrivePlanning re-enqueues the unrecorded chunks of chunked plans that stopped making progress (a
// lost job). A chunk that is recorded is skipped, and one that is running is de-duplicated by its unique
// key; a duplicate that slips past both is a no-op at recording.
func (r *Runner) redrivePlanning(ctx context.Context, tx store.Tx, t tenant.ID) error {
	if r.cfg.Jobs == nil {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT id::text, plan_items FROM public.operations WHERE tenant_id = $1::uuid AND state = 'planning'
AND plan_items IS NOT NULL AND updated_at < now() - $2 * interval '1 millisecond'`, t.String(), r.cfg.StallWindow.Milliseconds())
	if err != nil {
		return fmt.Errorf("operation: reading stalled plans: %w", err)
	}
	type stalled struct {
		id    string
		items int
	}
	var list []stalled
	for rows.Next() {
		var s stalled
		if err := rows.Scan(&s.id, &s.items); err != nil {
			rows.Close()
			return err
		}
		list = append(list, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range list {
		op, err := loadOp(ctx, tx, t, s.id, false)
		if err != nil {
			return err
		}
		if err := r.enqueuePlanChunks(ctx, tx, t, op, s.items); err != nil {
			return err
		}
	}
	return nil
}
