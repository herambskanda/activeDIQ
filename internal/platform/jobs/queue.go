package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Ref names one claim: a job and the attempt that holds it. Every recording is fenced on both.
type Ref struct {
	ID      int64
	Attempt int
}

// Claimed is a job a worker now holds until ClaimedUntil.
type Claimed struct {
	Ref
	Kind string
	// Tenant is the tenant the body must run in; the zero value is a platform job.
	Tenant      tenant.ID
	Args        json.RawMessage
	MaxAttempts int
	// ClaimedUntil is the database-clock time the claim lapses; Renew extends it.
	ClaimedUntil time.Time
}

// KindLease is one kind a worker will run and how long its claim lasts: the kind's timeout plus a grace.
type KindLease struct {
	Kind  string
	Lease time.Duration
}

// claim is one statement: pick runnable jobs of the offered kinds in order, skipping rows other workers
// hold, and mark them running with a new attempt and a lease on the database clock.
const claim = `WITH picked AS (
  SELECT j.id, k.lease_ms
  FROM public.jobs j JOIN unnest($1::text[], $2::bigint[]) AS k (kind, lease_ms) ON k.kind = j.kind
  WHERE j.state = 'available' AND j.run_at <= now() AND j.attempt < j.max_attempts
  ORDER BY j.priority, j.run_at, j.id
  LIMIT $3
  FOR UPDATE OF j SKIP LOCKED)
UPDATE public.jobs j SET state = 'running', attempt = j.attempt + 1,
  claimed_until = now() + picked.lease_ms * interval '1 millisecond', updated_at = now()
FROM picked WHERE j.id = picked.id
RETURNING j.id, j.attempt, j.kind, j.tenant_id::text, j.args, j.max_attempts, j.claimed_until`

// Claim takes up to limit runnable jobs of the offered kinds, for any tenant. It is the one registered
// platform-scope read of the queue (ADR-0002 Jobs row); the caller then runs each body in the job's own
// tenant. A job with no attempts left is never claimed (Fail and Rescue discard it).
func Claim(ctx context.Context, db *store.DB, kinds []KindLease, limit int) ([]Claimed, error) {
	if limit < 1 || limit > maxBatch {
		return nil, invalid("claim limit %d is outside 1..%d", limit, maxBatch)
	}
	if len(kinds) == 0 {
		return nil, invalid("claim needs at least one kind")
	}
	names := make([]string, len(kinds))
	leases := make([]int64, len(kinds))
	for i, k := range kinds {
		if !kindPattern.MatchString(k.Kind) {
			return nil, invalid("kind %q is not a valid job kind", k.Kind)
		}
		if k.Lease <= 0 || k.Lease > maxLease {
			return nil, invalid("lease for %q must be positive and at most %s", k.Kind, maxLease)
		}
		names[i], leases[i] = k.Kind, k.Lease.Milliseconds()
	}
	var out []Claimed
	err := db.WithPlatform(ctx, "jobs: claim runnable jobs", func(ctx context.Context, tx store.Tx) error {
		out = nil
		rows, err := tx.Query(ctx, claim, names, leases, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Claimed
			var tid *string
			if err := rows.Scan(&c.ID, &c.Attempt, &c.Kind, &tid, &c.Args, &c.MaxAttempts, &c.ClaimedUntil); err != nil {
				return err
			}
			if tid != nil {
				id, err := tenant.Parse(*tid)
				if err != nil {
					return fmt.Errorf("a job row holds an invalid tenant id: %w", err)
				}
				c.Tenant = id
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, mapErr("claim", err)
	}
	return out, nil
}

// The recordings below run in the body's own transaction (default-mode kinds), or in a short one of a
// ManagedTx body. Each is fenced on the job id, the attempt, state = running and the transaction's tenant
// (null for a platform job in a platform transaction).
const fence = `WHERE id = $1 AND attempt = $2 AND state = 'running'
  AND tenant_id IS NOT DISTINCT FROM NULLIF(current_setting('app.tenant_id', true), '')::uuid`

const complete = `UPDATE public.jobs SET state = 'completed', claimed_until = NULL, error_code = NULL,
  finalized_at = now(), updated_at = now() ` + fence

const fail = `UPDATE public.jobs SET
  state = CASE WHEN attempt >= max_attempts THEN 'discarded' ELSE 'available' END,
  run_at = CASE WHEN attempt >= max_attempts THEN run_at ELSE now() + $4 * interval '1 millisecond' END,
  finalized_at = CASE WHEN attempt >= max_attempts THEN now() END,
  claimed_until = NULL, error_code = $3, updated_at = now() ` + fence + ` RETURNING state`

const discard = `UPDATE public.jobs SET state = 'discarded', claimed_until = NULL, error_code = $3,
  finalized_at = now(), updated_at = now() ` + fence

const renew = `UPDATE public.jobs SET claimed_until = now() + $3 * interval '1 millisecond', updated_at = now() ` + fence

// Complete records success.
func Complete(ctx context.Context, tx store.Tx, r Ref) error {
	tag, err := tx.Exec(ctx, complete, r.ID, r.Attempt)
	return one("complete", tag.RowsAffected, err)
}

// Discard records a permanent failure: the job will not run again. code is a short snake_case code,
// never error text.
func Discard(ctx context.Context, tx store.Tx, r Ref, code string) error {
	if !codePattern.MatchString(code) {
		return invalid("error code %q is not a snake_case code", code)
	}
	tag, err := tx.Exec(ctx, discard, r.ID, r.Attempt, code)
	return one("discard", tag.RowsAffected, err)
}

// Renew extends the claim of a long-running body by lease, measured from now on the database clock.
func Renew(ctx context.Context, tx store.Tx, r Ref, lease time.Duration) error {
	if lease <= 0 || lease > maxLease {
		return invalid("lease must be positive and at most %s", maxLease)
	}
	tag, err := tx.Exec(ctx, renew, r.ID, r.Attempt, lease.Milliseconds())
	return one("renew", tag.RowsAffected, err)
}

// one maps the result of a fenced single-row recording: exactly one row must have been affected.
func one(op string, rows func() int64, err error) error {
	if err != nil {
		return mapErr(op, err)
	}
	if rows() != 1 {
		return ErrSuperseded
	}
	return nil
}

// Outcome is what Fail did with the job.
type Outcome string

const (
	// Retried: the job is available again after the backoff.
	Retried Outcome = "retried"
	// Exhausted: that was the last attempt; the job is discarded.
	Exhausted Outcome = "exhausted"
)

// Fail records a failed attempt. The job is retried after backoff (see Backoff), or discarded when that
// was its last attempt. code is a short snake_case code, never error text.
func Fail(ctx context.Context, tx store.Tx, r Ref, code string, backoff time.Duration) (Outcome, error) {
	if !codePattern.MatchString(code) {
		return "", invalid("error code %q is not a snake_case code", code)
	}
	if backoff < 0 || backoff > maxLease {
		return "", invalid("backoff must be between 0 and %s", maxLease)
	}
	var state string
	if err := tx.QueryRow(ctx, fail, r.ID, r.Attempt, code, backoff.Milliseconds()).Scan(&state); err != nil {
		if store.IsNoRows(err) {
			return "", ErrSuperseded
		}
		return "", mapErr("fail", err)
	}
	if state == "discarded" {
		return Exhausted, nil
	}
	return Retried, nil
}

// Backoff is the default retry delay after the given attempt (1-based): 5 s, doubling, capped at 1 h.
func Backoff(attempt int) time.Duration {
	const base, ceiling = 5 * time.Second, time.Hour
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 16 { // avoids overflow; 5 s << 11 already exceeds the cap
		return ceiling
	}
	return min(base<<(attempt-1), ceiling)
}

const rescue = `WITH lapsed AS (
  SELECT id FROM public.jobs WHERE state = 'running' AND claimed_until < now()
  ORDER BY claimed_until LIMIT $1 FOR UPDATE SKIP LOCKED)
UPDATE public.jobs j SET
  state = CASE WHEN j.attempt >= j.max_attempts THEN 'discarded' ELSE 'available' END,
  run_at = now(),
  finalized_at = CASE WHEN j.attempt >= j.max_attempts THEN now() END,
  claimed_until = NULL, error_code = 'claim_lapsed', updated_at = now()
FROM lapsed WHERE j.id = lapsed.id RETURNING j.state`

// Rescued counts what Rescue did.
type Rescued struct{ Requeued, Discarded int }

// Rescue re-queues running jobs whose claim lapsed (a crashed worker), and discards those with no
// attempts left. It handles at most limit jobs per call and is a registered platform-scope site; the
// caller runs it as a singleton under a platform lease (DM-06).
func Rescue(ctx context.Context, db *store.DB, limit int) (Rescued, error) {
	if limit < 1 || limit > maxBatch {
		return Rescued{}, invalid("rescue limit %d is outside 1..%d", limit, maxBatch)
	}
	var out Rescued
	err := db.WithPlatform(ctx, "jobs: rescue lapsed claims", func(ctx context.Context, tx store.Tx) error {
		out = Rescued{}
		rows, err := tx.Query(ctx, rescue, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var state string
			if err := rows.Scan(&state); err != nil {
				return err
			}
			if state == "discarded" {
				out.Discarded++
			} else {
				out.Requeued++
			}
		}
		return rows.Err()
	})
	if err != nil {
		return Rescued{}, mapErr("rescue", err)
	}
	return out, nil
}

const clean = `DELETE FROM public.jobs WHERE id IN (
  SELECT id FROM public.jobs WHERE finalized_at < now() - $1 * interval '1 millisecond'
  ORDER BY finalized_at LIMIT $2 FOR UPDATE SKIP LOCKED)`

// Clean deletes at most limit completed, cancelled and discarded jobs finished longer ago than retention
// and returns how many. It is a registered platform-scope site, run as a singleton under a lease.
func Clean(ctx context.Context, db *store.DB, retention time.Duration, limit int) (int64, error) {
	if retention < 0 {
		return 0, invalid("retention must not be negative")
	}
	if limit < 1 || limit > maxBatch {
		return 0, invalid("clean limit %d is outside 1..%d", limit, maxBatch)
	}
	var n int64
	err := db.WithPlatform(ctx, "jobs: clean finished jobs", func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, clean, retention.Milliseconds(), limit)
		n = tag.RowsAffected()
		return err
	})
	if err != nil {
		return 0, mapErr("clean", err)
	}
	return n, nil
}
