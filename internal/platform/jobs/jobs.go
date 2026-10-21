// Package jobs is the job queue of ADR-0001 erratum E3 and the ADR-0002 Jobs row (DM-43): a
// PostgreSQL table claimed with SELECT … FOR UPDATE SKIP LOCKED, owned by this package. It owns the
// registered-global table public.jobs, so only SQL in this package may name it (fitness-tenancy T5).
//
// The package is the queue primitive. Every access goes through the store package's two entry points, so
// no pool or pgx transaction leaves store:
//
//	Enqueue / Cancel            in the caller's own store.Tx, whose tenant context the database compares
//	                            with the job: the jobs_guard trigger (migration 0002) refuses a job for
//	                            any other tenant, so a bug in a caller cannot enqueue across tenants.
//	Claim / Rescue / Clean      each one registered store.WithPlatform site, the only cross-tenant reads.
//	Complete / Fail / Discard   record an outcome in a store.Tx and are fenced on id, attempt,
//	/ Renew                     state = running and the transaction's tenant, so a superseded run
//	                            changes nothing (DM-43 I4).
//
// A job is never the system of record (DM-43 I1): the domain record is, and a lost job is re-derived from
// it. Arguments are typed references, at most 4 KiB, never personal values, secrets or error text, and a
// failure is stored as a code.
//
// Not here: the kind registry and the wrapper that turns a claimed job into a tenant transaction
// (WithTenant, or a ManagedTx runner), the leases that make Rescue and Clean singleton (DM-06),
// schedules (DM-44), and the per-tenant quota and claim fairness that must exist before the saas
// profile hosts a second tenant (T-0214).
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Limits. The same bounds are CHECK constraints in migration 0002.
const (
	MaxArgsBytes       = 4096
	DefaultMaxAttempts = 5
	maxMaxAttempts     = 100
	maxUniqueKeyLen    = 200
	maxLease           = 24 * time.Hour
	maxBatch           = 1000
)

// sqlstateGuard is the SQLSTATE the jobs_guard trigger raises. It is in the product's own class (AD).
const sqlstateGuard = "AD403"

// Errors. None carries SQL text, arguments or a connection string.
var (
	// ErrCrossTenant is returned when the database refused a job whose tenant differs from the
	// transaction's tenant context, or an update of what a job is (jobs_guard).
	ErrCrossTenant = errors.New("jobs: the job's tenant differs from the transaction's tenant context")
	// ErrSuperseded is returned when an outcome is recorded for a job that is no longer running under
	// that attempt, in that tenant: the claim lapsed and was rescued or re-claimed, or the job is another
	// tenant's. Nothing changed.
	ErrSuperseded = errors.New("jobs: the claim was superseded; nothing recorded")
	// ErrNotCancellable is returned by Cancel for a job that is not available in the context's tenant.
	ErrNotCancellable = errors.New("jobs: no available job with that id in this tenant")
	// ErrInvalid is wrapped by every refusal of malformed input; no SQL ran.
	ErrInvalid = errors.New("jobs: invalid input")
)

var (
	kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,99}$`)
	codePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Job is one unit of work to enqueue.
type Job struct {
	// Kind names the registered job kind, such as "operation.apply": lower case, digits, '_' and '.'.
	Kind string
	// Tenant is the tenant the job runs for. The zero value means a platform job, which must be enqueued
	// in a transaction with no tenant context (store.WithPlatform) and be a registered platform kind.
	Tenant tenant.ID
	// Args is encoded as a JSON object holding typed references. Enqueue records the tenant in it as
	// "tenant_id" (it may be present, and must then equal Tenant); a platform job's args carry none.
	Args any
	// UniqueKey, when set, de-duplicates among available and running jobs of the same tenant and kind
	// (DM-43 I5). It never decides correctness.
	UniqueKey string
	// RunAt delays the first attempt; zero means now (the database clock).
	RunAt time.Time
	// MaxAttempts is the number of attempts before the job is discarded; 0 means DefaultMaxAttempts.
	MaxAttempts int
	// Priority orders the claim: lower runs first.
	Priority int16
}

// Enqueued is the result of Enqueue.
type Enqueued struct {
	ID int64
	// Duplicate is true when an available or running job with the same tenant, kind and UniqueKey already
	// exists. Nothing was inserted and ID is zero.
	Duplicate bool
}

const insertJob = `INSERT INTO public.jobs (tenant_id, kind, args, unique_key, priority, max_attempts, run_at)
VALUES ($1::uuid, $2, $3::jsonb, $4, $5, $6, COALESCE($7::timestamptz, now()))
ON CONFLICT (tenant_id, kind, unique_key) WHERE unique_key IS NOT NULL AND state IN ('available', 'running') DO NOTHING
RETURNING id`

// Enqueue inserts the job in the caller's transaction, so it commits or rolls back with the caller's
// own writes. The database refuses (ErrCrossTenant) a job whose tenant is not the transaction's tenant
// context.
func Enqueue(ctx context.Context, tx store.Tx, j Job) (Enqueued, error) {
	args, err := j.encodeArgs()
	if err != nil {
		return Enqueued{}, err
	}
	var tenantArg, keyArg, runAtArg any
	if !j.Tenant.IsZero() {
		tenantArg = j.Tenant.String()
	}
	if j.UniqueKey != "" {
		keyArg = j.UniqueKey
	}
	if !j.RunAt.IsZero() {
		runAtArg = j.RunAt
	}
	max := j.MaxAttempts
	if max == 0 {
		max = DefaultMaxAttempts
	}
	var id int64
	err = tx.QueryRow(ctx, insertJob, tenantArg, j.Kind, args, keyArg, j.Priority, max, runAtArg).Scan(&id)
	switch {
	case err == nil:
		return Enqueued{ID: id}, nil
	case store.IsNoRows(err):
		return Enqueued{Duplicate: true}, nil
	}
	return Enqueued{}, mapErr("enqueue", err)
}

func (j Job) encodeArgs() (string, error) {
	switch {
	case !kindPattern.MatchString(j.Kind):
		return "", invalid("kind %q is not lower-case letters, digits, '_' and '.' starting with a letter (at most 100)", j.Kind)
	case j.MaxAttempts < 0 || j.MaxAttempts > maxMaxAttempts:
		return "", invalid("max attempts %d is outside 1..%d", j.MaxAttempts, maxMaxAttempts)
	case len(j.UniqueKey) > maxUniqueKeyLen:
		return "", invalid("unique key longer than %d bytes", maxUniqueKeyLen)
	}
	obj := map[string]json.RawMessage{}
	if j.Args != nil {
		b, err := json.Marshal(j.Args)
		if err != nil {
			return "", invalid("args cannot be encoded: %v", err)
		}
		if err := json.Unmarshal(b, &obj); err != nil || obj == nil {
			return "", invalid("args must encode as a JSON object")
		}
	}
	if j.Tenant.IsZero() {
		if _, ok := obj["tenant_id"]; ok {
			return "", invalid("a platform job's args carry no tenant_id")
		}
	} else {
		want, _ := json.Marshal(j.Tenant.String())
		if have, ok := obj["tenant_id"]; ok && string(have) != string(want) {
			return "", fmt.Errorf("%w: args name a different tenant than the job", ErrCrossTenant)
		}
		obj["tenant_id"] = want
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return "", invalid("args cannot be encoded: %v", err)
	}
	if len(b) > MaxArgsBytes {
		return "", invalid("args are %d bytes; at most %d (arguments are typed references, not data)", len(b), MaxArgsBytes)
	}
	return string(b), nil
}

const cancelJob = `UPDATE public.jobs SET state = 'cancelled', finalized_at = now(), updated_at = now()
WHERE id = $1 AND state = 'available' AND tenant_id IS NOT DISTINCT FROM NULLIF(current_setting('app.tenant_id', true), '')::uuid`

// Cancel cancels an available job of the transaction's tenant. A running job is not cancelled here: its
// domain record says so and the body stops (DM-43 I1).
func Cancel(ctx context.Context, tx store.Tx, id int64) error {
	tag, err := tx.Exec(ctx, cancelJob, id)
	if err != nil {
		return mapErr("cancel", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotCancellable
	}
	return nil
}

// mapErr turns the guard's refusal into ErrCrossTenant and wraps anything else without echoing SQL.
func mapErr(op string, err error) error {
	if store.SQLState(err) == sqlstateGuard {
		return ErrCrossTenant
	}
	return fmt.Errorf("jobs: %s: %w", op, err)
}
