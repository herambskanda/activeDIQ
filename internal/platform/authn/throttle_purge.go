package authn

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// JobPurgeThrottle is the job kind that deletes a tenant's dead AN-8 throttle rows (T-0868). A row is
// only replaced when its own key returns, and a key made of a one-off submitted name never does, so
// without this job the table grows by one row per distinct name ever submitted.
const JobPurgeThrottle = "authn.throttle.purge"

const (
	// ThrottlePurgeMargin is how long past ThrottleWindow a row is kept before it is deleted. The window
	// is judged by the sign-in path's own clock; the margin keeps the purge from racing a row that a
	// slightly-behind node still treats as live.
	ThrottlePurgeMargin = 5 * time.Minute
	// ThrottlePurgeInterval is the cadence of the purge job.
	ThrottlePurgeInterval = 10 * time.Minute

	// CodeThrottlePurgeFailed and CodeBadArgs are the stored failure codes of the job.
	CodeThrottlePurgeFailed = "throttle_purge_failed"
	CodeBadArgs             = "bad_args"
)

// sqlPurgeThrottle deletes the tenant's rows whose window ended before $2 and whose not_before delay has
// passed ($3): a key still inside its delay is live whatever its window says. RLS also binds the tenant.
const sqlPurgeThrottle = `DELETE FROM public.authn_signin_throttle
WHERE tenant_id = $1::uuid AND window_start < $2 AND not_before < $3`

// PurgeThrottle deletes the tenant's throttle rows that are past ThrottleWindow plus ThrottlePurgeMargin
// and no longer delayed, in the caller's tenant transaction, and returns how many it deleted. Rows of any
// other tenant are out of reach: the statement names t and row-level security binds the transaction.
func (l *LocalCredentials) PurgeThrottle(ctx context.Context, tx store.Tx, t tenant.ID) (int, error) {
	if t.IsZero() {
		return 0, ErrInvalid
	}
	now := l.now()
	tag, err := tx.Exec(ctx, sqlPurgeThrottle, t.String(), now.Add(-ThrottleWindow-ThrottlePurgeMargin), now)
	if err != nil {
		return 0, fmt.Errorf("authn: purge throttle rows: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ThrottleJobs registers and schedules authn.throttle.purge.
type ThrottleJobs struct {
	reg   *jobs.Registry
	creds *LocalCredentials
	every time.Duration
}

// RegisterThrottleJobs registers authn.throttle.purge in reg. every is the cadence (zero takes
// ThrottlePurgeInterval).
func RegisterThrottleJobs(reg *jobs.Registry, creds *LocalCredentials, every time.Duration) (*ThrottleJobs, error) {
	if reg == nil || creds == nil {
		return nil, errors.New("authn: throttle purge needs a job registry and the local credentials")
	}
	if every == 0 {
		every = ThrottlePurgeInterval
	}
	if every < time.Second {
		return nil, errors.New("authn: throttle purge interval is too short")
	}
	j := &ThrottleJobs{reg: reg, creds: creds, every: every}
	err := reg.Register(jobs.Kind{Name: JobPurgeThrottle, Timeout: 2 * time.Minute, Mode: jobs.ModeManagedTx,
		ValidateArgs: purgeArgs, RunManaged: j.run})
	if err != nil {
		return nil, fmt.Errorf("authn: registering job kind: %w", err)
	}
	return j, nil
}

// purgeArgs: the job carries no arguments but the tenant, which Enqueue records.
func purgeArgs(raw jsontext.Value) error {
	var m map[string]jsontext.Value
	if err := json.Unmarshal(raw, &m); err != nil {
		return errors.New("args are not an object")
	}
	delete(m, "tenant_id")
	if len(m) != 0 {
		return errors.New("args do not match the kind")
	}
	return nil
}

// Schedule starts the tenant's purge cadence in the caller's tenant transaction (the boot-time seed). It
// is idempotent: a run already queued for the current interval is left alone, and the job's own
// successor lands in the same buckets, so a second start converges. The first run is immediate.
func (j *ThrottleJobs) Schedule(ctx context.Context, tx store.Tx, id tenant.ID) error {
	return j.enqueue(ctx, tx, id, time.Now(), true)
}

// enqueue queues the run for the interval bucket containing at. A successor waits for its bucket to open.
func (j *ThrottleJobs) enqueue(ctx context.Context, tx store.Tx, id tenant.ID, at time.Time, seed bool) error {
	bucket := at.UnixNano() / int64(j.every)
	job := jobs.Job{Kind: JobPurgeThrottle, Tenant: id, MaxAttempts: 1, UniqueKey: fmt.Sprintf("t%d", bucket)}
	if !seed {
		job.RunAt = time.Unix(0, bucket*int64(j.every))
	}
	_, err := j.reg.Enqueue(ctx, tx, job)
	return err
}

func (j *ThrottleJobs) run(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
	if err := purgeArgs(c.Args); err != nil {
		return &jobs.Failure{Code: CodeBadArgs, Permanent: true, Err: err}
	}
	// The successor is queued first, so nothing below can stop the cadence.
	if err := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		return j.enqueue(ctx, tx, c.Tenant, time.Now().Add(j.every), false)
	}); err != nil {
		return &jobs.Failure{Code: CodeThrottlePurgeFailed, Err: err}
	}
	var n int
	err := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		var err error
		n, err = j.creds.PurgeThrottle(ctx, tx, c.Tenant)
		return err
	})
	if err != nil {
		return &jobs.Failure{Code: CodeThrottlePurgeFailed, Err: err}
	}
	if n > 0 {
		slog.Info("authn: purged dead sign-in throttle rows", "tenant", c.Tenant.String(), "deleted", n)
	}
	return nil
}
