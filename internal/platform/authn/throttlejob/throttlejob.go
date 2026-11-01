// Package throttlejob is the authn.throttle.purge job (T-0868): the cadence that deletes a tenant's dead
// AN-8 throttle rows through authn.LocalCredentials.PurgeThrottle. It sits above both authn and jobs
// because authn may not import jobs (ADR-0005 rule 13); compose/server registers it.
package throttlejob

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// JobPurge is the job kind that deletes a tenant's dead AN-8 throttle rows. A row is only replaced when
// its own key returns, and a key made of a one-off submitted name never does, so without this job the
// table grows by one row per distinct name ever submitted.
const JobPurge = "authn.throttle.purge"

const (
	// PurgeInterval is the cadence of the purge job.
	PurgeInterval = 10 * time.Minute

	// CodePurgeFailed and CodeBadArgs are the stored failure codes of the job.
	CodePurgeFailed = "throttle_purge_failed"
	CodeBadArgs     = "bad_args"
)

// Jobs registers and schedules authn.throttle.purge.
type Jobs struct {
	reg   *jobs.Registry
	creds *authn.LocalCredentials
	every time.Duration
}

// Register registers authn.throttle.purge in reg. every is the cadence (zero takes
// PurgeInterval).
func Register(reg *jobs.Registry, creds *authn.LocalCredentials, every time.Duration) (*Jobs, error) {
	if reg == nil || creds == nil {
		return nil, errors.New("authn: throttle purge needs a job registry and the local credentials")
	}
	if every == 0 {
		every = PurgeInterval
	}
	if every < time.Second {
		return nil, errors.New("authn: throttle purge interval is too short")
	}
	j := &Jobs{reg: reg, creds: creds, every: every}
	err := reg.Register(jobs.Kind{Name: JobPurge, Timeout: 2 * time.Minute, Mode: jobs.ModeManagedTx,
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
func (j *Jobs) Schedule(ctx context.Context, tx store.Tx, id tenant.ID) error {
	return j.enqueue(ctx, tx, id, time.Now(), true)
}

// enqueue queues the run for the interval bucket containing at. A successor waits for its bucket to open.
func (j *Jobs) enqueue(ctx context.Context, tx store.Tx, id tenant.ID, at time.Time, seed bool) error {
	bucket := at.UnixNano() / int64(j.every)
	job := jobs.Job{Kind: JobPurge, Tenant: id, MaxAttempts: 1, UniqueKey: fmt.Sprintf("t%d", bucket)}
	if !seed {
		job.RunAt = time.Unix(0, bucket*int64(j.every))
	}
	_, err := j.reg.Enqueue(ctx, tx, job)
	return err
}

func (j *Jobs) run(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
	if err := purgeArgs(c.Args); err != nil {
		return &jobs.Failure{Code: CodeBadArgs, Permanent: true, Err: err}
	}
	// The successor is queued first, so nothing below can stop the cadence.
	if err := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		return j.enqueue(ctx, tx, c.Tenant, time.Now().Add(j.every), false)
	}); err != nil {
		return &jobs.Failure{Code: CodePurgeFailed, Err: err}
	}
	var n int
	err := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		var err error
		n, err = j.creds.PurgeThrottle(ctx, tx, c.Tenant)
		return err
	})
	if err != nil {
		return &jobs.Failure{Code: CodePurgeFailed, Err: err}
	}
	if n > 0 {
		slog.Info("authn: purged dead sign-in throttle rows", "tenant", c.Tenant.String(), "deleted", n)
	}
	return nil
}
