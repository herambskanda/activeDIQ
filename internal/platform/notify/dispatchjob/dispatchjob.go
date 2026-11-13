// Package dispatchjob is the notify.dispatch job (T-1004): the cadence that runs
// delivery.Dispatcher.DispatchDue for a tenant. It sits above both notify/delivery and jobs, like
// authn/throttlejob, because the Deliveries library does not import jobs.
//
// The Dispatcher it runs is built by the caller: the Renderer per purpose and the Accounts resolver
// are supplied by whatever enqueues Deliveries of that purpose (report delivery, B11). A Delivery whose
// purpose has no Renderer is given up with delivery.CodeNoRenderer, never retried forever.
package dispatchjob

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// JobDispatch is the job kind that attempts a tenant's due Deliveries.
const JobDispatch = "notify.dispatch"

const (
	// Interval is the default cadence.
	Interval = 30 * time.Second
	// BatchSize is the default number of Deliveries claimed per batch (the throttle toward the relay).
	BatchSize = 50
	// MaxBatches caps the batches of one run, so a backlog is worked off over several runs and one
	// tenant cannot hold a worker.
	MaxBatches = 10
	// Timeout bounds one run. It is below delivery.Dispatcher's default 5 min lease, so a run that stalls
	// has its context cancelled before a claimed Delivery can be handed to another worker (T-0950
	// residual risk: a stalled record() after a successful send re-sends).
	Timeout = 4 * time.Minute

	// CodeDispatchFailed and CodeBadArgs are the stored failure codes of the job.
	CodeDispatchFailed = "notify_dispatch_failed"
	CodeBadArgs        = "bad_args"
)

// Config tunes the cadence; zero values take the defaults.
type Config struct {
	Every     time.Duration
	BatchSize int
}

// Jobs registers and schedules notify.dispatch.
type Jobs struct {
	disp  *delivery.Dispatcher
	every time.Duration
	batch int
	reg   *jobs.Registry
}

// Register registers notify.dispatch in reg, running d.
func Register(reg *jobs.Registry, d *delivery.Dispatcher, cfg Config) (*Jobs, error) {
	if reg == nil || d == nil {
		return nil, errors.New("notify: dispatch job needs a job registry and a dispatcher")
	}
	if cfg.Every == 0 {
		cfg.Every = Interval
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = BatchSize
	}
	if cfg.Every < time.Second || cfg.BatchSize < 1 || cfg.BatchSize > 500 {
		return nil, errors.New("notify: dispatch job interval or batch size out of range")
	}
	j := &Jobs{disp: d, every: cfg.Every, batch: cfg.BatchSize, reg: reg}
	err := reg.Register(jobs.Kind{Name: JobDispatch, Timeout: Timeout, Mode: jobs.ModeManagedTx,
		ValidateArgs: dispatchArgs, RunManaged: j.run})
	if err != nil {
		return nil, fmt.Errorf("notify: registering job kind: %w", err)
	}
	return j, nil
}

// dispatchArgs: the job carries no arguments but the tenant, which Enqueue records.
func dispatchArgs(raw jsontext.Value) error {
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

// Schedule starts the tenant's dispatch cadence in the caller's tenant transaction. It is idempotent:
// a run already queued for the current interval is left alone. The first run is immediate.
func (j *Jobs) Schedule(ctx context.Context, tx store.Tx, id tenant.ID) error {
	return j.enqueue(ctx, tx, id, time.Now(), true)
}

func (j *Jobs) enqueue(ctx context.Context, tx store.Tx, id tenant.ID, at time.Time, seed bool) error {
	bucket := at.UnixNano() / int64(j.every)
	job := jobs.Job{Kind: JobDispatch, Tenant: id, MaxAttempts: 1, UniqueKey: fmt.Sprintf("t%d", bucket)}
	if !seed {
		job.RunAt = time.Unix(0, bucket*int64(j.every))
	}
	_, err := j.reg.Enqueue(ctx, tx, job)
	return err
}

func (j *Jobs) run(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
	if err := dispatchArgs(c.Args); err != nil {
		return &jobs.Failure{Code: CodeBadArgs, Permanent: true, Err: err}
	}
	// The successor is queued first, so nothing below can stop the cadence.
	if err := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		return j.enqueue(ctx, tx, c.Tenant, time.Now().Add(j.every), false)
	}); err != nil {
		return &jobs.Failure{Code: CodeDispatchFailed, Err: err}
	}
	var total delivery.Summary
	for range MaxBatches {
		s, err := j.disp.DispatchDue(ctx, c.Tenant, j.batch)
		total.Sent += s.Sent
		total.Retrying += s.Retrying
		total.GivenUp += s.GivenUp
		if err != nil {
			return &jobs.Failure{Code: CodeDispatchFailed, Err: err}
		}
		if s.Sent+s.Retrying+s.GivenUp < j.batch || ctx.Err() != nil {
			break
		}
	}
	if total != (delivery.Summary{}) {
		slog.Info("notify: dispatched due deliveries", "tenant", c.Tenant.String(),
			"sent", total.Sent, "retrying", total.Retrying, "given_up", total.GivenUp)
	}
	return nil
}
