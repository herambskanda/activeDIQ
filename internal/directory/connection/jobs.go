package connection

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

// JobScheduledCheck is the job kind of the scheduled rights check (spec L11, §8.1: rights checks run at
// least every 24 h). One job per tenant verifies every active connection of the tenant, in order.
const JobScheduledCheck = "connection.scheduled_check"

// DefaultCheckInterval is the ceiling of the cadence; a tenant may shorten it, never lengthen it.
const DefaultCheckInterval = 24 * time.Hour

// CodeCheckFailed is the stored failure code of a run that could not list or start its checks.
const CodeCheckFailed = "check_failed"

// CodeBadArgs is the stored failure code of a job whose args are not the kind's.
const CodeBadArgs = "bad_args"

// Jobs registers and schedules the scheduled rights check.
type Jobs struct {
	reg      *jobs.Registry
	svc      *Service
	interval time.Duration
}

// RegisterJobs registers connection.scheduled_check in reg. interval is the cadence (zero takes
// DefaultCheckInterval; above it is refused, since the 24 h ceiling is not lengthened).
func RegisterJobs(reg *jobs.Registry, svc *Service, interval time.Duration) (*Jobs, error) {
	if reg == nil || svc == nil {
		return nil, fmt.Errorf("%w: scheduled check needs a job registry and a service", ErrInvalid)
	}
	if interval == 0 {
		interval = DefaultCheckInterval
	}
	if interval < time.Minute || interval > DefaultCheckInterval {
		return nil, fmt.Errorf("%w: check interval must be between 1m and %s", ErrInvalid, DefaultCheckInterval)
	}
	j := &Jobs{reg: reg, svc: svc, interval: interval}
	// Timeout: connections are verified one at a time; a run is bounded by the kind, and the next run is
	// queued before any directory call, so a slow tenant cannot stop its own cadence.
	err := reg.Register(jobs.Kind{Name: JobScheduledCheck, Timeout: 30 * time.Minute, Mode: jobs.ModeManagedTx,
		ValidateArgs: checkArgs, RunManaged: j.run})
	if err != nil {
		return nil, fmt.Errorf("connection: registering job kind: %w", err)
	}
	return j, nil
}

// checkArgs: the job carries no arguments but the tenant, which Enqueue records.
func checkArgs(raw jsontext.Value) error {
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

// Schedule starts the tenant's cadence in the caller's tenant transaction. It is idempotent: a run
// already queued for the current interval is left alone, and the job's own successor lands in the same
// buckets, so a second start converges. The first run is not immediate: activation has just verified.
func (j *Jobs) Schedule(ctx context.Context, tx store.Tx, tid tenant.ID) error {
	return j.enqueue(ctx, tx, tid, time.Now().Add(j.interval))
}

// ScheduleCheck implements Scheduler.
func (j *Jobs) ScheduleCheck(ctx context.Context, tx store.Tx, tid tenant.ID) error {
	return j.Schedule(ctx, tx, tid)
}

func (j *Jobs) enqueue(ctx context.Context, tx store.Tx, tid tenant.ID, at time.Time) error {
	bucket := at.UnixNano() / int64(j.interval)
	_, err := j.reg.Enqueue(ctx, tx, jobs.Job{
		Kind: JobScheduledCheck, Tenant: tid, MaxAttempts: 1,
		UniqueKey: fmt.Sprintf("t%d", bucket),
		RunAt:     time.Unix(0, bucket*int64(j.interval)),
	})
	return err
}

func (j *Jobs) run(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
	if err := checkArgs(c.Args); err != nil {
		return &jobs.Failure{Code: CodeBadArgs, Permanent: true, Err: err}
	}
	// The successor is queued first, so nothing below can stop the cadence.
	err := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		return j.enqueue(ctx, tx, c.Tenant, time.Now().Add(j.interval))
	})
	if err != nil {
		return &jobs.Failure{Code: CodeCheckFailed, Err: err}
	}
	// Runs stranded in verifying by a crash are recovered on the same cadence (DM-10.I10). A failure to
	// sweep is logged and does not stop the rights check.
	if swept, err := j.svc.SweepStranded(ctx, c.Tenant, 0); err != nil {
		slog.Warn("connection: sweep of stranded runs incomplete", "tenant", c.Tenant.String(), "swept", len(swept), "err", err)
	}
	res, err := j.svc.RunScheduled(ctx, c.Tenant)
	if err != nil {
		return &jobs.Failure{Code: CodeCheckFailed, Err: err}
	}
	failed := 0
	for _, r := range res {
		if r.Err != nil {
			failed++
		}
	}
	// Each run, including a failed one, is already recorded and audited by the service; a failure is
	// never retried here (a permissions error must not become a hang against a DC).
	if failed > 0 {
		slog.Warn("connection: scheduled check: runs did not complete", "tenant", c.Tenant.String(), "failed", failed, "total", len(res))
	}
	return nil
}

// Scheduler starts the scheduled check of a tenant in the caller's transaction.
type Scheduler interface {
	ScheduleCheck(ctx context.Context, tx store.Tx, tid tenant.ID) error
}

// Option configures NewService.
type Option func(*Service)

// WithScheduler makes activation start the tenant's scheduled check, in the activation transaction.
func WithScheduler(s Scheduler) Option { return func(sv *Service) { sv.sched = s } }

// ActivationHook is told, in the activation's own transaction, that a connection became active. A failure
// rolls the activation back, so a hook enqueues work (a job row) and does not call out.
type ActivationHook interface {
	ConnectionActivated(ctx context.Context, tx store.Tx, tid tenant.ID, c Connection) error
}

// WithActivationHook makes activation tell h (the first sync of the connection starts from it).
func WithActivationHook(h ActivationHook) Option { return func(sv *Service) { sv.onAct = h } }
