package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Body is the body of a default-mode kind. tx is the wrapper's one transaction, scoped to the claimed
// job's tenant only; the job's completion is recorded in it, so the body's writes and the completion
// commit together or not at all. Returning an error (or panicking) rolls everything back.
type Body func(ctx context.Context, tx store.Tx, c Claimed) error

// ManagedBody is the body of a ManagedTx kind. It holds no transaction: it opens short ones through run,
// and never holds one across a directory call (ADR-0002 Jobs row as amended by ADR-0005 rule 6).
type ManagedBody func(ctx context.Context, run TenantTx, c Claimed) error

// TenantTx opens short transactions bound to the claimed job's tenant. There is no tenant parameter: a
// body cannot name another tenant, and the database refuses a row of any other.
type TenantTx interface {
	// Run runs fn in one transaction scoped to the job's tenant; fn returning nil commits.
	Run(ctx context.Context, fn func(ctx context.Context, tx store.Tx) error) error
}

type tenantTx struct {
	db     *store.DB
	c      Claimed
	closed atomic.Bool
}

// ErrRunnerClosed is returned by a TenantTx used after its body returned or its claim was superseded:
// late work (a kept runner, a stray goroutine) must not write for a job another worker may now drive.
var ErrRunnerClosed = errors.New("jobs: the job's runner is closed")

func (t *tenantTx) Run(ctx context.Context, fn func(ctx context.Context, tx store.Tx) error) error {
	if t.closed.Load() {
		return ErrRunnerClosed
	}
	return t.db.WithTenant(ctx, t.c.Tenant, func(ctx context.Context, tx store.Tx) error {
		// Fence on the live claim in the database before fn runs; the lock is held to the commit.
		if err := LockClaim(ctx, tx, t.c.Ref); err != nil {
			t.closed.Store(true)
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		if t.closed.Load() {
			return ErrRunnerClosed
		}
		return nil
	})
}

// Failure is an error a body returns to choose the stored code, and whether the job is discarded at once
// instead of retried. The code is a snake_case code; no error text is ever stored.
type Failure struct {
	Code      string
	Permanent bool
	Err       error // for logs and errors.Is only; never stored
}

func (f *Failure) Error() string {
	if f.Err != nil {
		return fmt.Sprintf("jobs: failed (%s): %v", f.Code, f.Err)
	}
	return "jobs: failed (" + f.Code + ")"
}

func (f *Failure) Unwrap() error { return f.Err }

// Result is what the wrapper recorded for a claimed job: Retried or Exhausted (as Fail reports them), or
// one of these.
type Result = Outcome

const (
	Completed Result = "completed"
	Discarded Result = "discarded"
	// Lost: the claim was superseded (lapsed and rescued, or taken over); nothing was recorded.
	Lost Result = "lost"
)

// Failure codes the wrapper itself stores.
const (
	CodeFailed      = "job_failed"
	CodePanic       = "job_panic"
	CodeTimeout     = "job_timeout"
	CodeCrossTenant = "cross_tenant"
)

// ErrPlatformJob is returned for a claimed platform job: this wrapper runs tenant-carrying kinds only,
// and the claim is left to lapse and be rescued.
var ErrPlatformJob = errors.New("jobs: platform jobs are not run by the tenant wrapper")

// Runner runs claimed jobs: it mints the tenant from the claimed row (the only place besides authn that
// does, ADR-0002 rule 5), runs the kind's body, and records the outcome.
type Runner struct {
	db  *store.DB
	reg *Registry
	// leaseFor is the claim lease of a kind; tests shorten it.
	leaseFor func(Kind) time.Duration
}

// NewRunner returns a Runner for jobs claimed with the leases of reg.Leases.
func NewRunner(db *store.DB, reg *Registry) *Runner {
	return &Runner{db: db, reg: reg, leaseFor: func(k Kind) time.Duration { return k.Timeout + ClaimGrace }}
}

// Execute runs one claimed job to its outcome. A default-mode kind's body and the Complete run in one
// WithTenant transaction. A ManagedTx kind's body gets a runner, and the claim is renewed every half
// lease while it runs. A body error or panic stores a code (Fail, or Discard for a Permanent Failure)
// and never the error text. The error is non-nil only when the outcome could not be recorded.
func (r *Runner) Execute(ctx context.Context, c Claimed) (Result, error) {
	k, err := r.reg.check(Job{Kind: c.Kind, Tenant: c.Tenant})
	if err != nil {
		return "", err
	}
	if c.Tenant.IsZero() {
		return "", fmt.Errorf("%w: %q", ErrPlatformJob, k.Name)
	}
	bodyCtx, cancel := context.WithTimeout(ctx, k.Timeout)
	defer cancel()

	var bodyErr error
	if k.Mode == ModeDefault {
		bodyErr = r.db.WithTenant(bodyCtx, c.Tenant, func(ctx context.Context, tx store.Tx) error {
			// Prove the claim is live and belongs to c.Tenant before any body code runs.
			if err := Renew(ctx, tx, c.Ref, r.leaseFor(k)); err != nil {
				return err
			}
			if err := safely(func() error { return k.Run(ctx, tx, c) }); err != nil {
				return err
			}
			return Complete(ctx, tx, c.Ref)
		})
		if bodyErr == nil {
			return Completed, nil
		}
	} else {
		bodyErr = r.runManaged(bodyCtx, k, c)
		if bodyErr == nil {
			bodyErr = r.record(ctx, c, func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, c.Ref) })
			if bodyErr == nil {
				return Completed, nil
			}
			if errors.Is(bodyErr, ErrSuperseded) {
				return Lost, nil
			}
			return "", bodyErr
		}
	}
	return r.failed(ctx, c, bodyCtx, bodyErr)
}

// runManaged runs a ManagedTx body, renewing the claim every half lease until it returns. A renewal that
// finds the claim superseded cancels the body's context: its late work must stop.
func (r *Runner) runManaged(ctx context.Context, k Kind, c Claimed) error {
	lease := r.leaseFor(k)
	// Prove in the database, before any body code runs, that this claim is live and belongs to c.Tenant:
	// the claimed row is fenced by RLS, so a Claimed carrying another tenant finds nothing to renew.
	if err := r.record(ctx, c, func(ctx context.Context, tx store.Tx) error { return Renew(ctx, tx, c.Ref, lease) }); err != nil {
		return err
	}
	run := &tenantTx{db: r.db, c: c}
	bctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(lease / 2)
		defer t.Stop()
		for {
			select {
			case <-bctx.Done():
				return
			case <-t.C:
				err := r.record(bctx, c, func(ctx context.Context, tx store.Tx) error { return Renew(ctx, tx, c.Ref, lease) })
				switch {
				case errors.Is(err, ErrSuperseded):
					run.closed.Store(true)
					cancel(ErrSuperseded)
					return
				case err != nil && bctx.Err() == nil:
					// Transient: the next tick retries, well inside the remaining half lease.
					slog.WarnContext(bctx, "jobs: renewing a claim failed", "job", c.ID, "attempt", c.Attempt)
				}
			}
		}
	}()
	err := safely(func() error { return k.RunManaged(bctx, run, c) })
	run.closed.Store(true)
	cancel(nil)
	wg.Wait()
	if cause := context.Cause(bctx); errors.Is(cause, ErrSuperseded) {
		return ErrSuperseded
	}
	return err
}

// failed records the failure of a body whose transaction (if any) already rolled back.
func (r *Runner) failed(ctx context.Context, c Claimed, bodyCtx context.Context, bodyErr error) (Result, error) {
	if errors.Is(bodyErr, ErrSuperseded) {
		return Lost, nil
	}
	code, permanent := failureCode(bodyCtx, bodyErr)
	var res Result
	err := r.record(ctx, c, func(ctx context.Context, tx store.Tx) error {
		if permanent {
			res = Discarded
			return Discard(ctx, tx, c.Ref, code)
		}
		o, err := Fail(ctx, tx, c.Ref, code, Backoff(c.Attempt))
		res = o
		return err
	})
	switch {
	case errors.Is(err, ErrSuperseded):
		return Lost, nil
	case err != nil:
		return "", err
	}
	return res, nil
}

// record runs fn in a short tenant transaction on a context that survives the body's timeout or the
// caller's cancellation by a bounded time, so a timed-out body can still be failed.
func (r *Runner) record(ctx context.Context, c Claimed, fn func(ctx context.Context, tx store.Tx) error) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	return r.db.WithTenant(rctx, c.Tenant, fn)
}

// failureCode maps a body error to the stored code. The text of err is never stored.
func failureCode(bodyCtx context.Context, err error) (string, bool) {
	var f *Failure
	var p panicError
	switch {
	case errors.As(err, &f) && codePattern.MatchString(f.Code):
		return f.Code, f.Permanent
	case errors.As(err, &p):
		return CodePanic, false
	case errors.Is(err, ErrCrossTenant):
		return CodeCrossTenant, false
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(bodyCtx.Err(), context.DeadlineExceeded):
		return CodeTimeout, false
	}
	return CodeFailed, false
}

// panicError marks a recovered panic. The panic value is not kept: it may hold personal data.
type panicError struct{}

func (panicError) Error() string { return "jobs: the job body panicked" }

func safely(fn func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = panicError{}
		}
	}()
	return fn()
}
