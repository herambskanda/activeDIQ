package jobs

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Clock is the worker's only source of waiting, so tests drive it without real sleeps.
type Clock interface {
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// ErrDrainTimeout is returned by Run when in-flight bodies did not return after the shutdown deadline and
// the forced cancellation. Their claims are left to lapse and Rescue requeues them.
var ErrDrainTimeout = errors.New("jobs: in-flight bodies did not stop before the shutdown deadline")

// WorkerConfig tunes a Worker. A zero field takes its default.
type WorkerConfig struct {
	// Holder names this worker in platform leases (holderPattern). Default: "worker-" + random hex.
	Holder string
	// Concurrency is the most bodies running at once. Default 8.
	Concurrency int
	// PollMin and PollMax bound the idle wait; it doubles from PollMin to PollMax on each empty poll and
	// resets when work is claimed. Defaults 250 ms and 5 s.
	PollMin, PollMax time.Duration
	// ShutdownGrace is how long Run waits for in-flight bodies after its context ends before it cancels
	// them (they then record nothing; Rescue requeues the claim). Default 30 s.
	ShutdownGrace time.Duration
	// RescueEvery and CleanEvery are the maintenance timers; both run under their platform lease.
	// Defaults 30 s and 1 h. Retention is how long a finished job is kept. Default 7 days.
	RescueEvery, CleanEvery, Retention time.Duration
	// Batch bounds one Rescue or Clean pass. Default 500.
	Batch int

	// Clock and Jitter are for tests. Jitter returns a value in [0, 1).
	Clock  Clock
	Jitter func() float64
}

func (c *WorkerConfig) defaults() error {
	if c.Holder == "" {
		var b [8]byte
		if _, err := crand.Read(b[:]); err != nil {
			return err
		}
		c.Holder = "worker-" + hex.EncodeToString(b[:])
	}
	if !holderPattern.MatchString(c.Holder) {
		return invalid("worker holder must be 1..200 characters of letters, digits and ._:@-")
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	if c.Concurrency == 0 {
		c.Concurrency = 8
	}
	if c.Batch == 0 {
		c.Batch = 500
	}
	def(&c.PollMin, 250*time.Millisecond)
	def(&c.PollMax, 5*time.Second)
	def(&c.ShutdownGrace, 30*time.Second)
	def(&c.RescueEvery, 30*time.Second)
	def(&c.CleanEvery, time.Hour)
	def(&c.Retention, 7*24*time.Hour)
	switch {
	case c.Concurrency < 1 || c.Concurrency > maxBatch:
		return invalid("worker concurrency %d is outside 1..%d", c.Concurrency, maxBatch)
	case c.Batch < 1 || c.Batch > maxBatch:
		return invalid("worker batch %d is outside 1..%d", c.Batch, maxBatch)
	case c.PollMin <= 0 || c.PollMax < c.PollMin:
		return invalid("worker poll interval needs 0 < PollMin <= PollMax")
	case c.ShutdownGrace <= 0 || c.RescueEvery <= 0 || c.CleanEvery <= 0 || c.Retention < 0:
		return invalid("worker durations must be positive")
	}
	if c.Clock == nil {
		c.Clock = realClock{}
	}
	if c.Jitter == nil {
		c.Jitter = rand.Float64
	}
	return nil
}

// Worker claims runnable jobs, hands each to the Runner (the tenant wrapper) and runs Rescue and Clean on
// timers, only under their platform leases (DM-06).
type Worker struct {
	db  *store.DB
	run *Runner
	reg *Registry
	cfg WorkerConfig
}

// NewWorker validates cfg and returns a Worker over the registry the runner was built with.
func NewWorker(db *store.DB, reg *Registry, cfg WorkerConfig) (*Worker, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	return &Worker{db: db, run: NewRunner(db, reg), reg: reg, cfg: cfg}, nil
}

// Run blocks until ctx ends. It then stops claiming, waits up to ShutdownGrace for running bodies, cancels
// the stragglers (which leaves their claims for Rescue) and returns nil, or ErrDrainTimeout if a body
// ignored the cancellation.
func (w *Worker) Run(ctx context.Context) error {
	// Bodies outlive ctx so a graceful stop lets them finish; stopBodies is the forced stop.
	bodyCtx, stopBodies := context.WithCancel(context.WithoutCancel(ctx))
	defer stopBodies()

	var maint sync.WaitGroup
	maint.Add(2)
	go func() {
		defer maint.Done()
		w.every(ctx, w.cfg.RescueEvery, w.rescue)
	}()
	go func() {
		defer maint.Done()
		w.every(ctx, w.cfg.CleanEvery, w.clean)
	}()

	var inflight sync.WaitGroup
	w.poll(ctx, bodyCtx, &inflight)

	drained := make(chan struct{})
	go func() { inflight.Wait(); close(drained) }()
	var err error
	select {
	case <-drained:
	case <-w.cfg.Clock.After(w.cfg.ShutdownGrace):
		slog.Warn("jobs: shutdown deadline reached; cancelling running bodies, their claims are left for rescue")
		stopBodies()
		select {
		case <-drained:
		case <-w.cfg.Clock.After(w.cfg.ShutdownGrace):
			err = ErrDrainTimeout
		}
	}
	maint.Wait()
	return err
}

// poll claims into free slots until ctx ends. Only this goroutine takes a slot, so the free count it reads
// can only grow while it claims.
func (w *Worker) poll(ctx, bodyCtx context.Context, inflight *sync.WaitGroup) {
	slots := make(chan struct{}, w.cfg.Concurrency)
	freed := make(chan struct{}, 1)
	idle := 0
	for ctx.Err() == nil {
		free := w.cfg.Concurrency - len(slots)
		if free == 0 {
			select {
			case <-freed:
			case <-ctx.Done():
			}
			continue
		}
		claimed, err := w.claim(ctx, min(free, maxBatch))
		if err != nil && ctx.Err() == nil {
			slog.Error("jobs: claiming failed", "err", err)
		}
		if len(claimed) == 0 {
			select {
			case <-w.cfg.Clock.After(w.backoff(idle)):
			case <-ctx.Done():
			}
			idle++
			continue
		}
		idle = 0
		for _, c := range claimed {
			slots <- struct{}{}
			inflight.Add(1)
			go func() {
				defer inflight.Done()
				defer func() {
					<-slots
					select {
					case freed <- struct{}{}:
					default:
					}
				}()
				w.execute(bodyCtx, c)
			}()
		}
	}
}

func (w *Worker) claim(ctx context.Context, n int) ([]Claimed, error) {
	kinds := w.reg.TenantLeases()
	if len(kinds) == 0 {
		return nil, nil
	}
	return Claim(ctx, w.db, kinds, n)
}

func (w *Worker) execute(ctx context.Context, c Claimed) {
	res, err := w.run.Execute(ctx, c)
	if err != nil {
		// The claim lapses and Rescue requeues it. Only identifiers are logged, never arguments.
		slog.Error("jobs: running a claimed job failed", "tenant_id", c.Tenant.String(), "job", c.ID, "kind", c.Kind, "attempt", c.Attempt, "err", err)
		return
	}
	slog.Debug("jobs: job finished", "tenant_id", c.Tenant.String(), "job", c.ID, "kind", c.Kind, "attempt", c.Attempt, "result", string(res))
}

// backoff is PollMin doubled per empty poll up to PollMax, with equal jitter (half fixed, half random) so
// workers started together do not poll in step.
func (w *Worker) backoff(idle int) time.Duration {
	d := w.cfg.PollMax
	if idle < 32 {
		d = min(w.cfg.PollMin<<idle, w.cfg.PollMax)
	}
	return d/2 + time.Duration(w.cfg.Jitter()*float64(d/2))
}

// every runs fn each period until ctx ends.
func (w *Worker) every(ctx context.Context, period time.Duration, fn func(context.Context)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.cfg.Clock.After(period):
			fn(ctx)
		}
	}
}

func (w *Worker) rescue(ctx context.Context) {
	res, ran, err := RunRescue(ctx, w.db, w.cfg.Holder, w.cfg.Batch)
	switch {
	case err != nil && ctx.Err() == nil:
		slog.Error("jobs: rescue failed", "err", err)
	case ran && (res.Requeued > 0 || res.Discarded > 0):
		slog.Info("jobs: rescued lapsed claims", "requeued", res.Requeued, "discarded", res.Discarded)
	}
}

func (w *Worker) clean(ctx context.Context) {
	n, ran, err := RunClean(ctx, w.db, w.cfg.Holder, w.cfg.Retention, w.cfg.Batch)
	switch {
	case err != nil && ctx.Err() == nil:
		slog.Error("jobs: clean failed", "err", err)
	case ran && n > 0:
		slog.Info("jobs: cleaned finished jobs", "deleted", n)
	}
}
