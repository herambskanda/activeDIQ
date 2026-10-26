package server

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/jobs/jobstest"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type wenv struct {
	db  *store.DB
	d   *storetest.Database
	ten tenant.ID
}

func setup(t *testing.T, s *storetest.Server) *wenv {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	ten := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(db.Close)
	return &wenv{db: db, d: d, ten: ten}
}

func (e *wenv) enqueue(t *testing.T, reg *jobs.Registry, kind string) int64 {
	t.Helper()
	var id int64
	err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		res, err := reg.Enqueue(ctx, tx, jobs.Job{Kind: kind, Tenant: e.ten})
		id = res.ID
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func wcfg(grace time.Duration) jobs.WorkerConfig {
	return jobs.WorkerConfig{ShutdownGrace: grace, PollMin: 5 * time.Millisecond, PollMax: 20 * time.Millisecond}
}

// Acceptance 1: with the server's worker running, queued jobs of a registered tenant kind are claimed and run.
func TestRunWorkerClaimsAndRunsQueuedJobs(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		var ran atomic.Int32
		reg := jobs.NewRegistry()
		if err := reg.Register(jobs.Kind{Name: "t.work", Timeout: time.Minute, Mode: jobs.ModeDefault,
			Run: func(context.Context, store.Tx, jobs.Claimed) error { ran.Add(1); return nil }}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runWorker(ctx, e.db, reg, wcfg(time.Second)) }()
		a, b := e.enqueue(t, reg, "t.work"), e.enqueue(t, reg, "t.work")
		_, _ = a, b
		eventually(t, "both jobs run", func() bool { return ran.Load() == 2 })
		cancel()
		if err := <-done; err != nil || ran.Load() != 2 {
			t.Fatalf("runWorker = %v after %d runs, want nil after 2", err, ran.Load())
		}
	})
}

// Acceptance 2: SIGTERM stops claiming, the in-flight body gets ShutdownGrace and is then cancelled, the
// process-level context ends runWorker, and the unfinished claim is rescued and run by the next process.
func TestSIGTERMDrainsWithinGraceAndLeavesTheClaimForRescue(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		started := make(chan struct{}, 1)
		var firstProcess atomic.Bool
		firstProcess.Store(true)
		var completed atomic.Int32
		newReg := func() *jobs.Registry {
			reg := jobs.NewRegistry()
			if err := reg.Register(jobs.Kind{Name: "t.stuck", Timeout: time.Minute, Mode: jobs.ModeDefault,
				Run: func(ctx context.Context, _ store.Tx, _ jobs.Claimed) error {
					if firstProcess.Load() {
						started <- struct{}{}
						<-ctx.Done()
						return ctx.Err()
					}
					completed.Add(1)
					return nil
				}}); err != nil {
				t.Fatal(err)
			}
			return reg
		}
		reg := newReg()
		e.enqueue(t, reg, "t.stuck")

		// The same wiring as cmd/server/main.go.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		const grace = 300 * time.Millisecond
		done := make(chan error, 1)
		// Concurrency 1: the second job is queued while the first body holds the only slot, so it cannot be
		// claimed before SIGTERM lands (with the default 8 slots a poll could claim it in that window, which
		// made Rescue see two interrupted claims: T-0399). Whether it is claimed after SIGTERM is still
		// pinned by the Requeued == 1 and completed == 0 assertions below.
		cfg := wcfg(grace)
		cfg.Concurrency = 1
		go func() { done <- runWorker(ctx, e.db, reg, cfg) }()
		<-started
		e.enqueue(t, reg, "t.stuck") // queued while a body is in flight; must not be claimed after SIGTERM
		sent := time.Now()
		// A real SIGTERM to this process, as a service manager sends it (Windows cannot deliver it: skip).
		self, _ := os.FindProcess(os.Getpid())
		if err := self.Signal(syscall.SIGTERM); err != nil {
			t.Skipf("cannot signal this process on this platform: %v", err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("runWorker = %v, want nil: the body honoured the forced cancellation", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("runWorker did not return after SIGTERM")
		}
		if took := time.Since(sent); took < grace {
			t.Errorf("returned after %s, before the %s grace period: the body was not given time", took, grace)
		}
		if completed.Load() != 0 {
			t.Fatalf("%d jobs completed after SIGTERM, want none", completed.Load())
		}
		// The next process rescues the lapsed claim and runs both jobs.
		firstProcess.Store(false)
		jobstest.LapseClaims(t, e.d.ExecOwner)
		if r, err := jobs.Rescue(context.Background(), e.db, 10); err != nil || r.Requeued != 1 {
			t.Fatalf("Rescue = %+v, %v; want the interrupted job requeued", r, err)
		}
		ctx2, cancel2 := context.WithCancel(context.Background())
		done2 := make(chan error, 1)
		go func() { done2 <- runWorker(ctx2, e.db, newReg(), wcfg(time.Second)) }()
		eventually(t, "the next process to run both jobs", func() bool { return completed.Load() == 2 })
		cancel2()
		if err := <-done2; err != nil {
			t.Fatalf("second runWorker = %v", err)
		}
	})
}

// A body that ignores cancellation makes runWorker return ErrDrainTimeout, which main turns into exit 1.
func TestRunWorkerReportsDrainTimeout(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		started := make(chan struct{}, 1)
		release := make(chan struct{})
		reg := jobs.NewRegistry()
		if err := reg.Register(jobs.Kind{Name: "t.deaf", Timeout: time.Minute, Mode: jobs.ModeDefault,
			Run: func(context.Context, store.Tx, jobs.Claimed) error { started <- struct{}{}; <-release; return nil }}); err != nil {
			t.Fatal(err)
		}
		e.enqueue(t, reg, "t.deaf")
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runWorker(ctx, e.db, reg, wcfg(100*time.Millisecond)) }()
		<-started
		cancel()
		err := <-done
		close(release)
		if !errors.Is(err, jobs.ErrDrainTimeout) {
			t.Fatalf("runWorker = %v, want ErrDrainTimeout", err)
		}
	})
}

func TestRunWorkerRejectsAnInvalidHolderBeforeClaiming(t *testing.T) {
	cfg := wcfg(time.Second)
	cfg.Holder = "bad holder; DROP"
	err := runWorker(context.Background(), nil, jobs.NewRegistry(), cfg)
	if err == nil || !strings.Contains(err.Error(), "holder") {
		t.Fatalf("runWorker = %v, want a holder validation error", err)
	}
}
