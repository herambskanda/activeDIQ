package jobs

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// fakeClock hands out timers that fire only when the test advances time.
type fakeClock struct {
	mu   sync.Mutex
	now  time.Duration
	reqs []time.Duration // every requested wait, in order
	ws   []fakeWaiter
}

type fakeWaiter struct {
	at time.Duration
	ch chan time.Time
	d  time.Duration
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.reqs = append(c.reqs, d)
	c.ws = append(c.ws, fakeWaiter{at: c.now + d, ch: ch, d: d})
	return ch
}

// advanceWaits fires every pending timer that was requested with exactly d.
func (c *fakeClock) fire(d time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	rest := c.ws[:0]
	for _, w := range c.ws {
		if w.d == d {
			w.ch <- time.Time{}
			n++
		} else {
			rest = append(rest, w)
		}
	}
	c.ws = rest
	return n
}

func (c *fakeClock) requested(d time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.reqs {
		if r == d {
			n++
		}
	}
	return n
}

func (c *fakeClock) all() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.reqs...)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (e *env) newWorker(t *testing.T, cfg WorkerConfig, kinds ...Kind) *Worker {
	t.Helper()
	reg := NewRegistry()
	for _, k := range kinds {
		if err := reg.Register(k); err != nil {
			t.Fatal(err)
		}
	}
	w, err := NewWorker(e.db, reg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (e *env) runWorker(w *Worker) (stop func(), done <-chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	go func() { ch <- w.Run(ctx) }()
	return cancel, ch
}

// Acceptance 1: queued jobs of a registered kind are claimed up to the concurrency limit and run through
// the wrapper (each in its tenant's transaction, completed with it).
func TestWorkerClaimsUpToConcurrencyAndRunsThroughWrapper(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		var running, peak, ran atomic.Int32
		release := make(chan struct{})
		var tenantSeen sync.Map
		body := func(ctx context.Context, tx store.Tx, c Claimed) error {
			n := running.Add(1)
			defer running.Add(-1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			var got string
			if err := tx.QueryRow(ctx, `SELECT current_setting('app.tenant_id')`).Scan(&got); err != nil {
				return err
			}
			tenantSeen.Store(got, true)
			<-release
			ran.Add(1)
			return nil
		}
		var ids []int64
		for i := 0; i < 5; i++ {
			ids = append(ids, e.enqueueKind(t, "t.work"))
		}
		w := e.newWorker(t, WorkerConfig{Concurrency: 2, PollMin: 5 * time.Millisecond, PollMax: 20 * time.Millisecond},
			Kind{Name: "t.work", Timeout: time.Minute, Mode: ModeDefault, Run: body})
		stop, done := e.runWorker(w)
		eventually(t, "two bodies running", func() bool { return running.Load() == 2 })
		time.Sleep(100 * time.Millisecond)
		if running.Load() != 2 {
			t.Fatalf("%d bodies running, want the concurrency limit 2", running.Load())
		}
		close(release)
		eventually(t, "all five completed", func() bool {
			for _, id := range ids {
				if st, _ := e.state(t, id); st != "completed" {
					return false
				}
			}
			return true
		})
		stop()
		if err := <-done; err != nil {
			t.Fatalf("Run = %v", err)
		}
		if peak.Load() > 2 {
			t.Errorf("peak concurrency %d exceeds the limit 2", peak.Load())
		}
		if _, ok := tenantSeen.Load(e.a.String()); !ok {
			t.Errorf("bodies did not run in tenant %s", e.a)
		}
	})
}

// A platform kind is never claimed: the tenant wrapper would refuse it and burn attempts.
func TestWorkerDoesNotClaimPlatformKinds(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(Kind{Name: "t.plat", Timeout: time.Minute, Mode: ModeDefault, Run: noop, Platform: true})
	_ = reg.Register(Kind{Name: "t.ten", Timeout: time.Minute, Mode: ModeDefault, Run: noop})
	got := reg.TenantLeases()
	if len(got) != 1 || got[0].Kind != "t.ten" {
		t.Fatalf("TenantLeases = %+v, want only t.ten", got)
	}
}

// Acceptance 2: on cancellation the worker stops claiming, waits for running bodies up to the deadline,
// and leaves the unfinished claim for Rescue.
func TestWorkerStopsClaimingDrainsAndLeavesStragglersForRescue(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		clock := &fakeClock{}
		const grace = 10 * time.Second
		started := make(chan struct{}, 4)
		finish := make(chan struct{})
		kinds := []Kind{
			{Name: "t.quick", Timeout: time.Minute, Mode: ModeDefault, Run: func(ctx context.Context, tx store.Tx, c Claimed) error {
				started <- struct{}{}
				<-finish // finishes within the grace period
				return nil
			}},
			{Name: "t.stuck", Timeout: time.Minute, Mode: ModeDefault, Run: func(ctx context.Context, tx store.Tx, c Claimed) error {
				started <- struct{}{}
				<-ctx.Done() // only the forced stop ends it
				return ctx.Err()
			}},
		}
		quick := e.enqueueKind(t, "t.quick")
		stuck := e.enqueueKind(t, "t.stuck")
		w := e.newWorker(t, WorkerConfig{
			Concurrency: 2, ShutdownGrace: grace, PollMin: time.Second, PollMax: time.Second,
			RescueEvery: 24 * time.Hour, CleanEvery: 48 * time.Hour, Clock: clock,
		}, kinds...)
		stop, done := e.runWorker(w)
		<-started
		<-started
		stop()
		eventually(t, "the shutdown timer", func() bool { return clock.requested(grace) == 1 })
		// A job enqueued after the stop must not be claimed.
		late := e.enqueueKind(t, "t.quick")
		close(finish) // the quick body finishes inside the grace period
		eventually(t, "quick completed", func() bool { st, _ := e.state(t, quick); return st == "completed" })
		select {
		case err := <-done:
			t.Fatalf("Run returned %v while a body was still running before the deadline", err)
		case <-time.After(50 * time.Millisecond):
		}
		clock.fire(grace) // the deadline passes: the stuck body is cancelled
		if err := <-done; err != nil {
			t.Fatalf("Run = %v", err)
		}
		if st, _ := e.state(t, stuck); st != "running" {
			t.Errorf("the interrupted job is %s, want running (left for Rescue, nothing recorded)", st)
		}
		if st, _ := e.state(t, late); st != "available" {
			t.Errorf("a job enqueued after the stop is %s, want available (not claimed)", st)
		}
		// Rescue requeues it once the claim lapses.
		if err := e.d.ExecOwner(context.Background(), `UPDATE public.jobs SET claimed_until = now() - interval '1 second' WHERE id = $1`, stuck); err != nil {
			t.Fatal(err)
		}
		r, err := Rescue(context.Background(), e.db, 10)
		if err != nil || r.Requeued != 1 {
			t.Fatalf("Rescue = %+v, %v; want the interrupted job requeued", r, err)
		}
		if st, _ := e.state(t, stuck); st != "available" {
			t.Errorf("after Rescue the job is %s, want available", st)
		}
	})
}

// Acceptance 3: an empty queue is polled with a growing, jittered wait capped at PollMax; it never spins.
func TestWorkerBacksOffWithJitterOnAnEmptyQueue(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		clock := &fakeClock{}
		const min, max = 100 * time.Millisecond, 800 * time.Millisecond
		w := e.newWorker(t, WorkerConfig{
			PollMin: min, PollMax: max, Jitter: func() float64 { return 0.5 },
			RescueEvery: 24 * time.Hour, CleanEvery: 48 * time.Hour, Clock: clock,
		}, Kind{Name: "t.work", Timeout: time.Minute, Mode: ModeDefault, Run: noop})
		stop, done := e.runWorker(w)
		// With jitter 0.5 each wait is 0.75 of the doubled base: 75, 150, 300, 600, then capped at 600.
		want := []time.Duration{75, 150, 300, 600, 600, 600}
		for i, ms := range want {
			d := ms * time.Millisecond
			eventually(t, "the next poll wait", func() bool { return clock.requested(d) > countOf(want[:i], ms) })
			// Without time advancing the loop must be asleep, not spinning.
			time.Sleep(30 * time.Millisecond)
			if n := len(clock.all()); n > 2+i+1 {
				t.Fatalf("%d timers requested after %d idle polls: the loop is spinning", n, i+1)
			}
			clock.fire(d)
		}
		stop()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func countOf(ds []time.Duration, v time.Duration) int {
	n := 0
	for _, d := range ds {
		if d == v {
			n++
		}
	}
	return n
}

// The jittered wait stays within [d/2, d] for any random draw and resets to the floor after work.
func TestBackoffBounds(t *testing.T) {
	for _, j := range []float64{0, 0.5, 0.999999} {
		w := &Worker{cfg: WorkerConfig{PollMin: 100 * time.Millisecond, PollMax: time.Second, Jitter: func() float64 { return j }}}
		for idle := 0; idle < 100; idle++ {
			base := min(w.cfg.PollMin<<min(idle, 31), w.cfg.PollMax)
			if idle >= 32 {
				base = w.cfg.PollMax
			}
			got := w.backoff(idle)
			if got < base/2 || got > base {
				t.Fatalf("backoff(%d) jitter %v = %v, want within [%v, %v]", idle, j, got, base/2, base)
			}
		}
	}
}

// Acceptance 4: Rescue and Clean run on their timers only while the platform lease is free.
func TestWorkerMaintenanceRunsOnlyUnderTheLease(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		clock := &fakeClock{}
		const rescueEvery, cleanEvery = 7 * time.Second, 11 * time.Second
		w := e.newWorker(t, WorkerConfig{
			Holder: "worker-a", PollMin: time.Hour, PollMax: time.Hour,
			RescueEvery: rescueEvery, CleanEvery: cleanEvery, Retention: time.Millisecond, Clock: clock,
		}, Kind{Name: "t.work", Timeout: time.Minute, Mode: ModeDefault, Run: noop})

		lapsed := e.enqueueKind(t, "t.work")
		c := e.claimOne(t, "t.work", time.Minute)
		if c.ID != lapsed {
			t.Fatalf("claimed %d, want %d", c.ID, lapsed)
		}
		old := e.enqueueKind(t, "t.work")
		if err := e.d.ExecOwner(ctx, `UPDATE public.jobs SET claimed_until = now() - interval '1 second' WHERE id = $1`, lapsed); err != nil {
			t.Fatal(err)
		}
		if err := e.d.ExecOwner(ctx, `UPDATE public.jobs SET state = 'completed', finalized_at = now() - interval '1 hour' WHERE id = $1`, old); err != nil {
			t.Fatal(err)
		}

		// Another worker holds both leases.
		rl, ok, _ := AcquireLease(ctx, e.db, LeaseRescue, "worker-b", time.Hour)
		cl, ok2, _ := AcquireLease(ctx, e.db, LeaseClean, "worker-b", time.Hour)
		if !ok || !ok2 {
			t.Fatal("setup: worker-b could not take the leases")
		}
		stop, done := e.runWorker(w)
		defer func() { stop(); <-done }()

		tick := func(d time.Duration) {
			t.Helper()
			eventually(t, "timer registered", func() bool { return clock.fire(d) > 0 })
		}
		tick(rescueEvery)
		tick(cleanEvery)
		// Wait for the next round of timers: that proves the previous tick finished.
		eventually(t, "second rescue timer", func() bool { return clock.requested(rescueEvery) == 2 })
		eventually(t, "second clean timer", func() bool { return clock.requested(cleanEvery) == 2 })
		if st, _ := e.state(t, lapsed); st != "running" {
			t.Errorf("rescue ran without the lease: job is %s", st)
		}
		if got := e.countJobs(t, "t.work"); got != "2" {
			t.Errorf("clean ran without the lease: %s jobs remain, want 2", got)
		}

		// The other worker lets go: the next ticks run.
		if err := ReleaseLease(ctx, e.db, rl); err != nil {
			t.Fatal(err)
		}
		if err := ReleaseLease(ctx, e.db, cl); err != nil {
			t.Fatal(err)
		}
		tick(rescueEvery)
		tick(cleanEvery)
		eventually(t, "rescued", func() bool { st, _ := e.state(t, lapsed); return st == "available" })
		eventually(t, "cleaned", func() bool { return e.countJobs(t, "t.work") == "1" })
	})
}

func TestWorkerConfigIsValidated(t *testing.T) {
	for name, cfg := range map[string]WorkerConfig{
		"bad holder":      {Holder: "has space"},
		"concurrency":     {Concurrency: -1},
		"poll range":      {PollMin: time.Second, PollMax: time.Millisecond},
		"negative retain": {Retention: -time.Second},
	} {
		if err := cfg.defaults(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var ok WorkerConfig
	if err := ok.defaults(); err != nil || !holderPattern.MatchString(ok.Holder) {
		t.Errorf("defaults = %v, holder %q", err, ok.Holder)
	}
}
