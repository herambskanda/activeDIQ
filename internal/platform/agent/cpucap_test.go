package agent

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeJob records the rate the "job" is at and can be told to fail the next n sets.
type fakeJob struct {
	mu   sync.Mutex
	rate uint32
	fail int
	n    int
}

func (j *fakeJob) set(r uint32) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.n++
	if j.fail > 0 {
		j.fail--
		return errors.New("injected SetInformationJobObject failure")
	}
	j.rate = r
	return nil
}

func (j *fakeJob) at() uint32     { j.mu.Lock(); defer j.mu.Unlock(); return j.rate }
func (j *fakeJob) failNext(n int) { j.mu.Lock(); j.fail = n; j.mu.Unlock() }

type recReporter struct {
	mu            sync.Mutex
	bad, restored int
	detail, fatal string
}

func (r *recReporter) CapNotRestored(d string) { r.mu.Lock(); r.bad++; r.detail = d; r.mu.Unlock() }
func (r *recReporter) CapRestored()            { r.mu.Lock(); r.restored++; r.mu.Unlock() }
func (r *recReporter) CapFailClosed(d string)  { r.mu.Lock(); r.fatal = d; r.mu.Unlock() }
func (r *recReporter) counts() (int, int)      { r.mu.Lock(); defer r.mu.Unlock(); return r.bad, r.restored }

func newTestCap() (*cpuCap, *fakeJob, *recReporter) {
	j := &fakeJob{rate: 500}
	c := newCPUCap(500, 10000, j.set)
	c.sleep = func(time.Duration) {}
	c.retryEvery = time.Millisecond
	c.afterFunc = func(time.Duration, func()) func() bool { return func() bool { return true } } // timer never fires
	c.exit = func() { panic("exit called in a test that does not expect it") }
	r := &recReporter{}
	c.setReporter(r)
	c.arm()
	return c, j, r
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 2000; i++ {
		if ok() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestCapNotArmedIsNoop(t *testing.T) {
	j := &fakeJob{rate: 500}
	c := newCPUCap(500, 10000, j.set)
	c.begin()()
	if j.n != 0 {
		t.Fatalf("an unarmed cap touched the job %d times", j.n)
	}
}

func TestCapLiftsAndRestoresReferenceCounted(t *testing.T) {
	c, j, r := newTestCap()
	a := c.begin()
	if j.at() != 10000 {
		t.Fatal("not lifted inside a window")
	}
	b := c.begin()
	a()
	a() // second close of the same window is a no-op
	if j.at() != 10000 {
		t.Fatal("restored while a second window was still open")
	}
	b()
	if j.at() != 500 {
		t.Fatalf("not restored after the last window: %d", j.at())
	}
	if bad, _ := r.counts(); bad != 0 {
		t.Fatal("reported a fault on the happy path")
	}
}

func TestCapLiftFailureIsNoopAndStaysCapped(t *testing.T) {
	c, j, _ := newTestCap()
	j.failNext(1)
	done := c.begin()
	if j.at() != 500 {
		t.Fatal("rate changed although the lift failed")
	}
	done()
	if j.at() != 500 {
		t.Fatal("closing a failed window changed the rate")
	}
}

func TestCapRestoreRetriesImmediately(t *testing.T) {
	c, j, r := newTestCap()
	done := c.begin()
	j.failNext(restoreAttempts - 1)
	done()
	if j.at() != 500 {
		t.Fatalf("a transient restore failure left the cap lifted: %d", j.at())
	}
	if bad, _ := r.counts(); bad != 0 {
		t.Fatal("reported a fault that the immediate retry cured")
	}
}

func TestCapRestoreFailureIsReportedRepairedAndReportedAgain(t *testing.T) {
	c, j, r := newTestCap()
	done := c.begin()
	j.failNext(restoreAttempts + 3) // all immediate retries and a few background ones fail
	done()
	if bad, _ := r.counts(); bad != 1 {
		t.Fatalf("restore failure reported %d times, want 1", bad)
	}
	if r.detail == "" {
		t.Fatal("report has no detail")
	}
	waitFor(t, "background repair", func() bool { return j.at() == 500 })
	waitFor(t, "recovery report", func() bool { _, ok := r.counts(); return ok == 1 })
	if bad, _ := r.counts(); bad != 1 {
		t.Fatalf("a repeated failure was reported %d times, want once per episode", bad)
	}
}

// fakeClock holds the maximum-lift timer so a test fires it by hand.
type fakeClock struct {
	mu      sync.Mutex
	t       time.Time
	pending []func()
	delays  []time.Duration
}

func (f *fakeClock) after(d time.Duration, fn func()) func() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = append(f.pending, fn)
	f.delays = append(f.delays, d)
	return func() bool { return true }
}
func (f *fakeClock) now() time.Time          { f.mu.Lock(); defer f.mu.Unlock(); return f.t }
func (f *fakeClock) advance(d time.Duration) { f.mu.Lock(); f.t = f.t.Add(d); f.mu.Unlock() }
func (f *fakeClock) fire(i int) {
	f.mu.Lock()
	fn := f.pending[i]
	f.mu.Unlock()
	fn()
}
func (f *fakeClock) timers() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.pending) }

func TestCapMaxLiftRestoresWhileWindowStillOpen(t *testing.T) {
	c, j, r := newTestCap()
	clk := &fakeClock{}
	c.afterFunc = clk.after
	done := c.begin()
	if clk.timers() != 1 || clk.delays[0] != maxLiftTime {
		t.Fatalf("lift armed %d timers, delays %v; want one for %s", clk.timers(), clk.delays, maxLiftTime)
	}
	if j.at() != 10000 {
		t.Fatal("not lifted")
	}
	clk.fire(0) // the window is still open (a stalled handshake)
	if j.at() != 500 {
		t.Fatalf("cap not restored at the maximum lift time with the window open: %d", j.at())
	}
	n := j.n
	overlap := c.begin() // overlaps the expired window: no new lift, no new timer
	if j.at() != 500 || clk.timers() != 1 || j.n != n {
		t.Fatalf("a window overlapping an expired lift lifted again (rate %d, timers %d)", j.at(), clk.timers())
	}
	done()
	overlap()
	if j.at() != 500 || j.n != n {
		t.Fatalf("closing expired windows touched the job (rate %d, sets %d->%d)", j.at(), n, j.n)
	}
	if bad, _ := r.counts(); bad != 0 {
		t.Fatal("reported a fault on a normal expiry")
	}
	again := c.begin() // a fresh window after everything closed lifts once more
	if j.at() != 10000 || clk.timers() != 2 {
		t.Fatal("a fresh window did not lift")
	}
	again()
	if j.at() != 500 {
		t.Fatal("fresh window not restored")
	}
}

func TestCapStaleTimerDoesNothing(t *testing.T) {
	c, j, _ := newTestCap()
	clk := &fakeClock{}
	c.afterFunc = clk.after
	c.begin()() // first lift, closed in time
	second := c.begin()
	clk.fire(0) // the first lift's timer fires late, during the second lift
	if j.at() != 10000 {
		t.Fatal("a stale timer ended a newer lift")
	}
	second()
}

func TestCapExpiryRestoreFailureIsReportedAndRepaired(t *testing.T) {
	c, j, r := newTestCap()
	clk := &fakeClock{}
	c.afterFunc = clk.after
	done := c.begin()
	j.failNext(restoreAttempts + 2)
	clk.fire(0)
	if bad, _ := r.counts(); bad != 1 {
		t.Fatal("restore failure at expiry not reported")
	}
	waitFor(t, "repair after expiry", func() bool { return j.at() == 500 })
	waitFor(t, "recovery report", func() bool { _, ok := r.counts(); return ok == 1 })
	done()
	if j.at() != 500 {
		t.Fatal("late close lifted the cap")
	}
}

// A restore that keeps failing ends the process (fail closed): the SCM recovery action restarts it
// and Confine re-applies the cap. No endless repair loop, and an open window does not hold it off.
func TestCapPersistentRestoreFailureExits(t *testing.T) {
	c, j, r := newTestCap()
	clk := &fakeClock{}
	c.now = clk.now
	c.afterFunc = clk.after
	exited := make(chan struct{})
	c.exit = func() { close(exited) }
	done := c.begin()
	j.failNext(1 << 30)
	done()
	if bad, _ := r.counts(); bad != 1 {
		t.Fatal("not reported")
	}
	_ = c.begin() // a window opened while the repair runs must not keep it waiting
	clk.advance(c.failClosedAfter - time.Second)
	select {
	case <-exited:
		t.Fatal("exited before the fail-closed deadline")
	case <-time.After(30 * time.Millisecond):
	}
	clk.advance(2 * time.Second)
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("a restore failing past the deadline did not end the process")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fatal == "" {
		t.Fatal("no fail-closed report before exit")
	}
}

func TestCapExitsEvenWithoutReporter(t *testing.T) {
	c, j, _ := newTestCap()
	c.setReporter(nil) // OpenEventLog failed: the restore failure must still be fatal
	clk := &fakeClock{}
	c.now = clk.now
	exited := make(chan struct{})
	c.exit = func() { close(exited) }
	done := c.begin()
	j.failNext(1 << 30)
	done()
	clk.advance(c.failClosedAfter)
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("no exit without a reporter")
	}
}
