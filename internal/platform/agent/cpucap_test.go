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
	detail        string
}

func (r *recReporter) CapNotRestored(d string) { r.mu.Lock(); r.bad++; r.detail = d; r.mu.Unlock() }
func (r *recReporter) CapRestored()            { r.mu.Lock(); r.restored++; r.mu.Unlock() }
func (r *recReporter) counts() (int, int)      { r.mu.Lock(); defer r.mu.Unlock(); return r.bad, r.restored }

func newTestCap() (*cpuCap, *fakeJob, *recReporter) {
	j := &fakeJob{rate: 500}
	c := newCPUCap(500, 10000, j.set)
	c.sleep = func(time.Duration) {}
	c.retryEvery = time.Millisecond
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

func TestCapWindowDuringRepairKeepsRepairWaitingThenRestores(t *testing.T) {
	c, j, r := newTestCap()
	done := c.begin()
	j.failNext(restoreAttempts + 1000) // keeps failing until we say so
	done()
	if bad, _ := r.counts(); bad != 1 {
		t.Fatal("not reported")
	}
	during := c.begin() // cap is already lifted: no second lift, window counts
	j.failNext(0)
	time.Sleep(20 * time.Millisecond)
	if j.at() != 500 && j.at() != 10000 {
		t.Fatalf("unexpected rate %d", j.at())
	}
	if j.at() == 500 {
		t.Fatal("repair restored the cap under an open window")
	}
	during()
	waitFor(t, "restore after the window closed", func() bool { return j.at() == 500 })
	waitFor(t, "recovery report", func() bool { _, ok := r.counts(); return ok == 1 })
}
