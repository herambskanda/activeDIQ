package agent

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// CapReporter is told when the CPU cap could not be put back after a Burst window and when it later
// was. The Windows service wires it to the event log (events 105 and 106). The text carries an error
// class and number only.
type CapReporter interface {
	CapNotRestored(detail string)
	CapRestored()
	// CapFailClosed is the last report before the process exits because the cap stayed lifted past
	// failClosedAfter (event 105 with an exiting text). The exit happens whether or not it is written.
	CapFailClosed(detail string)
}

// cpuCap is the "lift the hard CPU cap for connection set-up, then put it back" logic, separate from
// the job-object calls so it is tested on every platform with a failing setter and an injectable clock
// (fault injection) and, on Windows, against a real job (confine_windows_test.go).
//
// Two hard limits (T-1249 security review, TM-TB12-T9), neither of which depends on the caller:
//   - Time: a lift lasts at most maxLift, even if the window is still open (a stalled or tarpitted
//     handshake). The cap goes back on when the timer fires; the rest of that attempt runs capped, and
//     a later close neither lifts nor restores again. Windows that overlap an expired one do not lift.
//   - Restore failure fails closed: it is retried at once, reported, and repaired in the background,
//     but if the cap is not back within failClosedAfter the process exits non-zero. The SCM recovery
//     action restarts it and Confine applies the cap again; if Confine fails the service stops, which
//     is the right outcome on a domain controller (the server sees the agent offline).
type cpuCap struct {
	steady, burst   uint32
	set             func(rate uint32) error
	sleep           func(time.Duration) // between the immediate retries; injectable
	retryEvery      time.Duration       // background repair period
	maxLift         time.Duration       // longest a single lift may last
	failClosedAfter time.Duration       // longest a failing restore may keep the cap off before exit
	now             func() time.Time
	afterFunc       func(d time.Duration, f func()) (stop func() bool)
	exit            func() // ends the process; os.Exit(1) in production

	mu        sync.Mutex
	armed     bool   // the job exists (Confine succeeded)
	open      int    // Burst windows currently open
	lifted    bool   // the job is at the burst rate (or may be: a restore failed)
	epoch     uint64 // identifies the current lift, so a stale timer does nothing
	stopTimer func() bool
	repairing bool
	failedAt  time.Time // when the current restore-failure episode began
	reporter  CapReporter
}

const (
	restoreAttempts = 3
	restoreBackoff  = 20 * time.Millisecond
	repairPeriod    = 2 * time.Second
	// maxLiftTime: an uncapped connection set-up measured 1.3 s on a lab DC; 5 s leaves margin.
	maxLiftTime = 5 * time.Second
	// failClosedTime: a cap that cannot be put back within this long ends the process.
	failClosedTime = 30 * time.Second
)

func newCPUCap(steady, burst uint32, set func(uint32) error) *cpuCap {
	return &cpuCap{steady: steady, burst: burst, set: set, sleep: time.Sleep, retryEvery: repairPeriod,
		maxLift: maxLiftTime, failClosedAfter: failClosedTime, now: time.Now,
		afterFunc: func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop },
		exit:      func() { os.Exit(1) }}
}

func (c *cpuCap) arm() { c.mu.Lock(); c.armed = true; c.mu.Unlock() }

func (c *cpuCap) setReporter(r CapReporter) { c.mu.Lock(); c.reporter = r; c.mu.Unlock() }

// begin opens a window. Not armed, or the lift failing, makes it a no-op (the agent connects slowly,
// still capped). The returned function closes the window exactly once.
func (c *cpuCap) begin() func() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.armed {
		return func() {}
	}
	if c.open == 0 && !c.lifted {
		if err := c.set(c.burst); err != nil {
			return func() {}
		}
		c.lifted = true
		c.epoch++
		epoch := c.epoch
		c.stopTimer = c.afterFunc(c.maxLift, func() { c.expire(epoch) })
	}
	c.open++
	var once sync.Once
	return func() { once.Do(c.end) }
}

func (c *cpuCap) end() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.open--
	if c.open == 0 && c.lifted { // not lifted: the maximum lift time already put the cap back
		c.restoreLocked()
	}
}

// expire is the maximum-lift timer: the cap goes back on although a window is still open.
func (c *cpuCap) expire(epoch uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if epoch != c.epoch || !c.lifted {
		return
	}
	c.restoreLocked()
}

// restoreLocked puts the cap back, with immediate retries; on failure it reports and starts the repair loop.
func (c *cpuCap) restoreLocked() {
	var err error
	for i := 0; i < restoreAttempts; i++ {
		if err = c.set(c.steady); err == nil {
			c.lifted = false
			if c.stopTimer != nil {
				c.stopTimer()
			}
			return
		}
		if i < restoreAttempts-1 {
			c.sleep(restoreBackoff)
		}
	}
	if c.repairing {
		return
	}
	c.repairing = true
	c.failedAt = c.now()
	if c.reporter != nil {
		c.reporter.CapNotRestored(fmt.Sprintf("restoring the CPU limit failed after %d attempts (%v); the agent is uncapped until a retry succeeds", restoreAttempts, err))
	}
	go c.repair()
}

// repair retries the restore until it works, however many windows are open (a window never keeps the
// cap off), and ends the process when failClosedAfter has passed.
func (c *cpuCap) repair() {
	for {
		time.Sleep(c.retryEvery)
		c.mu.Lock()
		if !c.lifted || c.set(c.steady) == nil { // !lifted: a window's own close restored it
			c.lifted, c.repairing = false, false
			if c.stopTimer != nil {
				c.stopTimer()
			}
			if c.reporter != nil {
				c.reporter.CapRestored()
			}
			c.mu.Unlock()
			return
		}
		if c.now().Sub(c.failedAt) >= c.failClosedAfter {
			rep := c.reporter
			c.mu.Unlock()
			if rep != nil {
				rep.CapFailClosed(fmt.Sprintf("the CPU limit was not restored within %s; the agent is exiting so the service recovery action restarts it capped", c.failClosedAfter))
			}
			c.exit()
			return
		}
		c.mu.Unlock()
	}
}
