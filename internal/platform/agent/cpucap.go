package agent

import (
	"fmt"
	"sync"
	"time"
)

// CapReporter is told when the CPU cap could not be put back after a Burst window and when it later
// was. The Windows service wires it to the event log (events 105 and 106). The text carries an error
// class and number only.
type CapReporter interface {
	CapNotRestored(detail string)
	CapRestored()
}

// cpuCap is the reference-counted "lift the hard CPU cap for connection set-up, then put it back"
// logic, separate from the job-object calls so it is tested on every platform with a failing setter
// (fault injection) and, on Windows, against a real job (confine_windows_test.go).
//
// Fail-closed intent (T-1249 review): a restore that fails is retried at once and then in the
// background until it succeeds; it is reported (distinct event, error severity) the first time, and
// again as recovered. While it is failing the agent runs uncapped, which is a reported, visible state
// with a bounded repair loop, never a silent one. No new window can start a second lift while one is
// pending (the cap is already lifted), and a window that opens during the repair makes the repair wait
// for it to close.
type cpuCap struct {
	steady, burst uint32
	set           func(rate uint32) error
	sleep         func(time.Duration) // between the immediate retries; injectable
	retryEvery    time.Duration       // background repair period

	mu        sync.Mutex
	armed     bool // the job exists (Confine succeeded)
	open      int  // Burst windows currently open
	lifted    bool // the job is at the burst rate (or may be: a restore failed)
	repairing bool
	reporter  CapReporter
}

const (
	restoreAttempts = 3
	restoreBackoff  = 20 * time.Millisecond
	repairPeriod    = 2 * time.Second
)

func newCPUCap(steady, burst uint32, set func(uint32) error) *cpuCap {
	return &cpuCap{steady: steady, burst: burst, set: set, sleep: time.Sleep, retryEvery: repairPeriod}
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
	}
	c.open++
	var once sync.Once
	return func() { once.Do(c.end) }
}

func (c *cpuCap) end() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.open--
	if c.open == 0 {
		c.restoreLocked()
	}
}

// restoreLocked puts the cap back, with immediate retries; on failure it reports and starts the repair loop.
func (c *cpuCap) restoreLocked() {
	var err error
	for i := 0; i < restoreAttempts; i++ {
		if err = c.set(c.steady); err == nil {
			c.lifted = false
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
	if c.reporter != nil {
		c.reporter.CapNotRestored(fmt.Sprintf("restoring the CPU limit failed after %d attempts (%v); the agent is uncapped until a retry succeeds", restoreAttempts, err))
	}
	go c.repair()
}

func (c *cpuCap) repair() {
	for {
		time.Sleep(c.retryEvery)
		c.mu.Lock()
		if c.open == 0 { // a window in flight closes through restoreLocked itself
			if !c.lifted || c.set(c.steady) == nil { // lifted is false when a window's own close restored it
				c.lifted, c.repairing = false, false
				if c.reporter != nil {
					c.reporter.CapRestored()
				}
				c.mu.Unlock()
				return
			}
		}
		c.mu.Unlock()
	}
}
