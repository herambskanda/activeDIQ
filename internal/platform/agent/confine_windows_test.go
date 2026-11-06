//go:build windows

package agent

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// T-1249 review: the lift and restore of the CPU cap are read back from a real job object with
// QueryInformationJobObject, including a restore that fails and is repaired. These do not need elevation.

func mustRate(t *testing.T, job windows.Handle, want uint32, why string) {
	t.Helper()
	flags, rate, err := cpuRateOf(job)
	if err != nil {
		t.Fatalf("%s: QueryInformationJobObject: %v", why, err)
	}
	if rate != want || flags&cpuRateEnable == 0 || flags&cpuRateHardCap == 0 {
		t.Fatalf("%s: flags=%#x rate=%d, want hard cap enabled at %d", why, flags, rate, want)
	}
}

func newRealJob(t *testing.T) windows.Handle {
	t.Helper()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(job) })
	if err := setCPURate(job, steadyCPURate); err != nil {
		t.Fatal(err)
	}
	return job
}

type winReporter struct{ bad, ok atomic.Int32 }

func (r *winReporter) CapNotRestored(string) { r.bad.Add(1) }
func (r *winReporter) CapRestored()          { r.ok.Add(1) }
func (r *winReporter) CapFailClosed(string)  {}

// The maximum lift time puts the cap back on the real job while a window is still open; closing the
// window later does not lift or restore again.
func TestWindowsBurstMaxLiftRestoresRealJobWhileWindowOpen(t *testing.T) {
	job := newRealJob(t)
	c := newCPUCap(steadyCPURate, burstCPURate, func(r uint32) error { return setCPURate(job, r) })
	c.maxLift = 150 * time.Millisecond
	c.arm()
	done := c.begin()
	mustRate(t, job, burstCPURate, "inside a window")
	time.Sleep(c.maxLift + 400*time.Millisecond)
	mustRate(t, job, steadyCPURate, "after the maximum lift time, window still open")
	overlap := c.begin() // overlaps the expired window: must not lift again
	mustRate(t, job, steadyCPURate, "a window overlapping an expired one")
	done()
	overlap()
	mustRate(t, job, steadyCPURate, "after both windows closed")
	again := c.begin() // a fresh window lifts again, once
	mustRate(t, job, burstCPURate, "a fresh window")
	again()
	mustRate(t, job, steadyCPURate, "fresh window closed")
}

func TestWindowsBurstLiftsAndRestoresRealJob(t *testing.T) {
	job := newRealJob(t)
	mustRate(t, job, steadyCPURate, "before")
	c := newCPUCap(steadyCPURate, burstCPURate, func(r uint32) error { return setCPURate(job, r) })
	c.arm()
	a := c.begin()
	mustRate(t, job, burstCPURate, "inside a window")
	b := c.begin()
	mustRate(t, job, burstCPURate, "nested window")
	a()
	a()
	mustRate(t, job, burstCPURate, "one of two windows closed")
	b()
	mustRate(t, job, steadyCPURate, "after the last window")
}

func TestWindowsBurstRestoreFailureIsRepairedOnRealJob(t *testing.T) {
	job := newRealJob(t)
	var fail atomic.Int32
	set := func(r uint32) error {
		if r == steadyCPURate && fail.Add(-1) >= 0 {
			return errors.New("injected restore failure")
		}
		return setCPURate(job, r)
	}
	c := newCPUCap(steadyCPURate, burstCPURate, set)
	c.retryEvery = 5 * time.Millisecond
	rep := &winReporter{}
	c.setReporter(rep)
	c.arm()
	done := c.begin()
	fail.Store(restoreAttempts + 2) // every immediate retry and two background ones fail
	done()
	if rep.bad.Load() != 1 {
		t.Fatalf("failed restore reported %d times, want 1", rep.bad.Load())
	}
	mustRate(t, job, burstCPURate, "while the restore is failing (the visible, reported state)")
	deadline := time.Now().Add(5 * time.Second)
	for rep.ok.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if rep.ok.Load() != 1 {
		t.Fatal("repair never reported recovery")
	}
	mustRate(t, job, steadyCPURate, "after the background repair")
}

// The real Confine and Burst in a child process (Confine puts the process in a job it cannot leave, so
// it must not run in the test binary): the child reads its own job back (NULL handle = the calling
// process's job) before Burst, inside it, after nested closes.
func TestWindowsConfineAndBurstInChild(t *testing.T) {
	if os.Getenv("DIQ_CONFINE_CHILD") == "1" {
		childConfine(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsConfineAndBurstInChild$", "-test.v")
	cmd.Env = append(os.Environ(), "DIQ_CONFINE_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "CHILD-OK") {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
}

func childConfine(t *testing.T) {
	if err := Confine(); err != nil {
		t.Fatalf("Confine: %v", err)
	}
	if err := Confine(); err != nil { // idempotent: the idle loop calls it every pass
		t.Fatalf("second Confine: %v", err)
	}
	mustRate(t, 0, steadyCPURate, "after Confine")
	one := Burst()
	mustRate(t, 0, burstCPURate, "inside Burst")
	two := Burst()
	one()
	mustRate(t, 0, burstCPURate, "nested window still open")
	two()
	two()
	mustRate(t, 0, steadyCPURate, "after Burst closed")
	// The real timer (maxLiftTime): a window held open past it is capped again.
	held := Burst()
	mustRate(t, 0, burstCPURate, "inside a held window")
	time.Sleep(maxLiftTime + time.Second)
	mustRate(t, 0, steadyCPURate, "held window past the maximum lift time")
	held()
	mustRate(t, 0, steadyCPURate, "held window closed late")
	t.Log("CHILD-OK")
}
