//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

const prGetDumpable = 3

func TestHardenProcessChild(t *testing.T) {
	if os.Getenv("T0634_CHILD") != "1" {
		t.Skip("child helper")
	}
	if err := hardenProcess(func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rl); err != nil || rl.Cur != 0 || rl.Max != 0 {
		t.Fatalf("RLIMIT_CORE = %+v, err %v", rl, err)
	}
	r, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 || r != 0 {
		t.Fatalf("dumpable = %d, errno %v", r, errno)
	}
}

// Run in a subprocess so the test binary itself is not left undumpable.
func TestHardenProcessSetsLimits(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHardenProcessChild$", "-test.v")
	cmd.Env = append(os.Environ(), "T0634_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS") || strings.Contains(string(out), "SKIP") {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
}
