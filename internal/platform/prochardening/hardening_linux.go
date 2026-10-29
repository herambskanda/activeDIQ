//go:build linux

package prochardening

import (
	"fmt"
	"syscall"
)

const prSetDumpable = 4 // PR_SET_DUMPABLE, linux/prctl.h

// disableDumps sets RLIMIT_CORE=0 (no core file) and PR_SET_DUMPABLE=0 (no ptrace attach or
// /proc/<pid>/mem read by same-uid processes, no core dump even if the limit is raised later).
func disableDumps() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("set RLIMIT_CORE=0: %w", err)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE,0): %w", errno)
	}
	return nil
}
