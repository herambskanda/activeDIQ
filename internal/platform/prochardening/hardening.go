// Package prochardening disables core dumps and ptrace for every product process (TM-TB16-T6):
// RLIMIT_CORE=0, PR_SET_DUMPABLE=0, and refusal of GOTRACEBACK=crash. Every cmd/* main calls Apply first.
package prochardening

import (
	"fmt"
	"strings"
)

// refuseCrashTraceback rejects GOTRACEBACK values that make the Go runtime abort with a core dump
// (TM-TB16-T6). A crash dump of this process would contain key material and directory credentials.
// "crash" raises SIGABRT on fatal errors; "wer" does the equivalent on Windows. Values may be a
// comma-free level optionally followed by other tokens only in the form the runtime accepts, so we
// match on the whole value case-insensitively.
func refuseCrashTraceback(getenv func(string) string) error {
	v := strings.ToLower(strings.TrimSpace(getenv("GOTRACEBACK")))
	if v == "crash" || v == "wer" {
		return fmt.Errorf("GOTRACEBACK=%s is refused: it makes a fatal error write a core dump that would expose secrets; unset it or use none/single/all/system", getenv("GOTRACEBACK"))
	}
	return nil
}

// Apply applies the dump-suppression settings before any secret is loaded.
func Apply(getenv func(string) string) error {
	if err := refuseCrashTraceback(getenv); err != nil {
		return err
	}
	return disableDumps()
}
