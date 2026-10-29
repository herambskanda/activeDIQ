package main

import (
	"context"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
)

// repinTimeout bounds the network lookups of one repin run.
const repinTimeout = 60 * time.Second

// repin adopts newPin for the enrollment state in dir, keeping the component identity, and reports
// the outcome through audit exactly once (a parse failure of the state directory is reported too).
// It returns the process exit code.
func repin(dir, newPin string, audit func(msg string, failed bool)) int {
	ctx, cancel := context.WithTimeout(context.Background(), repinTimeout)
	defer cancel()
	reported := false
	err := dial.Repin(ctx, dir, newPin, func(e dial.RepinEvent) {
		reported = true
		if e.Err != nil {
			audit(fmt.Sprintf("repin from %s to %s failed: %v", e.OldPin, e.NewPin, e.Err), true)
			return
		}
		audit(fmt.Sprintf("repin from %s to %s succeeded; the component identity was kept", e.OldPin, e.NewPin), false)
	})
	if err != nil {
		if !reported {
			audit(fmt.Sprintf("repin to %s failed before any change: %v", newPin, err), true)
		}
		return 1
	}
	return 0
}
