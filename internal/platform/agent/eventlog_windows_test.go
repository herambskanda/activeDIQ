//go:build windows

package agent

import (
	"log/slog"
	"sync"
	"testing"
)

// The tunnel goroutine can log while the service shuts down: a report after Close must be a no-op,
// not a call on a deregistered handle, and Close must be idempotent (T-1277).
// ReportEvent on a source with no registered message file still succeeds; the text just renders
// with the "description cannot be found" preamble, so this runs on any Windows host.
func TestEventLogReportAfterCloseIsNoOp(t *testing.T) {
	l, err := OpenEventLog("activeDIQ Agent")
	if err != nil {
		t.Fatalf("OpenEventLog: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				l.Report(slog.LevelWarn, EventTunnelUnreachable, "tunnel ended: unreachable")
			}
		}()
	}
	l.Close()
	wg.Wait()
	l.Close()
	l.Report(slog.LevelError, EventAgentError, "after close")
}
