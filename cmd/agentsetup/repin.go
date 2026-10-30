package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
)

// repinTimeout bounds the network lookups of one repin run.
const repinTimeout = 60 * time.Second

// agentEventSource is the Application-log source the MSI registers (Agent.wxs util:EventSource) and
// the agent logs under. Audit events must use it so SIEM rules on the documented source see them.
const agentEventSource = "activeDIQ Agent"

// auditSink records one audit message; failed selects the failure event.
type auditSink func(msg string, failed bool)

// openAudit opens the audit sink and returns it with its closer. It is called before anything is
// changed: if it fails, repin does not run (the audit record is the control for this verb).
type openAudit func() (auditSink, func(), error)

// runRepin opens the audit sink first, refusing to proceed without it, then repins. actor names the
// invoking account and host and is part of every message.
func runRepin(dir, newPin, actor string, open openAudit) int {
	audit, closeSink, err := open()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentsetup: repin refused, the audit log cannot be opened:", err)
		return 1
	}
	defer closeSink()
	return repin(dir, newPin, func(msg string, failed bool) {
		audit("by "+actor+": "+msg, failed)
	})
}

// repin adopts newPin for the enrollment state in dir, keeping the component identity, and reports
// the outcome through audit exactly once (a parse failure of the state directory is reported too).
// It returns the process exit code.
func repin(dir, newPin string, audit auditSink) int {
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
