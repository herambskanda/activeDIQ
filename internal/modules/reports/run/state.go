// Package run is the report run path (T-0959; modules/reports.md §6, ADR-0010): the run record, the
// reports.run job, the one read gate (ReadAccess), the stored-result pages, the audit events and the
// retention sweep. It is the only package that compiles and executes a report query (RP3).
package run

import (
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

var (
	_ = tablekind.Declare(tablekind.Table{Name: "public.report_runs", Entity: "DM-72", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.report_run_rows", Entity: "DM-72", Kind: tablekind.Tenant})
)

// State is where a run is (§6.2). The set equals the CHECK list of report_runs.state.
type State string

// States.
const (
	StateQueued    State = "queued"
	StateRunning   State = "running"
	StateSucceeded State = "succeeded"
	StateFailed    State = "failed"
	StateCancelled State = "cancelled"
	StateExpired   State = "expired"
)

// States lists every state.
var States = []State{StateQueued, StateRunning, StateSucceeded, StateFailed, StateCancelled, StateExpired}

// Terminal reports whether no further work happens in s (succeeded still has its expiry flip).
func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateCancelled, StateExpired:
		return true
	}
	return false
}

// Final reports whether s can never change again.
func (s State) Final() bool { return s == StateFailed || s == StateCancelled || s == StateExpired }

// CanMoveTo reports whether s -> n is an edge of the table in §6.2. The report_runs_guard trigger
// enforces the same set.
func (s State) CanMoveTo(n State) bool {
	switch s {
	case StateQueued:
		return n == StateRunning || n == StateCancelled || n == StateFailed
	case StateRunning:
		return n == StateSucceeded || n == StateFailed || n == StateCancelled
	case StateSucceeded:
		return n == StateExpired
	}
	return false
}

// FailureReason says why a run failed (§6.2). The set equals the CHECK list of
// report_runs.failure_reason. The UI and the audit show the enum, never driver error text.
type FailureReason string

// Failure reasons.
const (
	FailRunnerInactive        FailureReason = "runner_inactive"
	FailTokenRefused          FailureReason = "token_refused"
	FailRowCapExceeded        FailureReason = "row_cap_exceeded"
	FailPerDCReadCapExceeded  FailureReason = "per_dc_read_cap_exceeded"
	FailScopeTooLarge         FailureReason = "scope_too_large"
	FailQueryTimeout          FailureReason = "query_timeout"
	FailConnectionUnavailable FailureReason = "connection_unavailable"
	FailDefinitionRetired     FailureReason = "definition_retired"
	FailInterrupted           FailureReason = "interrupted"
	FailInternal              FailureReason = "internal"
)

// FailureReasons lists every reason.
var FailureReasons = []FailureReason{
	FailRunnerInactive, FailTokenRefused, FailRowCapExceeded, FailPerDCReadCapExceeded, FailScopeTooLarge,
	FailQueryTimeout, FailConnectionUnavailable, FailDefinitionRetired, FailInterrupted, FailInternal,
}
