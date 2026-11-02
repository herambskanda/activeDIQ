//go:build windows

package agent

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Event IDs written to the Windows Application log by source "activeDIQ Agent" (documented in the
// agent runbook). The source's message file is .NET's EventLogMessages.dll (registered by the MSI),
// whose message table is a bare "%1" for every ID, so each event renders its insertion string.
// Verified on the lab DC (T-1249 log: AC3.renders, AC5 wevtutil): events render their insertion string
// with no empty description. Path/behaviour reference:
// https://learn.microsoft.com/dotnet/api/system.diagnostics.eventlog
const (
	EventApplied        = 100 // a policy or keyset was applied (what, sequence; never content)
	EventStartRefused   = 101 // the agent refused to start (reason class only)
	EventChannelUnread  = 102
	EventNotEnrolled    = 103 // installed but not enrolled: idling until `agent enroll` runs (warning)
	EventStateUnusable  = 104 // enrolment state exists but cannot be used; the class is in the text (error, T-1249)
	EventCapNotRestored = 105 // the CPU limit lifted for connection set-up could not be put back (error, T-1249)
	EventCapRestored    = 106 // ...and was put back by a later retry (information)
)

var (
	advapi              = windows.NewLazySystemDLL("advapi32.dll")
	procRegisterSource  = advapi.NewProc("RegisterEventSourceW")
	procDeregisterSrc   = advapi.NewProc("DeregisterEventSource")
	procReportEvent     = advapi.NewProc("ReportEventW")
	eventLogInformation = 4
	eventLogError       = 1
	eventLogWarning     = 2
)

// EventLog writes to the Application log. Contract:
// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw
type EventLog struct{ h uintptr }

// OpenEventLog registers the source handle. The source itself is created by the MSI.
func OpenEventLog(source string) (*EventLog, error) {
	p, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return nil, err
	}
	h, _, e := procRegisterSource.Call(0, uintptr(unsafe.Pointer(p)))
	if h == 0 {
		return nil, e
	}
	return &EventLog{h: h}, nil
}

// Close releases the handle.
func (l *EventLog) Close() { _, _, _ = procDeregisterSrc.Call(l.h) }

func (l *EventLog) report(kind int, id uint32, msg string) {
	s, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	_, _, _ = procReportEvent.Call(l.h, uintptr(kind), 0, uintptr(id), 0, 1, 0, uintptr(unsafe.Pointer(&s)), 0)
}

// Applied records that a policy or keyset was applied. Only the kind and sequence are written.
func (l *EventLog) Applied(what string, seq uint64) {
	l.report(eventLogInformation, EventApplied, fmt.Sprintf("%s applied, sequence %d", what, seq))
}

// Failed records that the agent stopped. The error text of the agent's own refusals contains no
// secrets or server-supplied text by construction.
func (l *EventLog) Failed(err error) {
	l.report(eventLogError, EventStartRefused, "agent stopped: "+err.Error())
}

// NotEnrolled records, once per service start, that the agent is waiting for enrolment. It is a
// warning, not a failure: the service stays running and picks up enrolment on its own.
func (l *EventLog) NotEnrolled() {
	l.report(eventLogWarning, EventNotEnrolled, "agent is installed but not enrolled; run `activediq-agent.exe enroll <server:port> <pin>` — waiting")
}

// StateUnusable records that enrolment state exists but was refused, with the class (unsafe-permissions,
// expired, corrupt) and the rule that failed. It is an error, distinct from 103 which means "no
// enrolment yet". The service keeps running and re-checks, so fixing the state needs no restart. The
// text names a file and a rule, never a SID list, path of secrets or content.
func (l *EventLog) StateUnusable(class, detail string) {
	l.report(eventLogError, EventStateUnusable, "enrolment state cannot be used ("+class+"); the agent is not connecting. "+detail)
}

// CapNotRestored records that the CPU limit lifted for connection set-up could not be restored; the
// agent retries in the background. detail is an error class and number, never content.
func (l *EventLog) CapNotRestored(detail string) {
	l.report(eventLogError, EventCapNotRestored, "agent CPU limit not restored: "+detail)
}

// CapFailClosed records, as event 105, that the CPU limit stayed off past the fail-closed deadline and
// the agent is exiting so the SCM recovery action restarts it with the cap re-applied.
func (l *EventLog) CapFailClosed(detail string) {
	l.report(eventLogError, EventCapNotRestored, "agent CPU limit not restored, exiting: "+detail)
}

// CapRestored records that a retry put the CPU limit back.
func (l *EventLog) CapRestored() {
	l.report(eventLogInformation, EventCapRestored, "agent CPU limit restored")
}
