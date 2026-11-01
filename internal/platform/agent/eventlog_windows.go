//go:build windows

package agent

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Event IDs written to the Windows Application log by source "activeDIQ Agent" (documented in the
// agent runbook). They are within 1..1000 so a source registered with EventCreate.exe as its message
// file renders them [UNVERIFIED — lab].
const (
	EventApplied       = 100 // a policy or keyset was applied (what, sequence; never content)
	EventStartRefused  = 101 // the agent refused to start (reason class only)
	EventChannelUnread = 102
)

var (
	advapi              = windows.NewLazySystemDLL("advapi32.dll")
	procRegisterSource  = advapi.NewProc("RegisterEventSourceW")
	procDeregisterSrc   = advapi.NewProc("DeregisterEventSource")
	procReportEvent     = advapi.NewProc("ReportEventW")
	eventLogInformation = 4
	eventLogError       = 1
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
