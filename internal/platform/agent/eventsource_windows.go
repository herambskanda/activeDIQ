//go:build windows

package agent

import (
	"context"
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/skenzeriq/activediq/internal/agenthost/hostapi"
)

// Windows event log API, wevtapi.dll. Contract of each call:
// https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log-reference
var (
	wevtapi          = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = wevtapi.NewProc("EvtSubscribe")
	procEvtNext      = wevtapi.NewProc("EvtNext")
	procEvtRender    = wevtapi.NewProc("EvtRender")
	procEvtClose     = wevtapi.NewProc("EvtClose")
)

const (
	evtSubscribeToFutureEvents          = 1
	evtSubscribeStartAtOldestRec        = 2
	evtRenderEventXml                   = 1
	errorNoMoreItems                    = syscall.Errno(259)
	maxBatch                            = 64
	waitSliceMs                  uint32 = 1000
)

type winSource struct{}

// NewEventSource returns the wevtapi-backed source.
func NewEventSource() hostapi.EventSource { return winSource{} }

func closeHandle(h uintptr) { _, _, _ = procEvtClose.Call(h) }

func (winSource) Subscribe(ctx context.Context, ch hostapi.Channel, after uint64, ids []uint16, emit func([]byte)) error {
	name, err := channelPath(ch)
	if err != nil {
		return err
	}
	// The record-id filter makes StartAtOldestRecord safe: only events newer than the bookmark return.
	// A zero bookmark (first run) subscribes to future events only; history before enrolment is not
	// ours to read (data minimisation).
	flags := uintptr(evtSubscribeStartAtOldestRec)
	if after == 0 {
		flags = evtSubscribeToFutureEvents
	}
	sig, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(sig)
	chPtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	qPtr, err := windows.UTF16PtrFromString(eventQuery(after, ids))
	if err != nil {
		return err
	}
	h, _, e := procEvtSubscribe.Call(0, uintptr(sig), uintptr(unsafe.Pointer(chPtr)), uintptr(unsafe.Pointer(qPtr)), 0, 0, 0, flags)
	if h == 0 {
		if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
			return hostapi.ErrUnreadable
		}
		return e
	}
	defer closeHandle(h)
	var evs [maxBatch]uintptr
	for {
		for {
			var n uint32
			r, _, e := procEvtNext.Call(h, maxBatch, uintptr(unsafe.Pointer(&evs[0])), 1000, 0, uintptr(unsafe.Pointer(&n)))
			if r == 0 {
				if e == errorNoMoreItems {
					break
				}
				if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
					return hostapi.ErrUnreadable
				}
				return e
			}
			for i := uint32(0); i < n; i++ {
				emit(render(evs[i]))
				closeHandle(evs[i])
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, _ = windows.WaitForSingleObject(sig, waitSliceMs)
	}
}

// render calls EvtRender(EvtRenderEventXml) with a size-probe retry, bounded by maxXMLBytes.
// A failure yields an Unparsable placeholder, never a skipped event.
func render(ev uintptr) []byte {
	buf := make([]uint16, 4096)
	for {
		var used, props uint32
		r, _, e := procEvtRender.Call(0, ev, evtRenderEventXml, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return []byte(windows.UTF16ToString(buf[:used/2]))
		}
		if e != syscall.Errno(122) /* ERROR_INSUFFICIENT_BUFFER */ || int(used) > hostapi.MaxEventXMLBytes*2 {
			return nil
		}
		buf = make([]uint16, used/2+1)
	}
}

var (
	procEvtOpenLog    = wevtapi.NewProc("EvtOpenLog")
	procEvtGetLogInfo = wevtapi.NewProc("EvtGetLogInfo")
)

const (
	evtOpenChannelPath       = 1
	evtLogOldestRecordNumber = 6 // EVT_LOG_PROPERTY_ID [UNVERIFIED — lab]
)

// OldestRecord reads EvtLogOldestRecordNumber with EvtGetLogInfo.
// https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtgetloginfo
func (winSource) OldestRecord(ch hostapi.Channel) (uint64, error) {
	name, err := channelPath(ch)
	if err != nil {
		return 0, err
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, _, e := procEvtOpenLog.Call(0, uintptr(unsafe.Pointer(p)), evtOpenChannelPath)
	if h == 0 {
		return 0, e
	}
	defer closeHandle(h)
	var v [16]byte // EVT_VARIANT: 8-byte union, Count, Type
	var used uint32
	r, _, e := procEvtGetLogInfo.Call(h, evtLogOldestRecordNumber, uintptr(len(v)), uintptr(unsafe.Pointer(&v[0])), uintptr(unsafe.Pointer(&used)))
	if r == 0 {
		return 0, e
	}
	return *(*uint64)(unsafe.Pointer(&v[0])), nil
}
