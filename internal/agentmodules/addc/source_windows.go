//go:build windows

package addc

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
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

// NewSource returns the wevtapi-backed source.
func NewSource() Source { return winSource{} }

// query builds the XPath filter from typed numbers only: nothing from a message or a document is
// interpolated as text (event IDs are uint32, the record id is uint64).
func query(after uint64, ids []uint32) string {
	var b strings.Builder
	b.WriteString("*[System[(EventRecordID>")
	b.WriteString(strconv.FormatUint(after, 10))
	b.WriteString(")")
	if len(ids) > 0 {
		b.WriteString(" and (")
		for i, id := range ids {
			if i > 0 {
				b.WriteString(" or ")
			}
			b.WriteString("EventID=")
			b.WriteString(strconv.FormatUint(uint64(id), 10))
		}
		b.WriteString(")")
	}
	b.WriteString("]]")
	return b.String()
}

func closeHandle(h uintptr) { _, _, _ = procEvtClose.Call(h) }

func (winSource) Subscribe(ctx context.Context, ch agentpolicy.Channel, after uint64, ids []uint32, emit func(RawEvent)) error {
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
	chPtr, err := windows.UTF16PtrFromString(logName(ch))
	if err != nil {
		return err
	}
	qPtr, err := windows.UTF16PtrFromString(query(after, ids))
	if err != nil {
		return err
	}
	h, _, e := procEvtSubscribe.Call(0, uintptr(sig), uintptr(unsafe.Pointer(chPtr)), uintptr(unsafe.Pointer(qPtr)), 0, 0, 0, flags)
	if h == 0 {
		if errors.Is(e, windows.ERROR_ACCESS_DENIED) {
			return ErrUnreadable
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
					return ErrUnreadable
				}
				return e
			}
			for i := uint32(0); i < n; i++ {
				if ev, err := render(evs[i]); err == nil {
					emit(ev)
				}
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
func render(ev uintptr) (RawEvent, error) {
	buf := make([]uint16, 4096)
	for {
		var used, props uint32
		r, _, e := procEvtRender.Call(0, ev, evtRenderEventXml, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return ParseEventXML([]byte(windows.UTF16ToString(buf[:used/2])))
		}
		if e != syscall.Errno(122) /* ERROR_INSUFFICIENT_BUFFER */ || int(used) > maxXMLBytes*2 {
			return RawEvent{}, e
		}
		buf = make([]uint16, used/2+1)
	}
}
