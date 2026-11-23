package agent

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Application-log event IDs for conditions the agent's structured log reports while it is running
// under the SCM, which discards stderr (T-1277). Documented in knowledge/development/runbooks/
// dc-agent-operations.md. 103 and 104 are reserved for the start-up reports of T-1249.
const (
	EventTunnelUnreachable  = 110 // server not reachable: connection refused, timeout, network down
	EventTunnelResolve      = 111 // the server's host name does not resolve
	EventTunnelTLSTrust     = 112 // the server's certificate was not accepted (pin, CA, name or validity)
	EventTunnelTLSHandshake = 113 // TLS failed for another reason, including the server refusing our certificate
	EventTunnelRejected     = 114 // the server refused the agent's identity (unauthenticated or denied)
	EventTunnelProtocol     = 115 // the server broke the tunnel protocol
	EventTunnelTransport    = 116 // the tunnel ended for any other transport reason
	EventAgentWarning       = 118 // any other warning the agent logged
	EventAgentError         = 119 // any other error the agent logged
)

// tunnelClasses maps the err_kind token tunnelclient logs to its event ID. "closed" (a clean end of
// a tunnel that was up) is deliberately absent: it is not a failure.
var tunnelClasses = map[string]uint32{
	"unreachable":   EventTunnelUnreachable,
	"resolve":       EventTunnelResolve,
	"tls_trust":     EventTunnelTLSTrust,
	"tls_handshake": EventTunnelTLSHandshake,
	"rejected":      EventTunnelRejected,
	"protocol":      EventTunnelProtocol,
	"transport":     EventTunnelTransport,
}

// EventReporter is where the service log handler delivers an event: on Windows the Application log.
// It must not block and must be safe for concurrent use.
type EventReporter interface {
	Report(level slog.Level, id uint32, msg string)
}

const (
	// DefaultEventInterval is how often one failure class may write an event. A tunnel that cannot
	// dial retries up to once a second at first; the log must not grow with the retry rate.
	DefaultEventInterval = 15 * time.Minute
	maxEventMessage      = 240 // bytes of a free message; longer is cut
	maxOtherKeys         = 32  // distinct generic messages tracked before they share one bucket
)

// ServiceLog is a slog.Handler for the agent running under the SCM. It forwards every record to Next
// (stderr JSON, useful in the foreground and under a debugger) and reports Warn and Error records to
// the event log, bounded and with a fixed shape:
//
//   - the event text is the record's constant message plus its err_kind token and nothing else, so no
//     error text, address, token or key material from the record's attributes can reach the log
//     (the T-1277 acceptance criterion); messages are code literals, never formatted from data, and
//     are cut at maxEventMessage bytes;
//   - each class (tunnel failure kind, or generic message) writes at most one event per Interval; the
//     next event of that class says how many were suppressed meanwhile. A different class is never
//     suppressed by another, and the number of tracked classes is bounded.
type ServiceLog struct {
	Next     slog.Handler
	Reporter EventReporter
	Interval time.Duration
	Now      func() time.Time

	mu    *sync.Mutex
	state map[string]*classState
}

type classState struct {
	last       time.Time
	suppressed int
}

// NewServiceLog returns the handler. A nil reporter makes it a pure pass-through to next.
func NewServiceLog(next slog.Handler, r EventReporter) *ServiceLog {
	return &ServiceLog{Next: next, Reporter: r, Interval: DefaultEventInterval, Now: time.Now,
		mu: new(sync.Mutex), state: map[string]*classState{}}
}

// Enabled implements slog.Handler.
func (h *ServiceLog) Enabled(ctx context.Context, l slog.Level) bool {
	return (h.Reporter != nil && l >= slog.LevelWarn) || h.Next.Enabled(ctx, l)
}

// WithAttrs implements slog.Handler. Bound attributes reach Next only; they are never reported.
func (h *ServiceLog) WithAttrs(a []slog.Attr) slog.Handler {
	c := *h
	c.Next = h.Next.WithAttrs(a)
	return &c
}

// WithGroup implements slog.Handler.
func (h *ServiceLog) WithGroup(n string) slog.Handler {
	c := *h
	c.Next = h.Next.WithGroup(n)
	return &c
}

// Handle implements slog.Handler. It never returns an error from the reporting path: logging must not
// disturb the agent.
func (h *ServiceLog) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if h.Next.Enabled(ctx, r.Level) {
		err = h.Next.Handle(ctx, r)
	}
	if h.Reporter != nil && r.Level >= slog.LevelWarn {
		h.report(r)
	}
	return err
}

func (h *ServiceLog) report(r slog.Record) {
	kind := ""
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "err_kind" && a.Value.Kind() == slog.KindString {
			kind = a.Value.String()
			return false
		}
		return true
	})
	var id uint32
	key := ""
	msg := cut(r.Message)
	switch {
	case kind == "closed":
		return
	case tunnelClasses[kind] != 0:
		id, key = tunnelClasses[kind], "tunnel/"+kind
		msg = "tunnel ended: " + kind
	case kind != "": // an unknown token is never echoed
		id, key = EventTunnelTransport, "tunnel/transport"
		msg = "tunnel ended: transport"
	case r.Level >= slog.LevelError:
		id, key = EventAgentError, "msg/"+msg
	default:
		id, key = EventAgentWarning, "msg/"+msg
	}
	n, ok := h.admit(key)
	if !ok {
		return
	}
	if n > 0 {
		msg += " (" + strconv.Itoa(n) + " more since the last report)"
	}
	level := slog.LevelWarn
	if r.Level >= slog.LevelError {
		level = slog.LevelError
	}
	h.Reporter.Report(level, id, msg)
}

// admit applies the per-class rate limit and returns how many records of the class were suppressed
// since its last event.
func (h *ServiceLog) admit(key string) (suppressed int, ok bool) {
	now := h.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if strings.HasPrefix(key, "msg/") && h.state[key] == nil && h.countOther() >= maxOtherKeys {
		key = "msg/*"
	}
	s := h.state[key]
	if s == nil {
		h.state[key] = &classState{last: now}
		return 0, true
	}
	if now.Sub(s.last) < h.Interval && !now.Before(s.last) {
		s.suppressed++
		return 0, false
	}
	n := s.suppressed
	s.suppressed, s.last = 0, now
	return n, true
}

func (h *ServiceLog) countOther() int {
	n := 0
	for k := range h.state {
		if strings.HasPrefix(k, "msg/") {
			n++
		}
	}
	return n
}

// cut bounds a message at maxEventMessage bytes on a rune boundary.
func cut(s string) string {
	if len(s) <= maxEventMessage {
		return s
	}
	s = s[:maxEventMessage]
	for len(s) > 0 {
		if r, size := utf8.DecodeLastRuneInString(s); r == utf8.RuneError && size <= 1 {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	return s + "..."
}
