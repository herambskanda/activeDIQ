package addc

import (
	"context"
	"errors"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
)

// Field is one rendered event data item. The renderer bounds count and size (render.go).
type Field struct{ Name, Value string }

// RawEvent is one event as read from a channel, already reduced to bounded fields.
type RawEvent struct {
	RecordID uint64
	EventID  uint32
	At       time.Time
	DCGUID   string
	Fields   []Field
}

// ErrUnreadable means the service identity may not read the channel (channel ACE missing or reset by
// GPO). It is reported in health, never worked around (ADR-0006 decision 2).
var ErrUnreadable = errors.New("addc: channel is not readable by the service identity")

// ErrUnsupported is returned on a platform with no event log API.
var ErrUnsupported = errors.New("addc: event log is not available on this platform")

// Source reads one channel. Subscribe delivers events with RecordID greater than after, in order, and
// blocks until ctx is done or the subscription fails. emit must be fast; it never performs I/O other
// than an outbox append.
type Source interface {
	Subscribe(ctx context.Context, ch agentpolicy.Channel, after uint64, ids []uint32, emit func(RawEvent)) error
}
