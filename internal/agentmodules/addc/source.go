package addc

import (
	"context"
	"time"

	"github.com/skenzeriq/activediq/internal/agenthost/api"
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
	// Unparsable marks an event the reader could not render or parse. RecordID is best effort (0 when
	// unknown). The collector turns it into an explicit GAP record: an event is never dropped silently.
	Unparsable bool
}

// ErrUnreadable and ErrUnsupported are the host's typed errors (internal/agenthost/api).
var (
	ErrUnreadable  = api.ErrUnreadable
	ErrUnsupported = api.ErrUnsupported
)

// Source reads one channel. Subscribe delivers events with RecordID greater than after, in order, and
// blocks until ctx is done or the subscription fails. emit must be fast; it never performs I/O other
// than an outbox append.
type Source interface {
	// OldestRecord returns the oldest record id still in the channel (0 when empty or unknown). The
	// collector compares it with the bookmark to tell a wrapped or cleared log from a filtered one.
	OldestRecord(ch agentpolicy.Channel) (uint64, error)
	Subscribe(ctx context.Context, ch agentpolicy.Channel, after uint64, ids []uint32, emit func(RawEvent)) error
}

// FromAPI adapts the host's read-only event source to Source. The host builds the query from the typed
// arguments; this side only decodes the rendered XML (DecodeEvent, pure and fuzzable). An event the
// host could not render arrives as nil and becomes an explicit unparsable record, never a skip.
func FromAPI(es api.EventSource) Source { return apiSource{es} }

type apiSource struct{ es api.EventSource }

func (a apiSource) OldestRecord(ch agentpolicy.Channel) (uint64, error) {
	return a.es.OldestRecord(api.Channel(ch))
}

func (a apiSource) Subscribe(ctx context.Context, ch agentpolicy.Channel, after uint64, ids []uint32, emit func(RawEvent)) error {
	u := make([]uint16, 0, len(ids))
	for _, id := range ids {
		if id > 0xFFFF {
			continue // not a valid event id; the catalogue holds none
		}
		u = append(u, uint16(id))
	}
	return a.es.Subscribe(ctx, api.Channel(ch), after, u, func(xml []byte) {
		if xml == nil {
			emit(RawEvent{Unparsable: true})
			return
		}
		emit(DecodeEvent(xml))
	})
}
