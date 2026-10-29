// Package api is the boundary between the agent host and an agent module (ADR-0006, T-0688 ruling 1):
// module -> api <- host. The host implements these interfaces and hands a module a ModuleDeps; a
// module imports this package and nothing of the host. There is no path, file, process, registry,
// network or service-control capability here, and fitness-agent-host R3 keeps it that way by limiting
// what this package itself may import.
package api

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc"

	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

// Event is the wire record a module appends. Aliases keep generated RegisterXServer calls and the
// sink compiling without a module-side import of grpc or the host's wire package.
type Event = agentv1.AgentEvent

// ServiceRegistrar is the tunnel's registrar a module's own service is registered on.
type ServiceRegistrar = grpc.ServiceRegistrar

// CollectionState is what a module reports to GetStatus.
type CollectionState = agentv1.CollectionState

// EventSink is how a module hands the host an observed event. It is the module's only way out.
type EventSink interface {
	// Append stores the record and returns its sequence. It never blocks on the network and never
	// waits; on a full or failing disk it returns an error and the caller carries on.
	Append(*Event) (uint64, error)
	// Flush makes everything appended so far durable.
	Flush() error
}

// Blobs is the small named-blob store a module gets instead of a path (its bookmark, for example).
// A name is lower-case letters, digits and dashes; there is no way to name a path.
type Blobs interface {
	Load(name string) ([]byte, error)
	Save(name string, data []byte) error
}

// Channel names an event log channel by the closed enum the host validates. The values match
// agentpolicy.Channel; a value outside the enum is refused by the host, never turned into a path or
// an XPath fragment.
type Channel uint8

const (
	ChannelSecurity         Channel = 1
	ChannelDirectoryService Channel = 2
)

// MaxEventXMLBytes bounds one rendered event the host returns.
const MaxEventXMLBytes = 256 << 10

var (
	// ErrUnreadable means the service identity may not read the channel (channel ACE missing or reset
	// by GPO). It is the fail-closed signal of ADR-0006 decision 2: reported in health, never retried
	// in a tight loop and never worked around.
	ErrUnreadable = errors.New("agent: channel is not readable by the service identity")
	// ErrUnsupported is returned on a platform with no event log API.
	ErrUnsupported = errors.New("agent: event log is not available on this platform")
	// ErrBadChannel is returned for a channel outside the closed enum.
	ErrBadChannel = errors.New("agent: unknown event log channel")
)

// EventSource is a read-only view of the Windows event log. The host builds the query from these
// typed arguments; no module-supplied string reaches XPath.
type EventSource interface {
	// OldestRecord returns the oldest record id still in the channel (0 when empty or unknown).
	OldestRecord(ch Channel) (uint64, error)
	// Subscribe delivers the rendered XML of events with record id greater than after (and, when ids
	// is not empty, one of ids), in order, until ctx is done or the subscription fails. after == 0
	// means future events only. Each xml is at most MaxEventXMLBytes; an unrenderable event is
	// delivered as nil so the caller can record a gap. emit must be fast.
	Subscribe(ctx context.Context, ch Channel, after uint64, ids []uint16, emit func(xml []byte)) error
}

// ModuleDeps is the whole of what a module is given (contract §1).
type ModuleDeps struct {
	Events EventSink
	Blobs  Blobs
	Log    *slog.Logger
	Now    func() time.Time
	Source EventSource
}

// EventField is one name/value item of an Event.
type EventField = agentv1.EventField

// EventKind and its values, re-exported so a module needs no import of the wire package.
type EventKind = agentv1.EventKind

const (
	EventKindEvent = agentv1.EventKind_EVENT_KIND_EVENT
	EventKindGap   = agentv1.EventKind_EVENT_KIND_GAP
)

// Collection states a module reports.
const (
	CollectionUnspecified       = agentv1.CollectionState_COLLECTION_STATE_UNSPECIFIED
	CollectionNoPolicy          = agentv1.CollectionState_COLLECTION_STATE_NO_POLICY
	CollectionStoppedByPolicy   = agentv1.CollectionState_COLLECTION_STATE_STOPPED_BY_POLICY
	CollectionChannelUnreadable = agentv1.CollectionState_COLLECTION_STATE_CHANNEL_UNREADABLE
	CollectionRunning           = agentv1.CollectionState_COLLECTION_STATE_RUNNING
)
