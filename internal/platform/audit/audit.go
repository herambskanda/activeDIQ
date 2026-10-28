// Package audit holds the event envelope of activeDIQ's own audit trail and the one port every
// appender uses (ADR-0005 rule 11). An event is requested inside the caller's transaction with
// Sink.Append, so it commits or rolls back with the change it describes (AG-1).
//
// This package carries the envelope and the port, and the per-tenant hash chain that implements Sink:
// the commit-time Chainer, signed checkpoints, and export. The pure format (canonical encoding, hash
// links, verifier) is in the standard-library-only subpackages canon and chain, which cmd/auditverify
// links. Tests of other packages give the runner a recording Sink.
package audit

import (
	"context"
	"errors"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/personal"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Kind names an event type, for example "operation.step.applied". It is registered by the owner of
// the Action that emits it (EP-7).
type Kind string

// Outcome is the result an event records.
type Outcome string

// Outcomes. A failed write and a refused write are both recorded (AG-2).
const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
)

// Change is one attribute's before and after value. A secret attribute carries neither value (AG-9).
// The values are personal data: the Chainer stores them in the personal side store at commit and the
// chained envelope holds a personal reference per value (T-0306), never the value. Subject names the
// person the values are about (dir:<connection>:<objectGUID> or acct:<id>, see personal.DirSubject). A
// change with no Subject is not about a person (a connection state, say) and records counts only.
type Change struct {
	Subject   string
	Attribute string
	Before    []string
	After     []string
	Secret    bool
}

// Detail is one public detail of an event; Event.Details is a slice of them in key order. Packages that
// may import audit but not audit/chain (ADR-0005 rule 13) name the type through this alias.
type Detail = chain.Detail

// Envelope is a chained event's canonical envelope (what Render takes), and Checkpoint a signed chain
// head (what an Anchor receives). The aliases, and ParseEnvelope, let packages that may import audit but
// not audit/chain (rule 13) read a stored envelope and implement an Anchor.
type (
	Envelope   = chain.Envelope
	Checkpoint = chain.Checkpoint
)

// ParseEnvelope decodes a stored envelope; it is chain.ParseEnvelope.
func ParseEnvelope(b []byte) (Envelope, error) { return chain.ParseEnvelope(b) }

// Snapshot is a display value (a name or similar) as it read when the event happened. Like a change value
// it is kept by reference.
type Snapshot struct {
	Subject string
	Field   string
	Value   string
}

// Event is the envelope (AG-3). The client address is a personal value too and is not a field yet.
type Event struct {
	ID        string // stable per logical event: a retried append reuses it, so an ambiguous commit is not recorded twice
	Kind      Kind
	At        time.Time
	Actor     authority.Chain
	Target    authority.TargetRef
	Key       step.Key
	Component string
	Outcome   Outcome
	Reason    string // machine reason code, never free text from a directory or a secret
	PlanHash  string
	Changes   []Change
	// Snapshots are display values kept by personal reference.
	Snapshots []Snapshot
	// Details are typed public details of the kind, in strictly increasing key order. They never carry
	// a secret or a personal value (ADR-0005 rules 11 and 12).
	Details []chain.Detail
}

// ErrInvalidEvent is returned by Validate for an event missing a field every event needs.
var ErrInvalidEvent = errors.New("audit: invalid event")

// Validate refuses an event without an ID, kind, time, requester or outcome.
func (e Event) Validate() error {
	if e.ID == "" || e.Kind == "" || e.At.IsZero() || e.Actor.Validate() != nil {
		return ErrInvalidEvent
	}
	for _, s := range e.Snapshots {
		if s.Subject == "" || s.Field == "" {
			return ErrInvalidEvent
		}
	}
	// An event about a directory object carries that object's subject on every value it records, so a
	// legal hold finds it (ADR-0005 rule 11, A9). A change with values and no Subject would be kept as
	// counts only and fall outside every hold.
	if _, person := personal.DirSubject(e.Target.Connection, e.Target.GUID); person {
		for _, c := range e.Changes {
			if c.Subject == "" && !c.Secret && (len(c.Before) > 0 || len(c.After) > 0) {
				return ErrInvalidEvent
			}
		}
	}
	switch e.Outcome {
	case Success, Failure, Denied:
		return nil
	}
	return ErrInvalidEvent
}

// Sink appends an event inside tx, the caller's transaction. Implementations chain the event at
// commit; they never open a transaction of their own.
type Sink interface {
	Append(ctx context.Context, tx store.Tx, ev Event) error
}
