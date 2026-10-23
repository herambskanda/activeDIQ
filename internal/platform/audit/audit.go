// Package audit holds the event envelope of activeDIQ's own audit trail and the one port every
// appender uses (ADR-0005 rule 11). An event is requested inside the caller's transaction with
// Sink.Append, so it commits or rolls back with the change it describes (AG-1).
//
// This package carries the envelope and the port. The per-tenant hash chain that implements Sink
// (the commit-time chainer, checkpoints, export, verifier) is T-0132; until it lands the runner is
// given a Sink by its host, and the tests give it a recording one.
package audit

import (
	"context"
	"errors"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
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
type Change struct {
	Attribute string
	Before    []string
	After     []string
	Secret    bool
}

// Event is the envelope (AG-3). Display snapshots and the client address are personal values and
// arrive with the personal side store; they are not fields here.
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
}

// ErrInvalidEvent is returned by Validate for an event missing a field every event needs.
var ErrInvalidEvent = errors.New("audit: invalid event")

// Validate refuses an event without an ID, kind, time, requester or outcome.
func (e Event) Validate() error {
	if e.ID == "" || e.Kind == "" || e.At.IsZero() || e.Actor.Validate() != nil {
		return ErrInvalidEvent
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
