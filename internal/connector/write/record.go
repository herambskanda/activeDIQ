package write

import (
	"context"
	"log/slog"
)

// Event is the connector's local record of one Plan or Apply, including every refusal (TM-TB6-T5).
// It carries identifiers only: never a value, a peer list, a fingerprint or credential material.
type Event struct {
	Op      string // "plan" or "apply"
	Outcome string // "ok", "refused" or "failed"
	Code    string // ConnectorError code when not ok
	Stage   string // step of §8.1 that ended the call
	// Object is the object a tier0 refusal named (the connector's own log only).
	Object string
	Bases  []string

	// Reason, PropertyOp and PropertyKeys are the audit-ready record of a property-write refusal
	// (contract §8.9): the reason, the declared operation and the attribute key names. Never values.
	Reason       string
	PropertyKind string // USER, DEVICE or GROUP: the declared kind of the check
	PropertyOp   string
	PropertyKeys []string

	Operation, Item, Step, Attempt string
	Account, Token                 string
	PlanDigest                     string

	// The context the server sent (F6 detective control).
	Tier0Revision     uint64
	Statements, Peers int
	Ignored           int

	// Override admission (TM-D23 rule 9); set only when the gate passed through the override.
	OverrideID     string
	OverrideAcked  int
	OverrideListed int

	// TierAfterWrite lists objects found tier0 after a write (rule 11); an empty-basis entry marks
	// an object that could not be classified.
	Tier0AfterWrite []string
}

// Recorder receives the local record. It must not block for long and must not fail the call: a
// durable record that is required (the ratchet) goes through Baseline, not here.
type Recorder interface{ Record(Event) }

// SlogRecorder writes events to a slog logger.
type SlogRecorder struct{ L *slog.Logger }

// Record implements Recorder.
func (r SlogRecorder) Record(e Event) {
	l := r.L
	if l == nil {
		l = slog.Default()
	}
	attrs := []any{"op", e.Op, "outcome", e.Outcome, "code", e.Code, "stage", e.Stage,
		"operation_id", e.Operation, "item", e.Item, "step", e.Step, "attempt", e.Attempt,
		"account_id", e.Account, "api_token_id", e.Token, "plan_digest", e.PlanDigest,
		"tier0_revision", e.Tier0Revision, "statements", e.Statements, "peers", e.Peers, "statements_ignored", e.Ignored}
	if e.Object != "" {
		attrs = append(attrs, "refused_object", e.Object, "bases", e.Bases)
	}
	if e.Reason != "" {
		attrs = append(attrs, "reason", e.Reason, "property_kind", e.PropertyKind, "property_op", e.PropertyOp, "property_keys", e.PropertyKeys)
	}
	if e.OverrideID != "" {
		attrs = append(attrs, "override_id", e.OverrideID, "override_acknowledged", e.OverrideAcked, "override_listed", e.OverrideListed)
	}
	if e.Tier0AfterWrite != nil {
		attrs = append(attrs, "tier0_after_write", e.Tier0AfterWrite)
	}
	lvl := slog.LevelInfo
	if e.Outcome != "ok" {
		lvl = slog.LevelWarn
	}
	if len(e.Tier0AfterWrite) > 0 {
		lvl = slog.LevelError
	}
	l.Log(context.Background(), lvl, "connector write", attrs...)
}
