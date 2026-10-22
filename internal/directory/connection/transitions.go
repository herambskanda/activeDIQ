package connection

import "slices"

// State is the lifecycle state of a Connection (DM-10).
type State string

// The DM-10 states. Health is observed and the one-word list status is derived: neither is a state.
const (
	StateDraft           State = "draft"
	StateVerifying       State = "verifying"
	StateActive          State = "active"
	StateSuspended       State = "suspended"
	StateDecommissioning State = "decommissioning"
	StateRemoved         State = "removed"
	StateDiscarded       State = "discarded"
)

// States lists every state, in lifecycle order.
func States() []State {
	return []State{StateDraft, StateVerifying, StateActive, StateSuspended, StateDecommissioning, StateRemoved, StateDiscarded}
}

// Edge is one legal transition. Row names the forest connection spec's §6 row (L1–L10) it implements.
type Edge struct {
	From, To State
	Row      string
}

// edges is the DM-10 lifecycle, verbatim (domain-model.md DM-10 "Lifecycle"; creation, L1, is not a
// transition). It is the only declaration of legal state changes: a pair not listed is illegal.
// Spec L10 (a duplicate identity) and L11 (re-verifying an active connection) are not transitions.
var edges = []Edge{
	{StateDraft, StateVerifying, "L2"},
	{StateVerifying, StateDraft, "L3"},
	{StateDraft, StateActive, "L4"},
	{StateVerifying, StateActive, "L4"},
	{StateActive, StateSuspended, "L5"},
	{StateSuspended, StateActive, "L6"},
	{StateActive, StateDecommissioning, "L7"},
	{StateSuspended, StateDecommissioning, "L7"},
	{StateDecommissioning, StateRemoved, "L8"},
	{StateDraft, StateDiscarded, "L9"},
}

// Edges returns a copy of the declared transitions.
func Edges() []Edge { return slices.Clone(edges) }

// CanTransition reports whether from → to is a declared edge.
func CanTransition(from, to State) bool {
	return slices.ContainsFunc(edges, func(e Edge) bool { return e.From == from && e.To == to })
}

// Valid reports whether s is a DM-10 state.
func (s State) Valid() bool { return slices.Contains(States(), s) }

// Terminal reports whether no transition leaves s.
func (s State) Terminal() bool {
	return !slices.ContainsFunc(edges, func(e Edge) bool { return e.From == s })
}

// retires reports whether entering s sets retired_at (I13).
func (s State) retires() bool { return s == StateDecommissioning || s == StateDiscarded }
