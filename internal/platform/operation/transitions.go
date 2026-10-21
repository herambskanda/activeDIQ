package operation

import (
	"sort"
)

// This file declares the operation, item and step state machines of ADR-0005 rule 3 (DM-41,
// DM-42). The ADR's `transitions` block is the source; fitness function O4 and TestTableMatchesADR
// fail when this table differs from it by one edge. Persistence, audit events and the runner are
// out of scope here: the transition function that writes a state column arrives with the pipeline.

// Kind names which of the three state machines a transition belongs to.
type Kind string

// The three state machines. The same state name (planned, failed, ...) means different things in
// each, so every transition names its Kind.
const (
	KindOperation Kind = "operation"
	KindItem      Kind = "item"
	KindStep      Kind = "step"
)

// OperationState is the state of an Operation (DM-41).
type OperationState string

// Operation states.
const (
	OpDraft              OperationState = "draft"
	OpPlanning           OperationState = "planning"
	OpPlanned            OperationState = "planned"
	OpNoChange           OperationState = "no_change"
	OpPlanFailed         OperationState = "plan_failed"
	OpAwaitingApproval   OperationState = "awaiting_approval"
	OpApproved           OperationState = "approved"
	OpRejected           OperationState = "rejected"
	OpQueued             OperationState = "queued"
	OpRunning            OperationState = "running"
	OpSucceeded          OperationState = "succeeded"
	OpPartiallySucceeded OperationState = "partially_succeeded"
	OpFailed             OperationState = "failed"
	OpCancelling         OperationState = "cancelling"
	OpCancelled          OperationState = "cancelled"
)

// ItemState is the state of one OperationItem (DM-42).
type ItemState string

// Item states.
const (
	ItemPending   ItemState = "pending"
	ItemPlanned   ItemState = "planned"
	ItemSkipped   ItemState = "skipped"
	ItemBlocked   ItemState = "blocked"
	ItemRunning   ItemState = "running"
	ItemSucceeded ItemState = "succeeded"
	ItemFailed    ItemState = "failed"
	ItemCancelled ItemState = "cancelled"
	ItemUndone    ItemState = "undone"
)

// StepState is the state of one step of an item (DM-42 steps[]).
type StepState string

// Step states.
const (
	StepPlanned      StepState = "planned"
	StepApplying     StepState = "applying"
	StepApplied      StepState = "applied"
	StepVerified     StepState = "verified"
	StepVerifyFailed StepState = "verify_failed"
	StepFailed       StepState = "failed"
	StepNotRun       StepState = "not_run"
	StepUndone       StepState = "undone"
)

// Edge is one declared transition of one state machine.
type Edge struct {
	Kind Kind
	From string
	To   string
}

func (e Edge) String() string { return string(e.Kind) + ": " + e.From + " -> " + e.To }

func edge[S ~string](k Kind, from, to S) Edge {
	return Edge{Kind: k, From: string(from), To: string(to)}
}

// Kinds lists the state machines in declaration order.
func Kinds() []Kind { return []Kind{KindOperation, KindItem, KindStep} }

// declaredEdges is the transition table, in the ADR's order. It is built once and never mutated.
var declaredEdges = []Edge{
	// Operation (DM-41)
	edge(KindOperation, OpDraft, OpPlanning),
	edge(KindOperation, OpDraft, OpCancelled),
	edge(KindOperation, OpPlanning, OpPlanned),
	edge(KindOperation, OpPlanning, OpNoChange),
	edge(KindOperation, OpPlanning, OpPlanFailed),
	edge(KindOperation, OpPlanning, OpCancelled),
	edge(KindOperation, OpPlanned, OpApproved),
	edge(KindOperation, OpPlanned, OpAwaitingApproval),
	edge(KindOperation, OpPlanned, OpRejected),
	edge(KindOperation, OpPlanned, OpPlanning),
	edge(KindOperation, OpPlanned, OpCancelled),
	edge(KindOperation, OpAwaitingApproval, OpApproved),
	edge(KindOperation, OpAwaitingApproval, OpRejected),
	edge(KindOperation, OpAwaitingApproval, OpPlanning),
	edge(KindOperation, OpAwaitingApproval, OpCancelled),
	edge(KindOperation, OpApproved, OpQueued),
	edge(KindOperation, OpApproved, OpPlanning),
	edge(KindOperation, OpApproved, OpCancelled),
	edge(KindOperation, OpQueued, OpRunning),
	edge(KindOperation, OpQueued, OpCancelled),
	edge(KindOperation, OpRunning, OpSucceeded),
	edge(KindOperation, OpRunning, OpPartiallySucceeded),
	edge(KindOperation, OpRunning, OpFailed),
	edge(KindOperation, OpRunning, OpCancelling),
	edge(KindOperation, OpCancelling, OpCancelled),
	// OperationItem (DM-42)
	edge(KindItem, ItemPending, ItemPlanned),
	edge(KindItem, ItemPending, ItemSkipped),
	edge(KindItem, ItemPending, ItemBlocked),
	edge(KindItem, ItemPlanned, ItemRunning),
	edge(KindItem, ItemPlanned, ItemCancelled),
	edge(KindItem, ItemRunning, ItemSucceeded),
	edge(KindItem, ItemRunning, ItemFailed),
	edge(KindItem, ItemRunning, ItemCancelled),
	edge(KindItem, ItemSucceeded, ItemUndone),
	edge(KindItem, ItemFailed, ItemUndone),
	// Step (DM-42 steps[])
	edge(KindStep, StepPlanned, StepApplying),
	edge(KindStep, StepPlanned, StepNotRun),
	edge(KindStep, StepApplying, StepApplied),
	edge(KindStep, StepApplying, StepFailed),
	edge(KindStep, StepApplying, StepNotRun),
	edge(KindStep, StepApplied, StepVerified),
	edge(KindStep, StepApplied, StepVerifyFailed),
	edge(KindStep, StepVerified, StepUndone),
	edge(KindStep, StepVerifyFailed, StepUndone),
}

// terminalStates are the states nothing leaves except the explicit `-> undone` rows, which an
// Undo operation drives (ADR-0005 rule 3, "Terminal states").
var terminalStates = map[Kind][]string{
	KindOperation: {"no_change", "plan_failed", "rejected", "succeeded", "partially_succeeded", "failed", "cancelled"},
	KindItem:      {"skipped", "blocked", "succeeded", "failed", "cancelled", "undone"},
	KindStep:      {"not_run", "failed", "verify_failed", "verified", "undone"},
}

type edgeKey struct {
	kind     Kind
	from, to string
}

var (
	edgeSet     = map[edgeKey]struct{}{}
	stateSet    = map[Kind]map[string]struct{}{}
	terminalSet = map[Kind]map[string]struct{}{}
)

func init() {
	for _, k := range Kinds() {
		stateSet[k] = map[string]struct{}{}
		terminalSet[k] = map[string]struct{}{}
		for _, s := range terminalStates[k] {
			terminalSet[k][s] = struct{}{}
		}
	}
	for _, e := range declaredEdges {
		edgeSet[edgeKey{e.Kind, e.From, e.To}] = struct{}{}
		stateSet[e.Kind][e.From] = struct{}{}
		stateSet[e.Kind][e.To] = struct{}{}
	}
}

// Edges returns a copy of the declared transitions.
func Edges() []Edge { return append([]Edge(nil), declaredEdges...) }

// States returns the sorted states of one state machine, or nil for an unknown kind.
func States(kind Kind) []string {
	out := make([]string, 0, len(stateSet[kind]))
	for s := range stateSet[kind] {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// TerminalStates returns the sorted terminal states of one state machine.
func TerminalStates(kind Kind) []string {
	out := append([]string(nil), terminalStates[kind]...)
	sort.Strings(out)
	return out
}

// IsTerminal reports whether state is terminal in kind. Only `-> undone` leaves a terminal state.
func IsTerminal(kind Kind, state string) bool {
	_, ok := terminalSet[kind][state]
	return ok
}

// Known reports whether state is a declared state of kind.
func Known(kind Kind, state string) bool {
	_, ok := stateSet[kind][state]
	return ok
}

// Allowed reports whether the edge is declared.
func Allowed(kind Kind, from, to string) bool {
	_, ok := edgeSet[edgeKey{kind, from, to}]
	return ok
}

// Next returns the sorted states reachable from state in one declared transition.
func Next(kind Kind, from string) []string {
	var out []string
	for _, e := range declaredEdges {
		if e.Kind == kind && e.From == from {
			out = append(out, e.To)
		}
	}
	sort.Strings(out)
	return out
}

// Unknown stands in for a kind or state that is not declared. Callers' values never reach an
// error: they may come from a request or a database row.
const Unknown = "unknown"

// TransitionError is returned for an edge that the table does not declare. It names the kind and
// the two states; any of the three that is not declared is reported as Unknown, never echoed.
type TransitionError struct {
	Kind Kind
	From string
	To   string
}

func (e *TransitionError) Error() string {
	return "operation: undeclared " + string(e.Kind) + " transition " + e.From + " -> " + e.To
}

// Transition is the pure guard: nil when from -> to is a declared edge of kind, otherwise a
// *TransitionError. It does no I/O and holds no state.
func Transition(kind Kind, from, to string) error {
	if Allowed(kind, from, to) {
		return nil
	}
	e := &TransitionError{Kind: kind, From: from, To: to}
	if _, ok := stateSet[kind]; !ok {
		e.Kind, e.From, e.To = Unknown, Unknown, Unknown
		return e
	}
	if !Known(kind, from) {
		e.From = Unknown
	}
	if !Known(kind, to) {
		e.To = Unknown
	}
	return e
}
