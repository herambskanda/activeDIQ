package operationtest

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// recordingSink keeps every event the runner appends, validated as the real sink would, and drops it
// with the rolled-back transaction. An event that fails Validate is kept too, with the error, so a
// missing field is reported under the audit clause and not as an unexplained run failure.
type recordingSink struct {
	mu      sync.Mutex
	events  []audit.Event
	invalid []string
}

func (s *recordingSink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	err := ev.Validate()
	ev.Changes = cloneChanges(ev.Changes)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	if err != nil {
		s.invalid = append(s.invalid, fmt.Sprintf("event %q (%s) failed audit.Event.Validate: %v", ev.ID, ev.Outcome, err))
	}
	return err
}

func (s *recordingSink) snapshot() ([]audit.Event, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events), slices.Clone(s.invalid)
}

func cloneChanges(cs []audit.Change) []audit.Change {
	out := slices.Clone(cs)
	for i := range out {
		out[i].Before, out[i].After = slices.Clone(out[i].Before), slices.Clone(out[i].After)
	}
	return out
}

// denyAfterPlan allows the authorisation the runner makes for each planned step at Plan time and
// refuses every later one: the Apply-time re-check, on facts read live immediately before the write
// (ADR-0005 rule 7). It remembers the target it refused, which is the target the denial event must name.
type denyAfterPlan struct {
	mu      sync.Mutex
	allowed int // authorisations allowed: one per planned step
	calls   int
	denied  *authority.TargetRef
}

var errContractDenied = fmt.Errorf("operationtest: contract denial")

func (d *denyAfterPlan) setAllowed(n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.allowed = n
}

func (d *denyAfterPlan) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (d *denyAfterPlan) Authorize(_ context.Context, _ authority.Chain, _ authz.Permission, t authority.TargetRef, _ authority.Facts) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.calls <= d.allowed {
		return nil
	}
	if d.denied == nil {
		d.denied = &t
	}
	return errContractDenied
}

func (d *denyAfterPlan) deniedTarget() (authority.TargetRef, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.denied == nil {
		return authority.TargetRef{}, false
	}
	return *d.denied, true
}

// eventWant is what one event must say.
type eventWant struct {
	kind      audit.Kind
	outcome   audit.Outcome
	actor     authority.Chain
	target    authority.TargetRef
	key       step.Key
	component string
	diff      []operation.Change // success events only: the plan's diff, which the event records
	checkDiff bool
}

// problems returns what is wrong with ev against want, one sentence each. It checks the AG-3 fields
// audit.Event carries (threat model §11): actor and on-behalf-of chain, target, outcome, correlation
// (the event ID and plan hash) and operation IDs, source component, and before/after with secrets
// redacted (AG-9). The verification factor, client IP and the target's DN at the time are not fields
// of audit.Event yet, so no Action can be held to them; see the package comment.
func problems(ev audit.Event, want eventWant) []string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	if ev.ID == "" {
		add("no event ID")
	}
	if ev.Kind != want.kind {
		add("kind %q, the Action declares %q", ev.Kind, want.kind)
	}
	if ev.At.IsZero() {
		add("no time")
	}
	if !sameChain(ev.Actor, want.actor) {
		add("actor chain is not the initiator chain of the request (requester and on-behalf-of principals)")
	}
	if ev.Target != want.target {
		add("target is not the planned step's target (GUID %q, class %q)", want.target.GUID, want.target.Class)
	}
	if ev.Key != want.key {
		add("operation/step key %+v, want %+v: the event cannot be correlated with the operation", ev.Key, want.key)
	}
	if ev.Component == "" || ev.Component != want.component {
		add("source component %q, want %q", ev.Component, want.component)
	}
	if ev.Outcome != want.outcome {
		add("outcome %q, want %q", ev.Outcome, want.outcome)
	}
	if ev.Reason == "" {
		add("no machine reason code")
	}
	if ev.PlanHash == "" {
		add("no plan hash")
	}
	for _, c := range ev.Changes {
		if c.Secret && (len(c.Before) > 0 || len(c.After) > 0) {
			add("change to %q is a secret and carries its values (AG-9)", c.Attribute)
		}
	}
	if want.checkDiff {
		out = append(out, diffProblems(ev.Changes, want.diff)...)
	}
	return out
}

func sameChain(a, b authority.Chain) bool {
	return a.Requester == b.Requester && slices.Equal(a.Via, b.Via)
}

// diffProblems compares the before/after an event records with the diff the plan previewed.
func diffProblems(got []audit.Change, plan []operation.Change) []string {
	if len(got) != len(plan) {
		return []string{fmt.Sprintf("records %d before/after change(s), the plan has %d", len(got), len(plan))}
	}
	var out []string
	for i, p := range plan {
		g := got[i]
		switch {
		case g.Attribute != p.Attribute || g.Secret != p.Secret:
			out = append(out, fmt.Sprintf("change %d is %q, the plan's is %q", i, g.Attribute, p.Attribute))
		case !p.Secret && (!slices.Equal(g.Before, p.Before) || !slices.Equal(g.After, p.After)):
			out = append(out, fmt.Sprintf("before/after of %q differ from the plan's diff", p.Attribute))
		}
	}
	return out
}
