package operationtest

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// reversibilityViolations runs the inverse of every step the success run applied and checks the
// three clauses that rest on it (ADR-0005 O5 third clause and O7):
//
//   - inverse-available: a step the Plan calls Reversible or Lossy has an Inverse that returns an
//     input, not ErrIrreversible;
//   - inverse-restores: apply, inverse, apply: after the inverse the fake directory and the fixture's
//     State are as they were before the first apply, and the second apply reaches the first apply's
//     after-state;
//   - lossy-undeclared: for a Lossy step, only what Fixture.Lost declares may differ.
//
// The inverses run in reverse order, each as its own operation through the same runner as the
// forward run, so the inverse is planned, authorised, applied and verified like any other change.
func (h *harness) reversibilityViolations() []Violation {
	h.mu.Lock()
	applied := slices.Clone(h.applied)
	haveBefore := h.haveBefore
	h.mu.Unlock()
	if len(applied) == 0 || !haveBefore {
		return nil // nothing was applied: there is no inverse to run
	}
	var vs []Violation
	add := func(clause, format string, a ...any) { vs = append(vs, Violation{clause, fmt.Sprintf(format, a...)}) }

	type inv struct {
		in   operation.Input
		item int
	}
	var invs []inv
	lossy, unavailable := false, false
	for _, a := range applied {
		cls := a.sp.Reversibility
		if cls == operation.Irreversible {
			continue // the Plan says there is no inverse, and the runner holds the Descriptor to it
		}
		h.exercise(ClauseInverseAvailable)
		if cls == operation.Lossy {
			lossy = true
			if strings.TrimSpace(a.sp.ReversibilityReason) == "" {
				add(ClauseLossyUndeclared, "step %d is Lossy and its plan gives no ReversibilityReason, so the preview cannot say what is lost", a.key.Item)
			}
		}
		in, err := h.inner.Inverse(a.sp, a.out)
		switch {
		case errors.Is(err, operation.ErrIrreversible):
			unavailable = true
			add(ClauseInverseAvailable, "step %d is planned %s and the Descriptor declares %s, but Inverse returns ErrIrreversible for the contract fixture (O5)",
				a.key.Item, cls, h.d.Reversibility)
		case err != nil:
			unavailable = true
			add(ClauseInverseAvailable, "Inverse of step %d returned an error: %v", a.key.Item, err)
		default:
			invs = append(invs, inv{in, a.key.Item})
		}
	}
	if unavailable || len(invs) == 0 {
		return vs
	}
	seesState := h.fx.Directory != nil || h.fx.State != nil
	if !seesState {
		return vs // no state the harness can see: inverse-restores is not exercised
	}

	// The inverse and the second apply are the harness's own work: the write counters a test reads
	// afterwards stay what the forward run made them.
	if dir := h.fx.Directory; dir != nil {
		w, c := dir.Writes(), dir.Changes()
		defer dir.resetCounters(w, c)
	}
	// Where the forward run left things; the inverse and the second apply are compared with it.
	h.mu.Lock()
	if h.fx.Directory != nil {
		h.afterForward = h.fx.Directory.snapshot()
	}
	h.afterState = h.state()
	h.mu.Unlock()

	invAct := h.fx.InverseAction
	if invAct == nil {
		invAct = h.inner
	}
	for i := len(invs) - 1; i >= 0; i-- {
		out, err := h.run(asStore{invAct}, allowAll{}, invs[i].in, fmt.Sprintf("inverse-%d", invs[i].item))
		if err != nil {
			add(ClauseInverseAvailable, "the inverse Action cannot be registered: %v", err)
			return vs
		}
		if out.err != nil {
			add(ClauseInverseRestores, "running the inverse of step %d failed: %v", invs[i].item, out.err)
			return vs
		}
	}
	h.exercise(ClauseInverseRestores)
	if lossy {
		h.exercise(ClauseLossyUndeclared)
	}
	diffs := h.stateDiffs(h.before, h.beforeState)
	vs = append(vs, h.classify(diffs, lossy, "after apply and inverse, the state differs from the before-state")...)

	// ...and apply again: the same after-state as the first apply.
	out, err := h.run(asStore{h.inner}, allowAll{}, h.fx.Input, "reapply")
	if err != nil {
		add(ClauseInverseRestores, "the Action cannot be registered for the second apply: %v", err)
		return vs
	}
	if out.err != nil {
		add(ClauseInverseRestores, "applying again after the inverse failed: %v", out.err)
		return vs
	}
	diffs = h.stateDiffs(h.afterForward, h.afterState)
	vs = append(vs, h.classify(diffs, lossy, "applying again after the inverse did not reach the first apply's after-state")...)
	return vs
}

// stateDiffs lists what differs between the live state and a reference taken earlier: "<guid>/<attr>"
// for the fake directory and "State" for the fixture's State.
func (h *harness) stateDiffs(ref snapshot, refState any) []string {
	var out []string
	if h.fx.Directory != nil {
		out = diffSnapshots(ref, h.fx.Directory.snapshot())
	}
	if h.fx.State != nil && !reflect.DeepEqual(refState, h.fx.State()) {
		out = append(out, "State")
	}
	return out
}

// diffSnapshots lists "<guid>/<attribute>" for every attribute whose values differ, sorted.
func diffSnapshots(a, b snapshot) []string {
	seen := map[string]bool{}
	var out []string
	note := func(g, attr string) {
		k := g + "/" + attr
		if !seen[k] && !slices.Equal(a[g][attr], b[g][attr]) {
			seen[k] = true
			out = append(out, k)
		}
	}
	for g, attrs := range a {
		for attr := range attrs {
			note(g, attr)
		}
	}
	for g, attrs := range b {
		for attr := range attrs {
			note(g, attr)
		}
	}
	sort.Strings(out)
	return out
}

// classify turns differences into violations. A Reversible plan may differ nowhere. A Lossy plan may
// differ only where Fixture.Lost declares it.
func (h *harness) classify(diffs []string, lossy bool, what string) []Violation {
	if len(diffs) == 0 {
		return nil
	}
	if !lossy {
		return []Violation{{ClauseInverseRestores, fmt.Sprintf("%s: %s", what, strings.Join(diffs, ", "))}}
	}
	var undeclared []string
	for _, d := range diffs {
		if !h.declaredLost(d) {
			undeclared = append(undeclared, d)
		}
	}
	if len(undeclared) == 0 {
		return nil
	}
	return []Violation{{ClauseLossyUndeclared, fmt.Sprintf("%s, and Fixture.Lost does not declare: %s", what, strings.Join(undeclared, ", "))}}
}

func (h *harness) declaredLost(diff string) bool {
	if diff == "State" {
		return slices.Contains(h.fx.Lost, "State")
	}
	_, attr, _ := strings.Cut(diff, "/")
	return slices.Contains(h.fx.Lost, diff) || slices.Contains(h.fx.Lost, attr)
}

// successEventViolations holds the success run's events to AG-3: one per applied step, each with the
// fields the planned step and the request give it.
func (h *harness) successEventViolations(out runOut) []Violation {
	h.mu.Lock()
	applied := slices.Clone(h.applied)
	op := h.op
	h.mu.Unlock()
	if len(applied) == 0 {
		return nil
	}
	h.exercise(ClauseAuditSuccess)
	events, invalid := out.sink.snapshot()
	var vs []Violation
	for _, msg := range invalid {
		vs = append(vs, Violation{ClauseAuditSuccess, msg})
	}
	var got []audit.Event
	for _, ev := range events {
		if ev.Outcome == audit.Success {
			got = append(got, ev)
		}
	}
	ids := map[string]bool{}
	for _, a := range applied {
		i := slices.IndexFunc(got, func(ev audit.Event) bool { return ev.Key == a.key })
		if i < 0 {
			vs = append(vs, Violation{ClauseAuditSuccess, fmt.Sprintf("no success event for step %d: a change that committed has no record (AG-2)", a.key.Item)})
			continue
		}
		ev := got[i]
		if ids[ev.ID] {
			vs = append(vs, Violation{ClauseAuditSuccess, fmt.Sprintf("event ID %q is used by two events", ev.ID)})
		}
		ids[ev.ID] = true
		for _, p := range problems(ev, eventWant{kind: h.d.AuditKind, outcome: audit.Success, actor: h.actor, target: a.sp.Target,
			key: a.key, component: component, diff: a.sp.Diff, checkDiff: true}) {
			vs = append(vs, Violation{ClauseAuditSuccess, fmt.Sprintf("step %d: %s", a.key.Item, p)})
		}
		if a.key.Operation != op {
			vs = append(vs, Violation{ClauseAuditSuccess, fmt.Sprintf("step %d ran under operation %q, the request's is %q", a.key.Item, a.key.Operation, op)})
		}
	}
	if len(got) > len(applied) {
		vs = append(vs, Violation{ClauseAuditSuccess, fmt.Sprintf("%d success event(s) for %d applied step(s)", len(got), len(applied))})
	}
	return vs
}

// failureViolations checks the failure path's event. The failing run is driven by run in modeFailure.
func (h *harness) failureViolations(out runOut) []Violation {
	h.mu.Lock()
	f, op := h.failure, h.op
	h.mu.Unlock()
	if f == nil {
		return h.violations() // no step reached Apply: nothing to drive
	}
	h.exercise(ClauseAuditFailure)
	events, invalid := out.sink.snapshot()
	vs := h.violations()
	for _, msg := range invalid {
		vs = append(vs, Violation{ClauseAuditFailure, msg})
	}
	var got []audit.Event
	for _, ev := range events {
		if ev.Outcome == audit.Failure {
			got = append(got, ev)
		}
	}
	if len(got) != 1 {
		return append(vs, Violation{ClauseAuditFailure, fmt.Sprintf("%d failure event(s) for a failed Apply, want exactly one: a failure that is not recorded is a gap in the trail (AG-2)", len(got))})
	}
	for _, p := range problems(got[0], eventWant{kind: h.d.AuditKind, outcome: audit.Failure, actor: h.actor, target: f.sp.Target,
		key: f.key, component: component}) {
		vs = append(vs, Violation{ClauseAuditFailure, p})
	}
	if f.key.Operation != op {
		vs = append(vs, Violation{ClauseAuditFailure, fmt.Sprintf("the failed step ran under operation %q, the request's is %q", f.key.Operation, op)})
	}
	return vs
}

// denialViolations checks the denial path's event.
func (h *harness) denialViolations(out runOut) []Violation {
	tgt, denied := h.deny.deniedTarget()
	if !denied {
		return nil // Plan returned no step, so there was no Apply-time re-check to refuse
	}
	h.exercise(ClauseAuditDenial)
	h.mu.Lock()
	op := h.op
	h.mu.Unlock()
	events, invalid := out.sink.snapshot()
	var vs []Violation
	for _, msg := range invalid {
		vs = append(vs, Violation{ClauseAuditDenial, msg})
	}
	var got []audit.Event
	for _, ev := range events {
		if ev.Outcome == audit.Denied {
			got = append(got, ev)
		}
	}
	if len(got) != 1 {
		return append(vs, Violation{ClauseAuditDenial, fmt.Sprintf("%d denial event(s) for a refused step, want exactly one: a denial that is not recorded is a gap in the trail (AG-2)", len(got))})
	}
	for _, p := range problems(got[0], eventWant{kind: h.d.AuditKind, outcome: audit.Denied, actor: h.actor, target: tgt,
		key: step.Key{Operation: op}, component: component}) {
		vs = append(vs, Violation{ClauseAuditDenial, p})
	}
	return vs
}
