// Package operationtest is the test kit for operation Actions (ADR-0005 rule 1, fitness-operation
// O6 and O7). Every Action runs through Contract in its own package's tests:
//
//	func TestContract(t *testing.T) {
//		dir := operationtest.NewFakeDirectory()
//		operationtest.Contract(t, newMyAction(dir), operationtest.Fixture{Directory: dir, Input: ...})
//	}
//
// Contract drives the Action through the real operation.Runner against a fake directory
// (FakeDirectory) and a rolled-back store, and fails the test, naming the clause, when:
//
//	plan-read-only      Plan's store transaction is not READ ONLY, or Plan wrote or tried to write
//	                    to the store or the fake directory;
//	apply-idempotent    Apply run a second time with the same step key changes state again;
//	verify-after-drop   Verify still passes after the fake directory drops the write Apply made.
//
// The remaining O7 behaviours (inverse restores the before-state, Lossy loses no undeclared field,
// success, failure and denial events with their AG-3 fields) are not checked yet; a Contract pass
// is not a claim about them. The Record of each run lists the clauses it really exercised.
//
// # Coverage record (O6)
//
// Each Contract run appends one JSON line to the coverage file, whether it passed or not:
//
//	{"action":"objects.user.create","version":1,"target":"ad","test":"TestContract","passed":true,
//	 "steps":1,"exercised":["plan-read-only","apply-idempotent","verify-after-drop"],"at":"..."}
//
// The file is build/operationtest/contract-coverage.jsonl under the module root, or the path in
// $ACTIVEDIQ_CONTRACT_COVERAGE. Test binaries of different packages append to it concurrently, one
// line per write; the file is never rewritten. It accumulates across runs, so the O6 check removes
// it before `go test ./...` and compares Ran(ReadCoverage(CoveragePath())) with the registry.
//
// # Scope
//
// Contract runs every Action, whatever its Descriptor.Target, as a Store step in the runner's inline
// path: Plan, authorise, Apply, Verify and a success event, with the Action's own directory
// access going to the FakeDirectory it was built with. The persisted Directory path (claims,
// reconciliation, pins) belongs to the O8 integration tests, not here. The store is a fake
// transaction: it classifies the SQL an Action sends but returns no rows, so an Action whose Plan
// reads through pc.Tx needs the PostgreSQL-backed run in its own integration test.
package operationtest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

// Clause names, as they appear in a Violation and in the coverage record.
const (
	ClauseDescriptor      = "descriptor"
	ClauseRun             = "run"
	ClausePlanReadOnly    = "plan-read-only"
	ClauseApplyIdempotent = "apply-idempotent"
	ClauseVerifyAfterDrop = "verify-after-drop"
)

// Fixture is what an Action needs to be exercised.
type Fixture struct {
	// Input is a valid input for the Action. It must plan at least one step for the Apply and Verify
	// clauses to be exercised; an Action that plans none is recorded as such.
	Input operation.Input
	// Directory is the FakeDirectory the Action under test was built with, or nil for an Action that
	// does not use one. Without it the directory halves of the clauses are not exercised.
	Directory *FakeDirectory
	// State, when set, returns a comparable view of any state the Action keeps outside the
	// FakeDirectory. Apply is idempotent only if it is unchanged by the second Apply. Without it, a
	// second Apply that sends a write statement to the store counts as a change.
	State func() any
	// Facts answers the live reads Plan makes through PlanContext.Facts; nil answers an empty Facts.
	Facts operation.LiveFacts
	// Pins are the DCs pinned for the operation, for an Action whose Plan reads on them.
	Pins authority.Pins
	// Actor is the initiator; the default is a human, "contract-human".
	Actor authority.Chain
}

// Violation is one clause an Action broke.
type Violation struct {
	Clause string
	Detail string
}

func (v Violation) String() string { return v.Clause + ": " + v.Detail }

// Contract runs the Action through every clause and fails t for each violation, naming the clause.
// It then appends the run to the coverage file; failing to do so also fails t.
func Contract(t testing.TB, action operation.Action, fx Fixture) {
	t.Helper()
	rec, vs := check(t, action, fx)
	rec.Test = t.Name()
	for _, v := range vs {
		t.Errorf("operationtest.Contract %q: clause %s (ADR-0005 O7)", rec.Action, v)
	}
	path, err := CoveragePath()
	if err == nil {
		err = appendRecord(path, rec)
	}
	if err != nil {
		t.Errorf("operationtest.Contract %q: coverage record not written (ADR-0005 O6): %v", rec.Action, err)
	}
}

// Check runs the clauses and returns the violations without failing a test, so a test of the
// harness itself can assert that a broken Action is caught.
func Check(t testing.TB, action operation.Action, fx Fixture) []Violation {
	t.Helper()
	_, vs := check(t, action, fx)
	return vs
}

func check(t testing.TB, action operation.Action, fx Fixture) (Record, []Violation) {
	rec := Record{At: time.Now().UTC()}
	if action == nil {
		return rec, []Violation{{ClauseDescriptor, "nil action"}}
	}
	d := action.Describe()
	rec.Action, rec.Version, rec.Target = d.ID, d.Version, string(d.Target)

	h := &harness{inner: action, fx: fx, d: d}
	// The wrapper presents the Action as a Store Action so the runner's inline path runs it; the
	// Action's own Describe is unchanged otherwise (the validation sees the same fields).
	reg, err := operation.NewRegistry(&probe{h: h})
	if err != nil {
		return rec, []Violation{{ClauseDescriptor, err.Error()}}
	}
	db := &rolledBackDB{}
	r, err := operation.NewRunner(operation.Config{DB: db, Audit: validatingSink{}, Authz: allowAll{},
		Registry: reg, Facts: fx.Facts})
	if err != nil {
		return rec, []Violation{{ClauseRun, err.Error()}}
	}
	actor := fx.Actor
	if actor.Validate() != nil {
		actor = authority.Chain{Requester: authority.Principal{ID: "contract-human", Kind: authority.Human}}
	}
	res, runErr := r.RunStore(context.Background(), operation.Request{
		Tenant: tenanttest.NewID(t), Actor: actor, Action: d.ID, Input: fx.Input, Pins: fx.Pins,
		Operation: step.OperationID("contract-" + string(d.ID)),
	})
	rec.Steps = len(res.Steps)

	vs := h.violations()
	// The statements the Plan transaction saw, in the harness's own bookkeeping, not the Action's.
	vs = append(vs, planTxViolations(db, h)...)
	if runErr != nil && len(vs) == 0 {
		vs = append(vs, Violation{ClauseRun, runErr.Error()})
	}
	rec.Exercised = h.exercised()
	rec.Passed = len(vs) == 0
	for _, v := range vs {
		if !slices.Contains(rec.Violations, v.Clause) {
			rec.Violations = append(rec.Violations, v.Clause)
		}
	}
	return rec, vs
}

// planTxViolations inspects the transaction Plan ran in.
func planTxViolations(db *rolledBackDB, h *harness) []Violation {
	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.txs) == 0 || !h.planned {
		return nil // the run was refused before Plan
	}
	tx := db.txs[0] // the runner opens the Plan transaction first
	var vs []Violation
	if !tx.isReadOnly() {
		vs = append(vs, Violation{ClausePlanReadOnly, "Plan's store transaction was not READ ONLY"})
	}
	if _, attempts := tx.counts(); attempts > 0 {
		vs = append(vs, Violation{ClausePlanReadOnly,
			fmt.Sprintf("Plan sent %d write statement(s) to the store in its READ ONLY transaction", attempts)})
	}
	return vs
}

// harness is the state of one Contract run, shared by the probe's hooks.
type harness struct {
	inner operation.Action
	fx    Fixture
	d     operation.Descriptor

	mu       sync.Mutex
	vs       []Violation
	planned  bool
	dropped  bool // Apply changed the fake directory, so there is a write to drop
	dropChk  bool // the drop probe ran
	planChk  bool
	idemChk  bool
	applyTx  *recordingTx
	preApply snapshot
}

func (h *harness) fail(clause, format string, a ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.vs = append(h.vs, Violation{clause, fmt.Sprintf(format, a...)})
}

func (h *harness) violations() []Violation {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.vs)
}

func (h *harness) exercised() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	if h.planChk {
		out = append(out, ClausePlanReadOnly)
	}
	if h.idemChk {
		out = append(out, ClauseApplyIdempotent)
	}
	if h.dropChk {
		out = append(out, ClauseVerifyAfterDrop)
	}
	return out
}

// probe wraps the Action under test with the clause checks. It is registered in the real runner, so
// Plan, Apply and Verify run with the runner's own Step and transactions.
type probe struct{ h *harness }

func (p *probe) Describe() operation.Descriptor {
	d := p.h.d
	d.Target = operation.TargetStore // run on the runner's inline path; see the package comment
	return d
}

func (p *probe) Plan(ctx context.Context, pc operation.PlanContext, in operation.Input) ([]operation.StepPlan, error) {
	h := p.h
	var before int
	if h.fx.Directory != nil {
		before = h.fx.Directory.Writes()
	}
	h.mu.Lock()
	h.planned, h.planChk = true, true
	h.mu.Unlock()
	steps, err := h.inner.Plan(ctx, pc, in)
	if h.fx.Directory != nil {
		if n := h.fx.Directory.Writes() - before; n > 0 {
			h.fail(ClausePlanReadOnly, "Plan made %d write attempt(s) on the fake directory", n)
		}
	}
	return steps, err
}

func (p *probe) Apply(ctx context.Context, s step.Step, sp operation.StepPlan) (operation.Outcome, error) {
	h := p.h
	dir := h.fx.Directory
	if dir != nil {
		h.mu.Lock()
		h.preApply = dir.snapshot()
		h.mu.Unlock()
	}
	changes0 := changes(dir)
	tx, _ := s.Tx().(*recordingTx)

	out, err := h.inner.Apply(ctx, s, sp)
	if err != nil {
		return out, err
	}
	changed := changes(dir)-changes0 > 0
	h.mu.Lock()
	h.dropped = changed
	h.mu.Unlock()

	// Second Apply, same Step and so the same key (operation, item, step): a crash and a retry.
	state1 := h.state()
	w1 := txWrites(tx)
	c1 := changes(dir)
	_, err2 := h.inner.Apply(ctx, s, sp)
	h.mu.Lock()
	h.idemChk = true
	h.mu.Unlock()
	switch {
	case err2 != nil && !errors.Is(err2, operation.ErrStaleState):
		h.fail(ClauseApplyIdempotent, "a second Apply with the same step key returned an error: %v", err2)
	case changes(dir)-c1 > 0:
		h.fail(ClauseApplyIdempotent, "a second Apply with the same step key changed the fake directory again (%d further change(s))", changes(dir)-c1)
	case h.fx.State != nil && !reflect.DeepEqual(state1, h.state()):
		h.fail(ClauseApplyIdempotent, "a second Apply with the same step key changed the state the fixture reports")
	case h.fx.State == nil && txWrites(tx)-w1 > 0:
		h.fail(ClauseApplyIdempotent, "a second Apply with the same step key sent %d write statement(s) to the store and the fixture gives no State to show they changed nothing", txWrites(tx)-w1)
	}
	return out, nil
}

func (h *harness) state() any {
	if h.fx.State == nil {
		return nil
	}
	return h.fx.State()
}

func changes(d *FakeDirectory) int {
	if d == nil {
		return 0
	}
	return d.Changes()
}

func txWrites(tx *recordingTx) int {
	if tx == nil {
		return 0
	}
	w, _ := tx.counts()
	return w
}

func (p *probe) Verify(ctx context.Context, s step.Step, sp operation.StepPlan, o operation.Outcome) (operation.Verdict, error) {
	h := p.h
	v, err := h.inner.Verify(ctx, s, sp, o)
	if err != nil || !v.OK {
		return v, err // the runner reports a Verify that fails a correct write
	}
	h.mu.Lock()
	drop := h.dropped && h.fx.Directory != nil
	pre := h.preApply
	h.mu.Unlock()
	if !drop {
		return v, nil
	}
	// The fake directory drops the write: the state goes back to before Apply, as if the DC lost it.
	h.mu.Lock()
	h.dropChk = true
	h.mu.Unlock()
	after := h.fx.Directory.snapshot()
	h.fx.Directory.restore(pre)
	v2, err2 := h.inner.Verify(ctx, s, sp, o)
	h.fx.Directory.restore(after)
	if err2 == nil && v2.OK {
		h.fail(ClauseVerifyAfterDrop, "Verify passed after the fake directory dropped the write Apply made")
	}
	return v, nil
}

func (p *probe) Inverse(sp operation.StepPlan, o operation.Outcome) (operation.Input, error) {
	return p.h.inner.Inverse(sp, o)
}
