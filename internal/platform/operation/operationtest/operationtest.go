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
//	verify-after-drop   Verify still passes after the fake directory drops the write Apply made;
//	inverse-available   a step the Plan calls Reversible or Lossy has an Inverse that returns
//	                    ErrIrreversible (O5, third clause) or that does not encode;
//	inverse-restores    apply, then the inverse, then apply again does not restore the before-state:
//	                    the fake directory and the fixture's State are compared after the inverse and
//	                    again after the second apply;
//	lossy-undeclared    a Lossy step loses a field its fixture does not declare in Fixture.Lost, or
//	                    its plan gives no ReversibilityReason (the plan names what is lost);
//	audit-success       the run does not emit one success event per applied step, or one is missing
//	audit-failure       an AG-3 field (below);
//	audit-denial        the same for a failure the harness injects into Apply, and for a denial the
//	                    harness injects at the Apply-time authorisation re-check.
//
// The AG-3 fields it holds each event to are the ones audit.Event carries: the Kind the Action
// declares, an event ID and time, the initiator chain (requester and on-behalf-of principals), the
// planned step's target, the operation/step key (the operation ID), the source component, the
// outcome and a machine reason, the plan hash, and for a success the plan's before/after with every
// secret change redacted (AG-9); a plan change to a statically secret attribute (secretattr) that is not flagged Secret fails audit-success. The verification factor, client IP and the target's DN at the time
// are not fields of audit.Event yet, so Contract cannot hold an Action to them (T-1280 adds them and
// extends this check). A failure or denial before any step is chosen (a Plan that fails, a
// denial at Plan) carries no operation key today (T-1281), so those paths are not driven.
//
// The Record of each run lists the clauses it really exercised; a clause an Action gave the harness
// nothing to check (an Action that plans no step has no inverse, no failure and no denial to drive)
// is absent from it.
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

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Clause names, as they appear in a Violation and in the coverage record.
const (
	ClauseDescriptor      = "descriptor"
	ClauseRun             = "run"
	ClausePlanReadOnly    = "plan-read-only"
	ClauseApplyIdempotent = "apply-idempotent"
	ClauseVerifyAfterDrop = "verify-after-drop"

	ClauseInverseAvailable = "inverse-available"
	ClauseInverseRestores  = "inverse-restores"
	ClauseLossyUndeclared  = "lossy-undeclared"
	ClauseAuditSuccess     = "audit-success"
	ClauseAuditFailure     = "audit-failure"
	ClauseAuditDenial      = "audit-denial"
)

// Fixture is what an Action needs to be exercised.
type Fixture struct {
	// Input is a valid input for the Action. It must plan at least one step for the Apply and Verify
	// clauses to be exercised; an Action that plans none is recorded as such.
	Input operation.Input
	// Directory is the FakeDirectory the Action under test was built with, or nil for an Action that
	// does not use one. Without it the directory halves of the clauses are not exercised. Its write
	// counters, read after Contract, are those of the forward run: the failure and denial paths, the
	// inverse and the second apply are the harness's own work and are not counted.
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
	// InverseAction is the Action that runs the input Inverse returns, when it is not the Action itself:
	// a Store Action's inverse is its family's restore Action (ADR-0005 rule 10). Nil: the Action is
	// its own inverse.
	InverseAction operation.Action
	// Lost names what a Lossy step is declared to lose: an attribute name ("description"), or
	// "<objectGUID>/<attribute>" for one object, or "State" for a difference in the fixture's State.
	// A Lossy step may leave exactly these different after apply and inverse; anything else it
	// loses fails the lossy-undeclared clause. A Reversible step may lose nothing.
	Lost []string
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
	rec, vs := check(action, fx)
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
func Check(action operation.Action, fx Fixture) []Violation {
	_, vs := check(action, fx)
	return vs
}

// options are the seams a test of the harness itself uses, to damage the pipeline the way a faulty
// Action or kernel would. Contract uses none.
type options struct {
	// sink wraps the audit sink the runner appends to, so a test can drop or alter an event.
	sink func(audit.Sink) audit.Sink
}

// component is the source component the runner is configured with, and the event must carry.
const component = "operationtest"

func check(action operation.Action, fx Fixture) (Record, []Violation) {
	return checkWith(action, fx, options{})
}

func checkWith(action operation.Action, fx Fixture, o options) (Record, []Violation) {
	rec := Record{At: time.Now().UTC()}
	if action == nil {
		return rec, []Violation{{ClauseDescriptor, "nil action"}}
	}
	d := action.Describe()
	rec.Action, rec.Version, rec.Target = d.ID, d.Version, string(d.Target)

	actor := fx.Actor
	if actor.Validate() != nil {
		actor = authority.Chain{Requester: authority.Principal{ID: "contract-human", Kind: authority.Human}}
	}
	newH := func(m mode) *harness {
		return &harness{inner: action, fx: fx, d: d, actor: actor, o: o, mode: m, deny: &denyAfterPlan{}}
	}

	// The failure and denial paths first, from the Action's pristine state: neither reaches the
	// Action's own successful Apply, so they leave nothing behind.
	hf, hd, h := newH(modeFailure), newH(modeDenial), newH(modeSuccess)
	var vs []Violation
	fout, err := hf.run(&probe{h: hf}, allowAll{}, fx.Input, "failure")
	if err != nil {
		return rec, []Violation{{ClauseDescriptor, err.Error()}}
	}
	vs = append(vs, hf.failureViolations(fout)...)
	dout, err := hd.run(&probe{h: hd}, hd.deny, fx.Input, "denial")
	if err != nil {
		return rec, []Violation{{ClauseDescriptor, err.Error()}}
	}
	vs = append(vs, hd.denialViolations(dout)...)

	// The success run: Plan, authorise, Apply (twice), Verify (and again after a drop), success event.
	out, err := h.run(&probe{h: h}, allowAll{}, fx.Input, "")
	if err != nil {
		return rec, []Violation{{ClauseDescriptor, err.Error()}}
	}
	rec.Steps = len(out.res.Steps)

	vs = append(h.violations(), vs...) // plan, apply and verify clauses lead, as they always have
	// The statements the Plan transaction saw, in the harness's own bookkeeping, not the Action's.
	vs = append(vs, planTxViolations(out.db, h)...)
	if out.err != nil && len(vs) == 0 {
		vs = append(vs, Violation{ClauseRun, out.err.Error()})
	}
	if out.err == nil {
		vs = append(vs, h.successEventViolations(out)...)
	}
	vs = append(vs, h.reversibilityViolations()...)

	rec.Exercised = exercised(h, hf, hd)
	rec.Passed = len(vs) == 0
	for _, v := range vs {
		if !slices.Contains(rec.Violations, v.Clause) {
			rec.Violations = append(rec.Violations, v.Clause)
		}
	}
	return rec, vs
}

// exercised lists, in a fixed order, the clauses the runs could really check.
func exercised(h, hf, hd *harness) []string {
	have := map[string]bool{}
	for _, x := range []*harness{h, hf, hd} {
		x.mu.Lock()
		for c := range x.ex {
			have[c] = true
		}
		x.mu.Unlock()
	}
	var out []string
	for _, c := range []string{ClausePlanReadOnly, ClauseApplyIdempotent, ClauseVerifyAfterDrop, ClauseInverseAvailable,
		ClauseInverseRestores, ClauseLossyUndeclared, ClauseAuditSuccess, ClauseAuditFailure, ClauseAuditDenial} {
		if have[c] {
			out = append(out, c)
		}
	}
	return out
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

// mode says which path a run drives.
type mode int

const (
	modeSuccess mode = iota // the Action's own Apply and Verify run, with the clause probes around them
	modeFailure             // the fake directory refuses the write; the failure event is expected
	modeDenial              // the Apply-time authorisation refuses; the denial event is expected
)

// harness is the state of one Contract run, shared by the probe's hooks.
type harness struct {
	inner operation.Action
	fx    Fixture
	d     operation.Descriptor
	actor authority.Chain
	o     options
	mode  mode
	deny  *denyAfterPlan

	mu       sync.Mutex
	vs       []Violation
	ex       map[string]bool // clauses really exercised
	planned  bool
	dropped  bool // Apply changed the fake directory, so there is a write to drop
	preApply snapshot

	// before-state, taken as Plan starts; afterForward is taken when the forward run ends.
	before       snapshot
	beforeState  any
	haveBefore   bool
	afterForward snapshot
	afterState   any

	op      step.OperationID
	applied []appliedStep // the steps Apply ran, once each, in order
	nsteps  int           // steps Plan returned
	failure *appliedStep  // modeFailure: the step whose Apply was failed
}

type appliedStep struct {
	key step.Key
	sp  operation.StepPlan
	out operation.Outcome
}

func (h *harness) fail(clause, format string, a ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.vs = append(h.vs, Violation{clause, fmt.Sprintf(format, a...)})
}

func (h *harness) exercise(clause string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ex == nil {
		h.ex = map[string]bool{}
	}
	h.ex[clause] = true
}

func (h *harness) violations() []Violation {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.vs)
}

// runOut is what one runner call left behind.
type runOut struct {
	res  operation.Result
	err  error
	db   *rolledBackDB
	sink *recordingSink
}

// run registers act (presented as a Store Action, see probe.Describe) in a fresh runner over a
// rolled-back store and runs one request. A non-nil error is a setup failure, not a clause.
func (h *harness) run(act operation.Action, az operation.Authorizer, in operation.Input, suffix string) (runOut, error) {
	reg, err := operation.NewRegistry(act)
	if err != nil {
		return runOut{}, err
	}
	db, rs := &rolledBackDB{}, &recordingSink{}
	var sink audit.Sink = rs
	if h.o.sink != nil {
		sink = h.o.sink(sink)
	}
	r, err := operation.NewRunner(operation.Config{DB: db, Audit: sink, Authz: az, Registry: reg,
		Facts: h.fx.Facts, Component: component})
	if err != nil {
		return runOut{}, err
	}
	id := "contract-" + string(h.d.ID)
	if suffix != "" {
		id = "contract-" + suffix + "-" + string(h.d.ID)
	}
	h.mu.Lock()
	if h.op == "" {
		h.op = step.OperationID(id)
	}
	h.mu.Unlock()
	res, runErr := r.RunStore(context.Background(), operation.Request{
		Tenant: tenant.New(), Actor: h.actor, Action: act.Describe().ID, Input: in, Pins: h.fx.Pins,
		Operation: step.OperationID(id),
	})
	return runOut{res: res, err: runErr, db: db, sink: rs}, nil
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
	h.planned = true
	if h.mode == modeSuccess {
		h.ex = orMap(h.ex)
		h.ex[ClausePlanReadOnly] = true
		if h.fx.Directory != nil {
			h.before = h.fx.Directory.snapshot()
		}
		h.beforeState, h.haveBefore = h.state(), true
	}
	h.mu.Unlock()
	steps, err := h.inner.Plan(ctx, pc, in)
	if h.mode == modeSuccess && h.fx.Directory != nil {
		if n := h.fx.Directory.Writes() - before; n > 0 {
			h.fail(ClausePlanReadOnly, "Plan made %d write attempt(s) on the fake directory", n)
		}
	}
	h.mu.Lock()
	h.nsteps = len(steps)
	h.mu.Unlock()
	if h.mode == modeDenial {
		h.deny.setAllowed(len(steps)) // the Plan-time authorisation of each step passes; the re-check does not
	}
	return steps, err
}

func orMap(m map[string]bool) map[string]bool {
	if m == nil {
		return map[string]bool{}
	}
	return m
}

func (p *probe) Apply(ctx context.Context, s step.Step, sp operation.StepPlan) (operation.Outcome, error) {
	h := p.h
	switch h.mode {
	case modeFailure:
		return h.applyFailing(ctx, s, sp)
	case modeDenial:
		// Not reached: the re-check refused first. If the runner got here the write would land while the
		// trail says "denied", so the Action is not called and the clause fails.
		h.fail(ClauseAuditDenial, "Apply ran after the Apply-time re-check refused the step: the write was not withheld")
		return operation.Outcome{}, errContractDenied
	}
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
	h.applied = append(h.applied, appliedStep{key: s.Key(), sp: sp, out: out})
	h.mu.Unlock()

	// Second Apply, same Step and so the same key (operation, item, step): a crash and a retry.
	state1 := h.state()
	w1 := txWrites(tx)
	c1 := changes(dir)
	_, err2 := h.inner.Apply(ctx, s, sp)
	h.exercise(ClauseApplyIdempotent)
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

// errInjected is the failure the harness makes Apply return when the fake directory has no write to
// refuse. It carries no content.
var errInjected = errors.New("operationtest: injected apply failure")

// applyFailing runs the Action's Apply while the fake directory refuses every write, so the Action's
// own error handling is what the failure event rests on. An Apply that reports success although its
// write was refused would never have its failure recorded.
func (h *harness) applyFailing(ctx context.Context, s step.Step, sp operation.StepPlan) (operation.Outcome, error) {
	h.mu.Lock()
	if h.failure == nil {
		h.failure = &appliedStep{key: s.Key(), sp: sp}
	}
	h.mu.Unlock()
	dir := h.fx.Directory
	if dir == nil {
		return operation.Outcome{}, errInjected
	}
	snap, w, c := dir.snapshot(), dir.Writes(), dir.Changes()
	dir.failWrites(errInjected)
	out, err := h.inner.Apply(ctx, s, sp)
	attempted := dir.Writes() > w
	dir.failWrites(nil)
	dir.restore(snap)
	dir.resetCounters(w, c)
	switch {
	case err == nil && attempted:
		h.fail(ClauseAuditFailure, "Apply returned success although the fake directory refused its write, so the failure would never be recorded")
		return out, errInjected // keep driving: the event for the failure is still checked
	case err == nil:
		return out, errInjected
	}
	return out, err
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
	h.exercise(ClauseVerifyAfterDrop)
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

// asStore presents an Action as a Store Action, as probe does, with no clause probes: it runs the
// inverse and the second apply.
type asStore struct{ operation.Action }

func (a asStore) Describe() operation.Descriptor {
	d := a.Action.Describe()
	d.Target = operation.TargetStore
	return d
}
