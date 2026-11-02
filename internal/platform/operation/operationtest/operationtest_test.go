package operationtest

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// TestMain points the coverage file at a temp path for the whole package, so the suite's own
// fixtures (including deliberately broken Actions) never reach the repository's coverage record.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "operationtest")
	if err != nil {
		panic(err)
	}
	os.Setenv(CoverageEnv, filepath.Join(dir, "coverage.jsonl"))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

const guid = "6f1c0c3e-0000-4000-8000-000000000001"

// fixtureAction is a Store/Directory-style Action over the fake directory. The flags make it
// deliberately wrong in one way each.
type fixtureAction struct {
	id  operation.ActionID
	dir *FakeDirectory
	// planWritesDir / planWritesSQL make Plan write; nonIdempotent appends a fresh value on every
	// Apply; verifyBlind makes Verify pass whatever the directory holds.
	planWritesSQL bool
	planSQL       string // the statement planWritesSQL sends; empty means a plain INSERT
	planSwallows  bool
	nonIdempotent bool
	verifyBlind   bool
	planHook      func() // runs inside Plan, for a Plan that misbehaves in a way a flag cannot say
	applies       int

	// The flags below make the Action wrong about reversibility or events, one way each.
	noInverse     bool // Inverse returns ErrIrreversible although the plan says Reversible
	inverseWrongs bool // Inverse returns an input that does not restore the before-state
	lossy         bool // the plan is Lossy and the Descriptor says so
	lossyDeletes  string
	swallowsFail  bool // Apply reports success when the directory refused the write
}

type fixtureInput struct{ Value string }

func (a *fixtureAction) Describe() operation.Descriptor {
	return operation.Descriptor{ID: a.id, Version: 1, Permission: "test.permission",
		Input: "#/components/schemas/Test", Target: operation.TargetAD,
		Reversibility: a.class(), AuditKind: "test.changed"}
}

func (a *fixtureAction) class() operation.Reversibility {
	if a.lossy {
		return operation.Lossy
	}
	return operation.Reversible
}

func (a *fixtureAction) Plan(ctx context.Context, pc operation.PlanContext, in operation.Input) ([]operation.StepPlan, error) {
	if a.planWritesSQL {
		sql := a.planSQL
		if sql == "" {
			sql = "INSERT INTO thing (id) VALUES ($1)"
		}
		_, err := pc.Tx.Exec(ctx, sql)
		if err != nil && !a.planSwallows {
			return nil, err
		}
	}
	if a.planHook != nil {
		a.planHook()
	}
	val := "hello"
	if len(in) > 2 { // {"Value":"..."}: the inverse's input
		var fi fixtureInput
		if err := json.Unmarshal(in, &fi); err != nil {
			return nil, err
		}
		val = fi.Value
	}
	sp := operation.StepPlan{
		Target: authority.TargetRef{GUID: guid, Class: "user"}, Kind: "modify", Reversibility: a.class(),
		Diff: []operation.Change{{Attribute: "description", Before: a.dir.Read(guid, "description"), After: []string{val}}},
	}
	if a.lossy {
		sp.ReversibilityReason = "the inverse restores description only"
	}
	return []operation.StepPlan{sp}, nil
}

func (a *fixtureAction) Apply(_ context.Context, s step.Step, sp operation.StepPlan) (operation.Outcome, error) {
	a.applies++
	m := Mutation{GUID: guid, Attribute: "description", Op: Replace, Values: sp.Diff[0].After}
	if a.nonIdempotent {
		m = Mutation{GUID: guid, Attribute: "log", Op: Add, Values: []string{fmt.Sprint("apply-", a.applies)}}
	}
	if a.lossyDeletes != "" && s.Key().Operation != "" && len(sp.Diff[0].After) == 1 && sp.Diff[0].After[0] == "hello" {
		// a forward apply of a Lossy action also wipes an attribute the inverse cannot bring back
		_ = a.dir.Write(s, Mutation{GUID: guid, Attribute: a.lossyDeletes, Op: Replace})
	}
	err := a.dir.Write(s, m)
	if err != nil && a.swallowsFail {
		return operation.Outcome{}, nil
	}
	return operation.Outcome{}, err
}

func (a *fixtureAction) Verify(_ context.Context, _ step.Step, sp operation.StepPlan, _ operation.Outcome) (operation.Verdict, error) {
	if a.verifyBlind || slices.Equal(a.dir.Read(guid, "description"), sp.Diff[0].After) ||
		a.nonIdempotent && len(a.dir.Read(guid, "log")) > 0 {
		return operation.Verdict{OK: true}, nil
	}
	return operation.Verdict{Reason: "read_back_mismatch"}, nil
}

func (a *fixtureAction) Inverse(sp operation.StepPlan, _ operation.Outcome) (operation.Input, error) {
	if a.noInverse {
		return nil, operation.ErrIrreversible
	}
	restore := sp.Diff[0].Before
	if a.inverseWrongs {
		restore = []string{"somewhere else"}
	}
	if len(restore) == 0 {
		restore = []string{""}
	}
	return json.Marshal(fixtureInput{Value: restore[0]})
}

func newFixture(id operation.ActionID) (*fixtureAction, Fixture) {
	dir := NewFakeDirectory()
	dir.Seed(guid, "description", "old")
	return &fixtureAction{id: id, dir: dir}, Fixture{Directory: dir, Input: operation.Input(`{}`)}
}

func clauses(vs []Violation) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.Clause)
	}
	return out
}

func TestContractPassesACorrectAction(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	vs := Check(a, fx)
	if len(vs) != 0 {
		t.Fatalf("a correct Action was refused: %v", vs)
	}
	if got := fx.Directory.Read(guid, "description"); !slices.Equal(got, []string{"hello"}) {
		t.Fatalf("the write did not land: %v", got)
	}
	if fx.Directory.Changes() != 1 {
		t.Fatalf("state changed %d times, want once", fx.Directory.Changes())
	}
	// the failure path 1, the forward run twice (the idempotency clause), the inverse 1, the second apply 1
	if a.applies != 5 {
		t.Fatalf("Apply ran %d times, want 5", a.applies)
	}
}

func TestPlanRunsReadOnlyWithZeroWrites(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	var sawReadOnly bool
	plan := &spyPlan{Action: a, onPlan: func(pc operation.PlanContext) {
		_, err := pc.Tx.Exec(context.Background(), "INSERT INTO t VALUES (1)")
		sawReadOnly = err != nil && strings.Contains(err.Error(), "read-only transaction")
	}}
	_ = Check(plan, fx)
	if !sawReadOnly {
		t.Fatal("a write in Plan's transaction was not refused as read-only")
	}
}

type spyPlan struct {
	operation.Action
	onPlan func(operation.PlanContext)
}

func (s *spyPlan) Plan(ctx context.Context, pc operation.PlanContext, in operation.Input) ([]operation.StepPlan, error) {
	s.onPlan(pc)
	return s.Action.Plan(ctx, pc, in)
}

func TestWritingPlanFailsNamingTheClause(t *testing.T) {
	for name, swallow := range map[string]bool{"error returned": false, "error swallowed": true} {
		t.Run(name, func(t *testing.T) {
			a, fx := newFixture("test.thing.modify")
			a.planWritesSQL, a.planSwallows = true, swallow
			vs := Check(a, fx)
			if !slices.Contains(clauses(vs), ClausePlanReadOnly) {
				t.Fatalf("a writing Plan passed Contract: %v", vs)
			}
			if !strings.Contains(vs[0].Detail, "READ ONLY") {
				t.Fatalf("detail does not say why: %q", vs[0].Detail)
			}
		})
	}
}

func TestPlanWritingToTheFakeDirectoryFails(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	// Plan has no Step, so its write carries the zero Step: the fake refuses it, but the attempt is counted.
	a.planHook = func() {
		var none step.Step
		_ = a.dir.Write(none, Mutation{GUID: guid, Attribute: "description", Op: Replace, Values: []string{"x"}})
	}
	vs := Check(a, fx)
	if !slices.Contains(clauses(vs), ClausePlanReadOnly) {
		t.Fatalf("a Plan that wrote to the directory passed: %v", vs)
	}
	if fx.Directory.Changes() != 1 { // Apply's one change; the refused write changed nothing
		t.Fatalf("the zero Step changed state: %d changes", fx.Directory.Changes())
	}
}

func TestApplyTwiceWithOneKeyChangesStateOnce(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	if vs := Check(a, fx); len(vs) != 0 {
		t.Fatal(vs)
	}
	if fx.Directory.Writes() != 2 || fx.Directory.Changes() != 1 {
		t.Fatalf("writes=%d changes=%d, want 2 writes of which 1 changed state", fx.Directory.Writes(), fx.Directory.Changes())
	}
}

func TestNonIdempotentActionFails(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	a.nonIdempotent = true
	vs := Check(a, fx)
	if !slices.Contains(clauses(vs), ClauseApplyIdempotent) {
		t.Fatalf("a non-idempotent Action passed: %v", vs)
	}
}

func TestStoreWriteOnSecondApplyNeedsState(t *testing.T) {
	var state int
	apply := func(ctx context.Context, s step.Step) error {
		_, err := s.Tx().Exec(ctx, "UPDATE thing SET n = n + 1")
		state++
		return err
	}
	act := &sqlAction{apply: apply}
	if vs := Check(act, Fixture{Input: operation.Input(`{}`)}); !slices.Contains(clauses(vs), ClauseApplyIdempotent) {
		t.Fatalf("a repeated store write with no State passed: %v", vs)
	}
	state = 0
	// The fixture reports state that an idempotent upsert leaves alone.
	idem := &sqlAction{apply: func(ctx context.Context, s step.Step) error {
		_, err := s.Tx().Exec(ctx, "INSERT INTO thing VALUES (1) ON CONFLICT DO NOTHING")
		if state == 0 {
			state = 1
		}
		return err
	}}
	if vs := Check(idem, Fixture{Input: operation.Input(`{}`), State: func() any { return state }}); len(vs) != 0 {
		t.Fatalf("an idempotent store Action with State was refused: %v", vs)
	}
}

type sqlAction struct {
	apply func(context.Context, step.Step) error
}

func (*sqlAction) Describe() operation.Descriptor {
	return operation.Descriptor{ID: "test.sql.set", Version: 1, Permission: "test.permission",
		Input: "#/components/schemas/Test", Target: operation.TargetStore,
		Reversibility: operation.Irreversible, AuditKind: "test.changed"}
}
func (*sqlAction) Plan(context.Context, operation.PlanContext, operation.Input) ([]operation.StepPlan, error) {
	return []operation.StepPlan{{Target: authority.TargetRef{GUID: "row-1", Class: "thing"}, Kind: "set", Reversibility: operation.Irreversible}}, nil
}
func (a *sqlAction) Apply(ctx context.Context, s step.Step, _ operation.StepPlan) (operation.Outcome, error) {
	return operation.Outcome{}, a.apply(ctx, s)
}
func (*sqlAction) Verify(context.Context, step.Step, operation.StepPlan, operation.Outcome) (operation.Verdict, error) {
	return operation.Verdict{OK: true}, nil
}
func (*sqlAction) Inverse(operation.StepPlan, operation.Outcome) (operation.Input, error) {
	return nil, operation.ErrIrreversible
}

func TestVerifyMustFailWhenTheWriteIsDropped(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	a.verifyBlind = true
	vs := Check(a, fx)
	if !slices.Contains(clauses(vs), ClauseVerifyAfterDrop) {
		t.Fatalf("a Verify that passes after the write was dropped passed Contract: %v", vs)
	}
	// ...and the directory is back in the state Apply left it.
	if got := fx.Directory.Read(guid, "description"); !slices.Equal(got, []string{"hello"}) {
		t.Fatalf("the drop probe left the directory in the dropped state: %v", got)
	}
}

func TestVerifyThatReadsTheDirectoryPasses(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	rec, vs := check(a, fx)
	if len(vs) != 0 {
		t.Fatal(vs)
	}
	if want := []string{ClausePlanReadOnly, ClauseApplyIdempotent, ClauseVerifyAfterDrop, ClauseInverseAvailable, ClauseInverseRestores, ClauseAuditSuccess, ClauseAuditFailure, ClauseAuditDenial}; !slices.Equal(rec.Exercised, want) {
		t.Fatalf("exercised = %v, want %v", rec.Exercised, want)
	}
}

func TestFailedVerifyOfACorrectWriteIsReported(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	a.nonIdempotent = false
	fx.Directory.Seed(guid, "description", "old")
	bad := &spyVerify{Action: a}
	vs := Check(bad, fx)
	if !slices.Contains(clauses(vs), ClauseRun) {
		t.Fatalf("a Verify failing a correct write was not reported: %v", vs)
	}
}

type spyVerify struct{ operation.Action }

func (*spyVerify) Verify(context.Context, step.Step, operation.StepPlan, operation.Outcome) (operation.Verdict, error) {
	return operation.Verdict{Reason: "mismatch"}, nil
}

func TestModuletestActionRunsGreen(t *testing.T) {
	Contract(t, moduletest.Action("test.noop.run"), Fixture{Input: operation.Input(`{}`)})
}

func TestInvalidDescriptorIsAViolation(t *testing.T) {
	bad := &sqlAction{}
	bad2 := &badDescriptor{sqlAction: bad}
	vs := Check(bad2, Fixture{})
	if !slices.Contains(clauses(vs), ClauseDescriptor) {
		t.Fatalf("an Action with no valid Descriptor passed: %v", vs)
	}
}

type badDescriptor struct{ *sqlAction }

func (badDescriptor) Describe() operation.Descriptor { return operation.Descriptor{ID: "nodots"} }

func TestCoverageRecordIsWrittenAndReadBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "cov.jsonl")
	t.Setenv(CoverageEnv, path)
	a, fx := newFixture("test.thing.modify")
	Contract(t, a, fx)
	Contract(t, moduletest.Action("test.noop.run"), Fixture{Input: operation.Input(`{}`)})
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(got), "\n"); n != 2 {
		t.Fatalf("%d lines, want one per run:\n%s", n, got)
	}
	recs, err := ReadCoverage(path)
	if err != nil {
		t.Fatal(err)
	}
	if ids := Ran(recs); !slices.Equal(ids, []operation.ActionID{"test.noop.run", "test.thing.modify"}) {
		t.Fatalf("Ran = %v", ids)
	}
	r := recs[0]
	if r.Action != "test.thing.modify" || !r.Passed || r.Steps != 1 || r.Target != "ad" || r.Version != 1 ||
		r.Test != t.Name() || r.At.IsZero() || len(r.Exercised) != 8 {
		t.Fatalf("record = %+v", r)
	}
	if recs[1].Steps != 0 || len(recs[1].Exercised) != 1 {
		t.Fatalf("a no-step Action must record only what it exercised: %+v", recs[1])
	}
}

func TestFailingRunIsRecordedAsFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cov.jsonl")
	t.Setenv(CoverageEnv, path)
	a, fx := newFixture("test.thing.modify")
	a.nonIdempotent = true
	rec, vs := check(a, fx)
	if err := appendRecord(path, rec); err != nil || len(vs) == 0 {
		t.Fatalf("err=%v violations=%v", err, vs)
	}
	recs, err := ReadCoverage(path)
	if err != nil || len(recs) != 1 || recs[0].Passed || !slices.Contains(recs[0].Violations, ClauseApplyIdempotent) {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
}

func TestReadCoverageFailsOnMissingOrCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadCoverage(filepath.Join(dir, "none")); err == nil {
		t.Fatal("a missing coverage file read as empty")
	}
	p := filepath.Join(dir, "bad")
	os.WriteFile(p, []byte("{not json\n"), 0o644)
	if _, err := ReadCoverage(p); err == nil {
		t.Fatal("a corrupt line was skipped")
	}
}

func TestDefaultCoveragePathIsUnderTheModuleRoot(t *testing.T) {
	t.Setenv(CoverageEnv, "")
	p, err := CoveragePath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(p), "build/operationtest/contract-coverage.jsonl") {
		t.Fatalf("path = %s", p)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(p))), "go.mod")); err != nil {
		t.Fatalf("not under the module root: %v", err)
	}
}

func TestFakeDirectoryRefusesAZeroStepButCountsIt(t *testing.T) {
	d := NewFakeDirectory()
	var none step.Step
	err := d.Write(none, Mutation{GUID: guid, Attribute: "a", Op: Replace, Values: []string{"v"}})
	if err == nil || d.Writes() != 1 || d.Changes() != 0 || d.Read(guid, "a") != nil {
		t.Fatalf("err=%v writes=%d changes=%d", err, d.Writes(), d.Changes())
	}
}

func TestSQLClassification(t *testing.T) {
	for sql, want := range map[string]bool{
		"SELECT * FROM t":                                false,
		"select 'update me' from t":                      false,
		"SELECT * FROM t FOR UPDATE":                     true,
		"  insert into t values (1)":                     true,
		"WITH x AS (DELETE FROM t RETURNING *) SELECT 1": true,
		"WITH x AS (SELECT 1) SELECT * FROM x":           false,
		"UPDATE t SET a = 1":                             true,
		"SELECT * INTO new_t FROM t":                     true,
		"SELECT nextval('s')":                            true,
	} {
		words := sqlWords(strings.Join(store.Statements(sql), ";"))
		if got := isWrite(words); got != want {
			t.Errorf("isWrite(%q) = %v, want %v", sql, got, want)
		}
	}
}

// TestPlanStatementsThatMustFailTheClause sends each statement from a Plan that swallows the error, so
// only the harness's own bookkeeping can catch it.
func TestPlanStatementsThatMustFailTheClause(t *testing.T) {
	for sql, wantViolation := range map[string]bool{
		// forms the first version caught
		"INSERT INTO t VALUES (1)":                       true,
		"/**/UPDATE t SET a = 1":                         true,
		"WITH x AS (DELETE FROM t RETURNING *) SELECT 1": true,
		// forms that hid from it
		"/* x */ INSERT INTO t VALUES (1)":                      true,
		"-- note\nINSERT INTO t VALUES (1)":                     true,
		"SELECT 1; DELETE FROM t":                               true,
		`select "a'b" from t; insert into t values (1)`:         true,
		"SET transaction_read_only = off":                       true,
		"SET LOCAL default_transaction_read_only TO 'off'":      true,
		"SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE": true,
		"SET TRANSACTION READ WRITE":                            true,
		"SET LOCAL client_encoding = 'SJIS'":                    true,
		"SET NAMES 'BIG5'":                                      true,
		"SELECT set_config('transaction_read_only','off',true)": true,
		"COMMIT":                  true,
		"SELECT 1; ROLLBACK":      true,
		"SAVEPOINT s":             true,
		"PREPARE TRANSACTION 'x'": true,
		"SELECT $$ ' $$; INSERT INTO t VALUES (1)": true,
		"SELECT * INTO new_t FROM t":               true,
		"SELECT nextval('s')":                      true,
		// CR ends a comment, E-string continuation, standard_conforming_strings = off
		"SELECT 1; -- x\rINSERT INTO t VALUES (1)":       true,
		"SELECT E'a'\n'x\\'' ; INSERT INTO t VALUES (1)": true,
		"SELECT 'x\\'' ; INSERT INTO t VALUES (1)":       true,
		"SELECT 1; -- x\rCOMMIT":                         true,
		// scan.l continuation: a "--" comment before the newline, and \v
		"SELECT E'a' -- c\n'x\\'', 'y\\' ; INSERT INTO t VALUES (1)": true,
		"SELECT E'a'\n\v'x\\'', 'y\\' ; INSERT INTO t VALUES (1)":    true,
		// negatives
		"SELECT 'INSERT INTO x'":                   false,
		"SELECT 1 -- INSERT INTO t":                false,
		"SELECT \"insert\" FROM t WHERE a = 'b;c'": false,
	} {
		a, fx := newFixture("test.thing.modify")
		a.planWritesSQL, a.planSwallows, a.planSQL = true, true, sql
		got := slices.Contains(clauses(Check(a, fx)), ClausePlanReadOnly)
		if got != wantViolation {
			t.Errorf("Plan sending %q: plan-read-only violation = %v, want %v", sql, got, wantViolation)
		}
	}
}

// recorder is a testing.TB that records Errorf instead of failing the test.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Errorf(format string, a ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, a...))
}

func TestContractFailsTheTestNamingTheClause(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	a.nonIdempotent = true
	r := &recorder{TB: t}
	Contract(r, a, fx)
	// A non-idempotent fixture also fails to restore its before-state; the clause it breaks is named.
	if len(r.errs) == 0 || !strings.Contains(r.errs[0], "clause "+ClauseApplyIdempotent) || !strings.Contains(r.errs[0], `"test.thing.modify"`) {
		t.Fatalf("errors = %q", r.errs)
	}
}

// --- O5 third clause and the O7 behaviours that rest on the inverse -------------------------------

func hasClause(vs []Violation, clause string) bool { return slices.Contains(clauses(vs), clause) }

func detailOf(vs []Violation, clause string) string {
	for _, v := range vs {
		if v.Clause == clause {
			return v.Detail
		}
	}
	return ""
}

func TestInverseRestoresTheBeforeState(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	rec, vs := check(a, fx)
	if len(vs) != 0 {
		t.Fatal(vs)
	}
	if !slices.Contains(rec.Exercised, ClauseInverseRestores) || !slices.Contains(rec.Exercised, ClauseInverseAvailable) {
		t.Fatalf("exercised = %v", rec.Exercised)
	}
	// the harness left the directory in the forward run's after-state, and its counters at the forward run's
	if got := fx.Directory.Read(guid, "description"); !slices.Equal(got, []string{"hello"}) {
		t.Fatalf("description = %v", got)
	}
}

func TestInverseThatDoesNotRestoreFailsNamingTheClause(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	a.inverseWrongs = true
	vs := Check(a, fx)
	if !hasClause(vs, ClauseInverseRestores) || !strings.Contains(detailOf(vs, ClauseInverseRestores), guid+"/description") {
		t.Fatalf("an inverse that restores the wrong value passed: %v", vs)
	}
}

func TestApplyWithASideEffectTheInverseDoesNotUndoFails(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	a.lossyDeletes = "thumbnailPhoto" // the forward apply also wipes this; the Action says Reversible
	fx.Directory.Seed(guid, "thumbnailPhoto", "bytes")
	vs := Check(a, fx)
	if !hasClause(vs, ClauseInverseRestores) || !strings.Contains(detailOf(vs, ClauseInverseRestores), "thumbnailPhoto") {
		t.Fatalf("a Reversible Action that loses a field passed: %v", vs)
	}
	if hasClause(vs, ClauseLossyUndeclared) {
		t.Fatalf("a Reversible step was judged as Lossy: %v", vs)
	}
}

func TestInverseThatIsIrreversibleForAReversibleActionFails(t *testing.T) {
	for name, lossy := range map[string]bool{"Reversible": false, "Lossy": true} {
		t.Run(name, func(t *testing.T) {
			a, fx := newFixture("test.thing.modify")
			a.noInverse, a.lossy = true, lossy
			vs := Check(a, fx)
			if !hasClause(vs, ClauseInverseAvailable) || !strings.Contains(detailOf(vs, ClauseInverseAvailable), "ErrIrreversible") {
				t.Fatalf("an Action declaring %s whose Inverse is ErrIrreversible passed: %v", name, vs)
			}
		})
	}
}

// irreversibleAction declares Irreversible and says so in its plan: its Inverse is ErrIrreversible, rightly.
type irreversibleAction struct{ *fixtureAction }

func (a irreversibleAction) Describe() operation.Descriptor {
	d := a.fixtureAction.Describe()
	d.Reversibility = operation.Irreversible
	return d
}

func (a irreversibleAction) Plan(ctx context.Context, pc operation.PlanContext, in operation.Input) ([]operation.StepPlan, error) {
	steps, err := a.fixtureAction.Plan(ctx, pc, in)
	for i := range steps {
		steps[i].Reversibility = operation.Irreversible
	}
	return steps, err
}

func TestIrreversibleActionNeedsNoInverse(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	a.noInverse = true
	rec, vs := check(irreversibleAction{a}, fx)
	if len(vs) != 0 {
		t.Fatalf("an Irreversible Action with ErrIrreversible failed: %v", vs)
	}
	if slices.Contains(rec.Exercised, ClauseInverseAvailable) || slices.Contains(rec.Exercised, ClauseInverseRestores) {
		t.Fatalf("the inverse clauses were claimed for an Irreversible Action: %v", rec.Exercised)
	}
}

func TestLossyStepMayLoseOnlyWhatItDeclares(t *testing.T) {
	setup := func() (*fixtureAction, Fixture) {
		a, fx := newFixture("test.thing.modify")
		a.lossy, a.lossyDeletes = true, "thumbnailPhoto"
		fx.Directory.Seed(guid, "thumbnailPhoto", "bytes")
		return a, fx
	}
	t.Run("undeclared loss fails", func(t *testing.T) {
		a, fx := setup()
		vs := Check(a, fx)
		if !hasClause(vs, ClauseLossyUndeclared) || !strings.Contains(detailOf(vs, ClauseLossyUndeclared), "thumbnailPhoto") {
			t.Fatalf("a Lossy step that loses an undeclared field passed: %v", vs)
		}
		if hasClause(vs, ClauseInverseRestores) {
			t.Fatalf("a Lossy step's loss was judged as a Reversible failure: %v", vs)
		}
	})
	t.Run("declared loss passes", func(t *testing.T) {
		a, fx := setup()
		fx.Lost = []string{"thumbnailPhoto"}
		rec, vs := check(a, fx)
		if len(vs) != 0 {
			t.Fatalf("a declared loss was refused: %v", vs)
		}
		if !slices.Contains(rec.Exercised, ClauseLossyUndeclared) {
			t.Fatalf("exercised = %v", rec.Exercised)
		}
	})
	t.Run("declared for another object fails", func(t *testing.T) {
		a, fx := setup()
		fx.Lost = []string{"someone-else/thumbnailPhoto"}
		if vs := Check(a, fx); !hasClause(vs, ClauseLossyUndeclared) {
			t.Fatalf("a loss declared for another object passed: %v", vs)
		}
	})
	t.Run("declared for the object passes", func(t *testing.T) {
		a, fx := setup()
		fx.Lost = []string{guid + "/thumbnailPhoto"}
		if vs := Check(a, fx); len(vs) != 0 {
			t.Fatalf("%v", vs)
		}
	})
	t.Run("a plan that names nothing lost fails", func(t *testing.T) {
		a, fx := setup()
		fx.Lost = []string{"thumbnailPhoto"}
		noReason := &mutPlan{Action: a, mut: func(sp *operation.StepPlan) { sp.ReversibilityReason = "" }}
		if vs := Check(noReason, fx); !hasClause(vs, ClauseLossyUndeclared) || !strings.Contains(detailOf(vs, ClauseLossyUndeclared), "ReversibilityReason") {
			t.Fatalf("a Lossy step with no reason passed: %v", vs)
		}
	})
}

// mutPlan changes every step the Action plans.
type mutPlan struct {
	operation.Action
	mut func(*operation.StepPlan)
}

func (m *mutPlan) Plan(ctx context.Context, pc operation.PlanContext, in operation.Input) ([]operation.StepPlan, error) {
	steps, err := m.Action.Plan(ctx, pc, in)
	for i := range steps {
		m.mut(&steps[i])
	}
	return steps, err
}

func TestInverseOfAStoreActionIsRunByItsRestoreAction(t *testing.T) {
	// The action's inverse input is for another Action, as a Store family's is (ADR-0005 rule 10).
	a, fx := newFixture("test.thing.modify")
	restore, _ := newFixture("test.thing.restore")
	restore.dir = a.dir
	fx.InverseAction = restore
	if vs := Check(a, fx); len(vs) != 0 {
		t.Fatalf("%v", vs)
	}
	if restore.applies != 1 {
		t.Fatalf("the restore Action applied %d times, want once", restore.applies)
	}
}

// --- success, failure and denial events (AG-3, TM-F-AUDIT) --------------------------------------

// mutSink damages the events the runner appends: it can drop one or change a field, as a faulty
// Action or pipeline would.
type mutSink struct {
	audit.Sink
	mut func(audit.Event) (audit.Event, bool)
}

func (m mutSink) Append(ctx context.Context, tx store.Tx, ev audit.Event) error {
	ev, keep := m.mut(ev)
	if !keep {
		return nil
	}
	return m.Sink.Append(ctx, tx, ev)
}

func withSink(mut func(audit.Event) (audit.Event, bool)) options {
	return options{sink: func(s audit.Sink) audit.Sink { return mutSink{s, mut} }}
}

func TestEveryPathEmitsItsEvent(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	rec, vs := check(a, fx)
	if len(vs) != 0 {
		t.Fatal(vs)
	}
	for _, c := range []string{ClauseAuditSuccess, ClauseAuditFailure, ClauseAuditDenial} {
		if !slices.Contains(rec.Exercised, c) {
			t.Errorf("%s was not exercised: %v", c, rec.Exercised)
		}
	}
}

func TestMissingEventFailsTheClauseOfItsPath(t *testing.T) {
	for outcome, clause := range map[audit.Outcome]string{
		audit.Success: ClauseAuditSuccess, audit.Failure: ClauseAuditFailure, audit.Denied: ClauseAuditDenial,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			a, fx := newFixture("test.thing.modify")
			_, vs := checkWith(a, fx, withSink(func(ev audit.Event) (audit.Event, bool) { return ev, ev.Outcome != outcome }))
			if !hasClause(vs, clause) {
				t.Fatalf("a pipeline that never emits the %s event passed: %v", outcome, vs)
			}
			for _, other := range []string{ClauseAuditSuccess, ClauseAuditFailure, ClauseAuditDenial} {
				if other != clause && hasClause(vs, other) {
					t.Fatalf("dropping the %s event also failed %s: %v", outcome, other, vs)
				}
			}
		})
	}
}

func TestEventMissingAnAG3FieldFails(t *testing.T) {
	cases := map[string]func(*audit.Event){
		"kind": func(e *audit.Event) { e.Kind = "other.changed" },
		"actor": func(e *audit.Event) {
			e.Actor.Via = append(slices.Clone(e.Actor.Via), authority.Principal{ID: "token-1", Kind: authority.APIToken})
		},
		"target":    func(e *audit.Event) { e.Target.GUID = "" },
		"key":       func(e *audit.Event) { e.Key.Operation = "" },
		"component": func(e *audit.Event) { e.Component = "" },
		"reason":    func(e *audit.Event) { e.Reason = "" },
		"plan hash": func(e *audit.Event) { e.PlanHash = "" },
		"outcome": func(e *audit.Event) {
			if e.Outcome == audit.Success {
				e.Outcome = audit.Failure
			} else {
				e.Outcome = audit.Success
			}
		},
	}
	for field, damage := range cases {
		for outcome, clause := range map[audit.Outcome]string{
			audit.Success: ClauseAuditSuccess, audit.Failure: ClauseAuditFailure, audit.Denied: ClauseAuditDenial,
		} {
			t.Run(field+"/"+string(outcome), func(t *testing.T) {
				a, fx := newFixture("test.thing.modify")
				_, vs := checkWith(a, fx, withSink(func(ev audit.Event) (audit.Event, bool) {
					if ev.Outcome == outcome {
						damage(&ev)
					}
					return ev, true
				}))
				if !hasClause(vs, clause) {
					t.Fatalf("an event with a damaged %s passed %s: %v", field, clause, vs)
				}
			})
		}
	}
}

func TestEventThatDoesNotValidateIsReportedUnderItsClause(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	_, vs := checkWith(a, fx, withSink(func(ev audit.Event) (audit.Event, bool) {
		if ev.Outcome == audit.Denied {
			ev.ID = ""
		}
		return ev, true
	}))
	if d := detailOf(vs, ClauseAuditDenial); !strings.Contains(d, "Validate") {
		t.Fatalf("violations = %v", vs)
	}
}

func TestSuccessEventRecordsThePlansBeforeAndAfter(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	_, vs := checkWith(a, fx, withSink(func(ev audit.Event) (audit.Event, bool) {
		if ev.Outcome == audit.Success && len(ev.Changes) > 0 {
			ev.Changes = slices.Clone(ev.Changes)
			ev.Changes[0].After = []string{"something else"}
		}
		return ev, true
	}))
	if !hasClause(vs, ClauseAuditSuccess) || !strings.Contains(detailOf(vs, ClauseAuditSuccess), "before/after") {
		t.Fatalf("an event recording a different after-value passed: %v", vs)
	}
}

func TestSecretChangeCarriesNoValueInTheEvent(t *testing.T) {
	secret := func(sp *operation.StepPlan) {
		sp.Diff = append(sp.Diff, operation.Change{Attribute: "unicodePwd", Before: []string{"old"}, After: []string{"new"}, Secret: true})
	}
	a, fx := newFixture("test.thing.modify")
	// The runner redacts a secret value from the plan before the event: a correct pipeline passes...
	if vs := Check(&mutPlan{Action: a, mut: secret}, fx); len(vs) != 0 {
		t.Fatalf("a redacted secret change failed: %v", vs)
	}
	// ...and one that lets the value into the event does not (AG-9).
	_, vs := checkWith(&mutPlan{Action: a, mut: secret}, fx, withSink(func(ev audit.Event) (audit.Event, bool) {
		ev.Changes = cloneChanges(ev.Changes)
		for i := range ev.Changes {
			if ev.Changes[i].Secret {
				ev.Changes[i].After = []string{"new"}
			}
		}
		return ev, true
	}))
	if !hasClause(vs, ClauseAuditSuccess) || !strings.Contains(detailOf(vs, ClauseAuditSuccess), "secret") {
		t.Fatalf("an event carrying a secret value passed: %v", vs)
	}
}

func TestUnflaggedSecretAttributeFailsAG9(t *testing.T) {
	for _, attr := range []string{"unicodePwd", "UnicodePWD", "ms-Mcs-AdmPwd", "msLAPS-Password"} {
		a, fx := newFixture("test.thing.modify")
		unflagged := &mutPlan{Action: a, mut: func(sp *operation.StepPlan) {
			sp.Diff = append(sp.Diff, operation.Change{Attribute: attr, Before: []string{"old"}, After: []string{"P@ssw0rd!"}})
		}}
		vs := Check(unflagged, fx)
		if !hasClause(vs, ClauseAuditSuccess) || !strings.Contains(detailOf(vs, ClauseAuditSuccess), "AG-9") || !strings.Contains(detailOf(vs, ClauseAuditSuccess), attr) {
			t.Errorf("%s planned with Secret=false passed or did not name AG-9: %v", attr, vs)
		}
	}
}

func TestApplyAfterTheRecheckRefusedFailsTheDenialClause(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	hd := &harness{inner: a, fx: fx, d: a.Describe(), actor: authority.Chain{Requester: authority.Principal{ID: "h", Kind: authority.Human}},
		mode: modeDenial, deny: &denyAfterPlan{}}
	// A runner regression that reaches Apply anyway: authorisation allows the re-check.
	out, err := hd.run(&probe{h: hd}, allowAll{}, fx.Input, "denial")
	if err != nil {
		t.Fatal(err)
	}
	vs := hd.denialViolations(out)
	if !hasClause(vs, ClauseAuditDenial) || !strings.Contains(detailOf(vs, ClauseAuditDenial), "Apply ran") {
		t.Fatalf("an Apply after the refused re-check passed: %v", vs)
	}
	if fx.Directory.Changes() != 0 {
		t.Fatalf("the Action's Apply was called in the denial path: %d change(s)", fx.Directory.Changes())
	}
}

func TestApplyThatSwallowsTheDirectoryErrorFails(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	a.swallowsFail = true
	vs := Check(a, fx)
	if !hasClause(vs, ClauseAuditFailure) || !strings.Contains(detailOf(vs, ClauseAuditFailure), "refused its write") {
		t.Fatalf("an Apply that reports success when the write was refused passed: %v", vs)
	}
}

func TestFailureAndDenialPathsLeaveNoTrace(t *testing.T) {
	a, fx := newFixture("test.thing.modify")
	// A Plan-only look: the failure and denial paths must not change the directory or its counters.
	before := fx.Directory.snapshot()
	hf := &harness{inner: a, fx: fx, d: a.Describe(), actor: authority.Chain{Requester: authority.Principal{ID: "h", Kind: authority.Human}},
		mode: modeFailure, deny: &denyAfterPlan{}}
	if _, err := hf.run(&probe{h: hf}, allowAll{}, fx.Input, "failure"); err != nil {
		t.Fatal(err)
	}
	if fx.Directory.Writes() != 0 || fx.Directory.Changes() != 0 || !reflect.DeepEqual(before, fx.Directory.snapshot()) {
		t.Fatalf("the failure path left writes=%d changes=%d state=%v", fx.Directory.Writes(), fx.Directory.Changes(), fx.Directory.snapshot())
	}
}

func TestNoStepMeansNoInverseFailureOrDenialToDrive(t *testing.T) {
	rec, vs := check(moduletest.Action("test.noop.run"), Fixture{Input: operation.Input(`{}`)})
	if len(vs) != 0 {
		t.Fatal(vs)
	}
	for _, c := range []string{ClauseInverseAvailable, ClauseInverseRestores, ClauseLossyUndeclared, ClauseAuditSuccess, ClauseAuditFailure, ClauseAuditDenial} {
		if slices.Contains(rec.Exercised, c) {
			t.Errorf("%s claimed for an Action that plans no step", c)
		}
	}
}
