package operationtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
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
	planSwallows  bool
	nonIdempotent bool
	verifyBlind   bool
	planHook      func() // runs inside Plan, for a Plan that misbehaves in a way a flag cannot say
	applies       int
}

func (a *fixtureAction) Describe() operation.Descriptor {
	return operation.Descriptor{ID: a.id, Version: 1, Permission: "test.permission",
		Input: "#/components/schemas/Test", Target: operation.TargetAD,
		Reversibility: operation.Reversible, AuditKind: "test.changed"}
}

func (a *fixtureAction) Plan(ctx context.Context, pc operation.PlanContext, _ operation.Input) ([]operation.StepPlan, error) {
	if a.planWritesSQL {
		_, err := pc.Tx.Exec(ctx, "INSERT INTO thing (id) VALUES ($1)", "x")
		if err != nil && !a.planSwallows {
			return nil, err
		}
	}
	if a.planHook != nil {
		a.planHook()
	}
	return []operation.StepPlan{{
		Target: authority.TargetRef{GUID: guid, Class: "user"}, Kind: "modify", Reversibility: operation.Reversible,
		Diff: []operation.Change{{Attribute: "description", After: []string{"hello"}}},
	}}, nil
}

func (a *fixtureAction) Apply(_ context.Context, s step.Step, _ operation.StepPlan) (operation.Outcome, error) {
	a.applies++
	m := Mutation{GUID: guid, Attribute: "description", Op: Replace, Values: []string{"hello"}}
	if a.nonIdempotent {
		m = Mutation{GUID: guid, Attribute: "log", Op: Add, Values: []string{fmt.Sprint("apply-", a.applies)}}
	}
	return operation.Outcome{}, a.dir.Write(s, m)
}

func (a *fixtureAction) Verify(context.Context, step.Step, operation.StepPlan, operation.Outcome) (operation.Verdict, error) {
	if a.verifyBlind || slices.Equal(a.dir.Read(guid, "description"), []string{"hello"}) ||
		a.nonIdempotent && len(a.dir.Read(guid, "log")) > 0 {
		return operation.Verdict{OK: true}, nil
	}
	return operation.Verdict{Reason: "read_back_mismatch"}, nil
}

func (a *fixtureAction) Inverse(operation.StepPlan, operation.Outcome) (operation.Input, error) {
	return nil, operation.ErrIrreversible
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
	if a.applies != 2 {
		t.Fatalf("Apply ran %d times, the clause runs it twice", a.applies)
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
		Reversibility: operation.Reversible, AuditKind: "test.changed"}
}
func (*sqlAction) Plan(context.Context, operation.PlanContext, operation.Input) ([]operation.StepPlan, error) {
	return []operation.StepPlan{{Target: authority.TargetRef{GUID: "row-1", Class: "thing"}, Kind: "set", Reversibility: operation.Reversible}}, nil
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
	if want := []string{ClausePlanReadOnly, ClauseApplyIdempotent, ClauseVerifyAfterDrop}; !slices.Equal(rec.Exercised, want) {
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
		r.Test != t.Name() || r.At.IsZero() || len(r.Exercised) != 3 {
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
	if err != nil || len(recs) != 1 || recs[0].Passed || !slices.Equal(recs[0].Violations, []string{ClauseApplyIdempotent}) {
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
		"SET TRANSACTION READ ONLY":                      false,
		"SELECT set_config('a', 'b', true)":              false,
	} {
		if got := isWrite(sqlWords(sql)); got != want {
			t.Errorf("isWrite(%q) = %v, want %v", sql, got, want)
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
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "clause "+ClauseApplyIdempotent) || !strings.Contains(r.errs[0], `"test.thing.modify"`) {
		t.Fatalf("errors = %q", r.errs)
	}
}
