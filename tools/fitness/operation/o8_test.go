package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures run the real `go test` in a throw-away module, so each case proves the check fails
// on the violation it names and passes on the clean tree.

const o8FixtureManifest = `package operation

type o8Test struct{ Dir, Name string }
type o8Clause struct {
	ID, Rule, Gap string
	Tests         []o8Test
}

const opDir = "internal/platform/operation"

var o8Manifest = []o8Clause{
	{ID: "O8.alpha", Rule: "alpha holds", Tests: []o8Test{{opDir, "TestAlpha"}}},
	{ID: "O8.beta", Rule: "beta holds", Tests: []o8Test{{opDir, "TestBeta"}}},
	{ID: "O8.later", Rule: "later holds", Gap: "T-0824: not evaluated yet"},
}
`

func o8Tree(t *testing.T, manifest, tests string, extra map[string]string) string {
	t.Helper()
	files := map[string]string{
		"internal/platform/operation/o8_manifest_test.go": manifest,
		"internal/platform/operation/x_test.go":           tests,
	}
	for k, v := range extra {
		files[k] = v
	}
	return tree(t, fixtureDAG, files)
}

const o8Clean = `package operation

import "testing"

func TestAlpha(t *testing.T) {}
func TestBeta(t *testing.T)  { t.Run("sub", func(t *testing.T) {}) }
`

func runO8(t *testing.T, root string, lab bool) ([]Violation, O8Report) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}
	vs, rep, err := CheckO8(context.Background(), root, lab, GoTestRunner)
	if err != nil {
		t.Fatal(err)
	}
	return vs, rep
}

func TestO8Passes(t *testing.T) {
	vs, rep := runO8(t, o8Tree(t, o8FixtureManifest, o8Clean, nil), false)
	if len(vs) != 0 {
		t.Fatalf("violations = %v", vs)
	}
	if rep.Clauses != 3 || rep.Pinned != 2 || rep.Ran != 2 || len(rep.Gaps) != 1 || !strings.Contains(rep.Gaps[0], "T-0824") {
		t.Fatalf("report = %+v", rep)
	}
}

func TestO8Violations(t *testing.T) {
	cases := map[string]struct{ tests, want string }{
		"a bound test fails":           {strings.Replace(o8Clean, "func TestAlpha(t *testing.T) {}", "func TestAlpha(t *testing.T) { t.Fatal(\"boom\") }", 1), "TestAlpha: O8 [pipeline behaviour] the test failed"},
		"a bound test is skipped":      {strings.Replace(o8Clean, "func TestAlpha(t *testing.T) {}", "func TestAlpha(t *testing.T) { t.Skip(\"no docker\") }", 1), "skipped"},
		"a bound subtest is skipped":   {strings.Replace(o8Clean, `t.Run("sub", func(t *testing.T) {})`, `t.Run("sub", func(t *testing.T) { t.Skip("x") })`, 1), "a subtest was skipped"},
		"a bound test is renamed":      {strings.Replace(o8Clean, "TestBeta", "TestBetaRenamed", 1), "TestBeta: O8 [pipeline behaviour] O8.beta: the test the manifest names does not exist"},
		"a bound test is deleted":      {"package operation\n\nimport \"testing\"\n\nfunc TestAlpha(t *testing.T) {}\n", "TestBeta: O8 [pipeline behaviour] O8.beta: the test the manifest names does not exist"},
		"the package no longer builds": {o8Clean + "\nfunc broken() { undefinedSymbol() }\n", "did not run"},
	}
	for name, c := range cases {
		vs, _ := runO8(t, o8Tree(t, o8FixtureManifest, c.tests, nil), false)
		if len(vs) == 0 {
			t.Errorf("%s: no violation", name)
			continue
		}
		var all []string
		for _, v := range vs {
			if v.Check != "O8" || !strings.Contains(v.String(), "O8 [pipeline behaviour]") {
				t.Errorf("%s: %v is not an O8 violation", name, v)
			}
			all = append(all, v.String())
		}
		if !strings.Contains(strings.Join(all, "\n"), c.want) {
			t.Errorf("%s: %v, want one containing %q", name, all, c.want)
		}
	}
}

func TestO8ManifestShape(t *testing.T) {
	bad := map[string]struct{ manifest, want string }{
		"a clause with neither tests nor gap": {strings.Replace(o8FixtureManifest, `Tests: []o8Test{{opDir, "TestBeta"}}`, ``, 1), "needs named tests or a Gap"},
		"a gap with no ticket":                {strings.Replace(o8FixtureManifest, `T-0824: not`, `someday: not`, 1), "must name the ticket"},
		"a duplicate clause":                  {strings.Replace(o8FixtureManifest, `O8.beta`, `O8.alpha`, 1), "duplicate clause"},
	}
	for name, c := range bad {
		vs, _ := runO8(t, o8Tree(t, c.manifest, o8Clean, nil), false)
		if len(vs) == 0 || !strings.Contains(vs[0].String(), c.want) {
			t.Errorf("%s: %v, want %q", name, vs, c.want)
		}
	}
	// A tree with no manifest at all is an error, never a pass.
	root := o8Tree(t, o8FixtureManifest, o8Clean, nil)
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(o8ManifestFile))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckO8(context.Background(), root, false, GoTestRunner); err == nil {
		t.Fatal("a missing manifest must fail the check")
	}
}

const o8LabManifest = `package operation

type o8Test struct{ Dir, Name string }
type o8Clause struct {
	ID, Rule, Gap string
	Tests         []o8Test
}

var o8Manifest = []o8Clause{
	{ID: "O8.lab", Rule: "lab holds", Tests: []o8Test{{"internal/platform/operation", "TestLabThing"}}},
}
`

func TestO8LabTestsAreListedUnlessRequested(t *testing.T) {
	labTest := "//go:build lab\n\npackage operation\n\nimport \"testing\"\n\nfunc TestLabThing(t *testing.T) { t.Fatal(\"lab says no\") }\n"
	root := o8Tree(t, o8LabManifest, "package operation\n", map[string]string{"internal/platform/operation/lab_test.go": labTest})
	vs, rep := runO8(t, root, false)
	if len(vs) != 0 || len(rep.LabNotRun) != 1 || rep.Ran != 0 {
		t.Fatalf("without -o8-lab: violations %v, report %+v", vs, rep)
	}
	vs, _ = runO8(t, root, true)
	if len(vs) != 1 || !strings.Contains(vs[0].Msg, "the test failed") {
		t.Fatalf("with -o8-lab a failing lab test must fail the check: %v", vs)
	}
	// A lab test that was deleted is a violation even when the lab is not run.
	gone := o8Tree(t, o8LabManifest, "package operation\n", nil)
	vs, _ = runO8(t, gone, false)
	if len(vs) != 1 || !strings.Contains(vs[0].Msg, "does not exist") {
		t.Fatalf("a missing lab test: %v", vs)
	}
}

// TestO8RealManifestParses pins the real manifest to the shape the check reads: a change to the
// manifest's layout must not turn the check into a no-op.
func TestO8RealManifestParses(t *testing.T) {
	cs, err := ReadO8Manifest("../../..")
	if err != nil {
		t.Fatal(err)
	}
	pinned := 0
	for _, c := range cs {
		if c.ID == "" || c.Rule == "" {
			t.Errorf("clause %+v has no ID or Rule", c)
		}
		pinned += len(c.Tests)
	}
	if len(cs) < 20 || pinned < 30 {
		t.Fatalf("manifest read as %d clauses, %d tests: the parser is missing most of it", len(cs), pinned)
	}
}
