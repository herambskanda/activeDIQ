package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/tools/fitness/internal/boundtest"
)

const mod = "example.test/m"

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// base is a small repository that has the report packages and obeys every rule.
func base() map[string]string {
	return map[string]string{
		"go.mod": "module " + mod + "\n\ngo 1.22\n",
		"internal/platform/authz/authz.go": `package authz

type ReadScope struct{ n int }

func NewReadScope(n int) ReadScope    { return ReadScope{n} }
func (s ReadScope) Terms() []int      { return nil }
func (s ReadScope) Token() (int, bool) { return 0, false }
func (s ReadScope) Empty() bool       { return s.n == 0 }
`,
		"internal/platform/authz/authztest/authztest.go": `package authztest

import "` + mod + `/internal/platform/authz"

func ReadScope(n int) authz.ReadScope { return authz.NewReadScope(n) }
`,
		"internal/platform/rbac/rbac.go": `package rbac

import "` + mod + `/internal/platform/authz"

func For() authz.ReadScope { return authz.NewReadScope(1) }
`,
		"internal/platform/store/reportsql/reportsql.go": `package reportsql

import "` + mod + `/internal/platform/authz"

type CompiledSQL string
type Query struct{ sql CompiledSQL }
type Registry struct{}

func (r *Registry) Compile(s authz.ReadScope) Query    { _ = s.Terms(); _, _ = s.Token(); return Query{} }
func (r *Registry) CompileCount(s authz.ReadScope) Query { return Query{} }
func (r *Registry) Exec(q Query) error                { return nil }
`,
		"internal/platform/report/report.go": `package report

type Dataset struct{ ID string }
`,
		"internal/modules/reports/run/run.go": `package run

import "` + mod + `/internal/platform/store/reportsql"

func Do(r *reportsql.Registry) error { return r.Exec(r.Compile(nil2())) }
`,
		"internal/modules/reports/run/scope.go": `package run

import "` + mod + `/internal/platform/authz"

func nil2() authz.ReadScope { return authz.ReadScope{} }
`,
		"internal/modules/reports/export/export.go": `package export

func Write(rows []string) int { return len(rows) }
`,
		"internal/directory/inventory/datasets.go": `package inventory

import "` + mod + `/internal/platform/report"

func Datasets() []report.Dataset {
	return []report.Dataset{{ID: "inventory.users"}, {ID: "inventory.groups"}}
}
`,
	}
}

func tree(t *testing.T, extra map[string]string) string {
	t.Helper()
	files := base()
	for k, v := range extra {
		files[k] = v
	}
	root := t.TempDir()
	write(t, root, files)
	return root
}

func run(t *testing.T, root string, o Options) *Result {
	t.Helper()
	o.Root = root
	o.StaticOnly = o.StaticOnly || o.Bindings == nil
	r, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func expect(t *testing.T, r *Result, check, rule, where, msg string) {
	t.Helper()
	for _, v := range r.Violations {
		if v.Check == check && v.Rule == rule && strings.Contains(v.Where, where) && strings.Contains(v.Msg, msg) {
			return
		}
	}
	t.Fatalf("want %s [%s] at %q containing %q, got:\n%v", check, rule, where, msg, r.Violations)
}

func TestCleanTreePasses(t *testing.T) {
	r := run(t, tree(t, nil), Options{})
	if len(r.Violations) != 0 {
		t.Fatalf("clean tree: %v", r.Violations)
	}
	for _, p := range r.Pending {
		if strings.HasPrefix(p, "RP2") || strings.HasPrefix(p, "RP3") {
			t.Fatalf("RP2/RP3 must be active when the packages exist, pending: %v", r.Pending)
		}
	}
	if got := strings.Join(r.Pending, ";"); !strings.Contains(got, "RP7") {
		t.Fatalf("RP7 must be pending without a library: %v", r.Pending)
	}
}

// A tree without the report packages is pending, not passing.
func TestAbsentPackagesArePending(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"go.mod": "module " + mod + "\n\ngo 1.22\n", "main.go": "package main\n\nfunc main() {}\n"})
	r := run(t, root, Options{})
	if len(r.Violations) != 0 || len(r.Pending) != 3 {
		t.Fatalf("violations %v pending %v", r.Violations, r.Pending)
	}
}

// ---- RP3 ----

func TestRP3ExportCallsCompile(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/export/bad.go": `package export

import (
	"` + mod + `/internal/platform/authz"
	"` + mod + `/internal/platform/store/reportsql"
)

func Rerun(r *reportsql.Registry) error { return r.Exec(r.Compile(authz.ReadScope{})) }
`}), Options{})
	expect(t, r, "RP3", "export-compiles", "internal/modules/reports/export/bad.go:", "reportsql.Compile")
	expect(t, r, "RP3", "export-compiles", "internal/modules/reports/export/bad.go:", "reportsql.Exec")
}

func TestRP3EveryCompilerEntryAndMethodValue(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/schedule/s.go": `package schedule

import (
	"` + mod + `/internal/platform/authz"
	"` + mod + `/internal/platform/store/reportsql"
)

func Count(r *reportsql.Registry) reportsql.Query { return r.CompileCount(authz.ReadScope{}) }

var viaValue = (*reportsql.Registry).Exec
`}), Options{})
	expect(t, r, "RP3", "export-compiles", "schedule/s.go:", "CompileCount")
	expect(t, r, "RP3", "export-compiles", "schedule/s.go:", "reportsql.Exec")
}

func TestRP3ReportsRootPackageIsJudged(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/reports.go": `package reports

import "` + mod + `/internal/platform/store/reportsql"

func f(r *reportsql.Registry) error { return r.Exec(reportsql.Query{}) }
`}), Options{})
	expect(t, r, "RP3", "export-compiles", "internal/modules/reports/reports.go:", "Exec")
}

func TestRP3InterfaceIsASecondDoor(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/export/iface.go": `package export

import (
	"` + mod + `/internal/platform/authz"
	"` + mod + `/internal/platform/store/reportsql"
)

type compiler interface {
	Compile(authz.ReadScope) reportsql.Query
}
`}), Options{})
	expect(t, r, "RP3", "export-compiles", "export/iface.go:", "second door")
}

// An Exec method that has nothing to do with reportsql is not a violation.
func TestRP3UnrelatedExecInterfaceIsFine(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/export/x.go": `package export

type runner interface{ Exec(string) error }
`}), Options{})
	if len(r.Violations) != 0 {
		t.Fatalf("%v", r.Violations)
	}
}

func TestRP3OutsideReportsModuleIsNotRP3(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/platform/jobs/j.go": `package jobs

import "` + mod + `/internal/platform/store/reportsql"

func f(r *reportsql.Registry) error { return r.Exec(reportsql.Query{}) }
`}), Options{})
	for _, v := range r.Violations {
		if v.Check == "RP3" {
			t.Fatalf("RP3 is stated for internal/modules/reports/**: %v", v)
		}
	}
}

// ---- RP2 ----

func TestRP2TermsAndTokenOutsideRendererFail(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/export/scope.go": `package export

import "` + mod + `/internal/platform/authz"

func Leak(s authz.ReadScope) []int { _, _ = s.Token(); return s.Terms() }
`, "internal/platform/store/other/o.go": `package other

import "` + mod + `/internal/platform/authz"

var m = authz.ReadScope.Terms
`}), Options{})
	expect(t, r, "RP2", "scope-renderer", "export/scope.go:", "ReadScope.Token")
	expect(t, r, "RP2", "scope-renderer", "export/scope.go:", "ReadScope.Terms")
	expect(t, r, "RP2", "scope-renderer", "other/o.go:", "ReadScope.Terms") // a method expression
}

func TestRP2TermsThroughEmbeddingFails(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/x/x.go": `package x

import "` + mod + `/internal/platform/authz"

type wrapped struct{ authz.ReadScope }

func f(w wrapped) []int { return w.Terms() }
`}), Options{})
	expect(t, r, "RP2", "scope-renderer", "x/x.go:", "ReadScope.Terms")
}

func TestRP2NewReadScopeOutsideProducerFails(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/run/mint.go": `package run

import "` + mod + `/internal/platform/authz"

func Mint() authz.ReadScope { return authz.NewReadScope(99) }
`}), Options{})
	expect(t, r, "RP2", "scope-producer", "run/mint.go:", "NewReadScope")
}

func TestRP2ProductImportOfAuthztestFails(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/y/y.go": `package y

import "` + mod + `/internal/platform/authz/authztest"

var s = authztest.ReadScope(1)
`}), Options{})
	expect(t, r, "RP2", "test-double-import", "y/y.go:", "authztest")
}

// Test files are not judged by RP2 (the rule is stated for non-test files).
func TestRP2TestFilesAreNotJudged(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/export/e_test.go": `package export

import (
	"testing"

	"` + mod + `/internal/platform/authz"
)

func TestX(t *testing.T) { _ = authz.NewReadScope(1).Terms() }
`}), Options{})
	if len(r.Violations) != 0 {
		t.Fatalf("%v", r.Violations)
	}
}

// A package that uses the scope types but does not type-check is a failure, never a pass.
func TestBrokenPackageFailsClosed(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/export/broken.go": `package export

import "` + mod + `/internal/platform/authz"

func f(s authz.ReadScope) int { return undefinedName + s.Missing() }
`}), Options{})
	expect(t, r, "RP2", "type-check", "export/broken.go:", "does not type-check")
}

// ---- RP11 dataset enumeration ----

func TestDatasetIDMustBeConstant(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/directory/inventory/dyn.go": `package inventory

import "` + mod + `/internal/platform/report"

func Dyn(id string) report.Dataset { return report.Dataset{ID: id} }
`}), Options{})
	expect(t, r, "RP11", "dataset-id", "inventory/dyn.go:", "not a constant")
}

// ---- RP7 ----

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

const defA = `{"id":"USR-01","version":1}`

func libTree(t *testing.T, extra map[string]string) string {
	files := map[string]string{
		libraryDir + "/USR-01.v1.json": defA,
		lockFile:                       "# shipped definitions\n" + sha(defA) + "  USR-01.v1.json\n",
	}
	for k, v := range extra {
		if v == "\x00" {
			delete(files, k)
			continue
		}
		files[k] = v
	}
	return tree(t, files)
}

func TestRP7CleanLibraryPasses(t *testing.T) {
	r := run(t, libTree(t, nil), Options{})
	if len(r.Violations) != 0 {
		t.Fatalf("%v", r.Violations)
	}
	for _, p := range r.Pending {
		if strings.HasPrefix(p, "RP7") {
			t.Fatalf("RP7 pending although the library exists: %v", r.Pending)
		}
	}
}

func TestRP7ChangedByteFails(t *testing.T) {
	r := run(t, libTree(t, map[string]string{libraryDir + "/USR-01.v1.json": `{"id":"USR-01","version":2}`}), Options{})
	expect(t, r, "RP7", "locked-file-changed", "USR-01.v1.json", "ship a new version")
}

func TestRP7SingleByteFlipFails(t *testing.T) {
	r := run(t, libTree(t, map[string]string{libraryDir + "/USR-01.v1.json": defA + "\n"}), Options{})
	expect(t, r, "RP7", "locked-file-changed", "USR-01.v1.json", "changed")
}

func TestRP7DeletedFileFails(t *testing.T) {
	r := run(t, libTree(t, map[string]string{libraryDir + "/USR-01.v1.json": "\x00", libraryDir + "/keep.txt": "x"}), Options{})
	expect(t, r, "RP7", "locked-file-missing", "USR-01.v1.json", "missing")
}

func TestRP7UnlistedFileFails(t *testing.T) {
	r := run(t, libTree(t, map[string]string{libraryDir + "/sub/USR-02.v1.json": `{}`}), Options{})
	expect(t, r, "RP7", "unlisted-file", "sub/USR-02.v1.json", "not listed")
}

func TestRP7MissingLockFails(t *testing.T) {
	r := run(t, libTree(t, map[string]string{lockFile: "\x00"}), Options{})
	expect(t, r, "RP7", "lock-missing", "LOCK", "no LOCK")
}

func TestRP7MalformedAndEscapingEntriesFail(t *testing.T) {
	r := run(t, libTree(t, map[string]string{lockFile: sha(defA) + "  USR-01.v1.json\nnot a line\n" + sha("x") + "  ../x.json\n" + sha(defA) + "  USR-01.v1.json\n"}), Options{})
	expect(t, r, "RP7", "lock-format", "LOCK:2", "sha256")
	expect(t, r, "RP7", "lock-path", "LOCK:3", "clean relative path")
	expect(t, r, "RP7", "lock-duplicate", "LOCK:4", "twice")
}

func gitRun(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// The LOCK file cannot be edited together with the definition it protects.
func TestRP7LockRewrittenAgainstBaseFails(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := libTree(t, nil)
	gitRun(t, root, "init", "-q", "-b", "main")
	gitRun(t, root, "add", ".")
	gitRun(t, root, "commit", "-q", "-m", "base")

	// a new version appended: fine
	newDef := `{"id":"USR-01","version":2}`
	write(t, root, map[string]string{
		libraryDir + "/USR-01.v2.json": newDef,
		lockFile:                       "# shipped\n" + sha(defA) + "  USR-01.v1.json\n" + sha(newDef) + "  USR-01.v2.json\n",
	})
	if r := run(t, root, Options{LockBase: "main"}); len(r.Violations) != 0 {
		t.Fatalf("appending a version must pass: %v", r.Violations)
	}

	if err := os.Remove(filepath.Join(root, libraryDir, "USR-01.v2.json")); err != nil {
		t.Fatal(err)
	}
	// definition and LOCK both edited: LOCK is self-consistent but rewrites a base entry
	edited := `{"id":"USR-01","version":1,"edited":true}`
	write(t, root, map[string]string{
		libraryDir + "/USR-01.v1.json": edited,
		lockFile:                       sha(edited) + "  USR-01.v1.json\n",
	})
	r := run(t, root, Options{LockBase: "main"})
	expect(t, r, "RP7", "lock-entry-rewritten", "LOCK", "USR-01.v1.json")
	if r2 := run(t, root, Options{}); len(r2.Violations) != 0 {
		t.Fatalf("without -lock-base the self-consistent edit passes (and the job says so in a note): %v", r2.Violations)
	}

	// an entry dropped from LOCK (its file is then unlisted too)
	write(t, root, map[string]string{libraryDir + "/USR-01.v1.json": defA, lockFile: "# nothing\n"})
	r = run(t, root, Options{LockBase: "main"})
	expect(t, r, "RP7", "lock-entry-removed", "LOCK", "gone")
	expect(t, r, "RP7", "unlisted-file", "USR-01.v1.json", "not listed")
}

func TestRP7UnresolvableBaseIsAnError(t *testing.T) {
	root := libTree(t, nil)
	gitRun(t, root, "init", "-q", "-b", "main")
	_, err := Run(context.Background(), Options{Root: root, StaticOnly: true, LockBase: "no-such-ref"})
	if err == nil || !strings.Contains(err.Error(), "no-such-ref") {
		t.Fatalf("want an error naming the ref, got %v", err)
	}
}

// ---- bound tests (RP4, RP5, RP6, RP8, RP9, RP10, RP11) ----

func ev(action, test string) string {
	return `{"Action":"` + action + `","Package":"p","Test":"` + test + `"}`
}

func fake(lines ...string) boundtest.Runner {
	return func(context.Context, string, []string, []string) ([]byte, error) {
		return []byte(strings.Join(lines, "\n") + "\n"), nil
	}
}

func landed(name string) []binding {
	for _, b := range defaultBindings {
		if b.Name == name {
			b.Landed = true
			return []binding{b}
		}
	}
	panic(name)
}

func TestEveryRPTestIsBound(t *testing.T) {
	want := map[string]string{
		"RP4": "Test_expired_run_is_not_served", "RP5": "Test_export_digest_equals_run_digest",
		"RP6": "Test_compiled_scope_matches_read_oracle", "RP8": "Test_derived_columns_match_reference",
		"RP9": "Test_run_read_bound_to_runner_and_scope", "RP10": "Test_delivery_link_authorised_by_delivery_row",
		"RP11": "Test_dataset_reveals_nothing_outside_scope",
	}
	got := map[string]string{}
	for _, b := range defaultBindings {
		got[b.Check] = b.Name
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s bound to %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("bindings %v", got)
	}
}

func TestBoundTestsPendingUntilLanded(t *testing.T) {
	// The shipped bindings change as the rows land (RP6 is landed); this tests the not-landed path
	// for every check, so it clears the flag on a copy.
	bs := slices.Clone(defaultBindings)
	for i := range bs {
		bs[i].Landed = false
	}
	r := run(t, tree(t, nil), Options{Bindings: bs})
	if len(r.Violations) != 0 || len(r.Pending) < 7 {
		t.Fatalf("violations %v pending %v", r.Violations, r.Pending)
	}
}

func TestBoundTestAbsentFailsNamingIt(t *testing.T) {
	for _, name := range []string{"Test_expired_run_is_not_served", "Test_export_digest_equals_run_digest", "Test_compiled_scope_matches_read_oracle", "Test_derived_columns_match_reference", "Test_run_read_bound_to_runner_and_scope", "Test_delivery_link_authorised_by_delivery_row"} {
		r := run(t, tree(t, nil), Options{Bindings: landed(name), Runner: fake(`{"Action":"output","Output":"testing: warning: no tests to run\n"}`)})
		found := false
		for _, v := range r.Violations {
			found = found || (v.Rule == "test-missing" && strings.Contains(v.Where, name))
		}
		if !found {
			t.Errorf("%s: absent test not reported: %v", name, r.Violations)
		}
	}
}

func TestBoundTestSkippedOrFailedFails(t *testing.T) {
	name := "Test_export_digest_equals_run_digest"
	r := run(t, tree(t, nil), Options{Bindings: landed(name), Runner: fake(ev("skip", name))})
	expect(t, r, "RP5", "test-skipped", name, "skipped")
	r = run(t, tree(t, nil), Options{Bindings: landed(name), Runner: fake(ev("fail", name))})
	expect(t, r, "RP5", "test-failed", name, "failed")
	r = run(t, tree(t, nil), Options{Bindings: landed(name), Runner: fake(ev("skip", name+"/needs_docker"), ev("pass", name))})
	expect(t, r, "RP5", "test-skipped", name, "subtest was skipped")
	r = run(t, tree(t, nil), Options{Bindings: landed(name), Runner: fake(ev("pass", name))})
	if len(r.Violations) != 0 {
		t.Fatalf("a passing test: %v", r.Violations)
	}
}

func TestDeclaredButNotLandedFails(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/export/d_test.go": `package export

import "testing"

func Test_export_digest_equals_run_digest(t *testing.T) {}
`}), Options{Bindings: defaultBindings})
	expect(t, r, "RP5", "binding-not-landed", "Test_export_digest_equals_run_digest", "flip it")
}

const rp11 = "Test_dataset_reveals_nothing_outside_scope"

func rp11Tree(t *testing.T) string {
	return tree(t, map[string]string{"internal/directory/inventory/rp11_test.go": `package inventory

import "testing"

func ` + rp11 + `(t *testing.T) {}
`})
}

// One subtest per registered dataset: a dataset the test does not cover fails and is named.
func TestRP11DatasetWithoutSubtestFails(t *testing.T) {
	r := run(t, rp11Tree(t), Options{Bindings: landed(rp11), Runner: fake(ev("pass", rp11+"/inventory.users"), ev("pass", rp11))})
	expect(t, r, "RP11", "subtest-missing", "inventory.groups", "no subtest named inventory.groups")
	for _, v := range r.Violations {
		if strings.Contains(v.Where, "inventory.users") {
			t.Fatalf("covered dataset reported: %v", v)
		}
	}
}

func TestRP11SkippedDatasetSubtestFails(t *testing.T) {
	r := run(t, rp11Tree(t), Options{Bindings: landed(rp11), Runner: fake(ev("pass", rp11+"/inventory.users"), ev("skip", rp11+"/inventory.groups"), ev("pass", rp11))})
	expect(t, r, "RP11", "subtest-skip", "inventory.groups", "did not pass")
}

func TestRP11AllDatasetsCoveredPasses(t *testing.T) {
	r := run(t, rp11Tree(t), Options{Bindings: landed(rp11), Runner: fake(ev("pass", rp11+"/inventory.users"), ev("pass", rp11+"/inventory.groups"), ev("pass", rp11))})
	if len(r.Violations) != 0 {
		t.Fatalf("%v", r.Violations)
	}
}

func TestRP11LandedWithoutDatasetsFails(t *testing.T) {
	root := rp11Tree(t)
	if err := os.Remove(filepath.Join(root, "internal/directory/inventory/datasets.go")); err != nil {
		t.Fatal(err)
	}
	r := run(t, root, Options{Bindings: landed(rp11), Runner: fake(ev("pass", rp11))})
	expect(t, r, "RP11", "no-datasets", rp11, "prove nothing")
}

func TestRP11LandedWithNoTestFails(t *testing.T) {
	r := run(t, tree(t, nil), Options{Bindings: landed(rp11), Runner: fake()})
	expect(t, r, "RP11", "test-missing", rp11, "no package declares")
}
