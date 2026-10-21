package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mod = "example.test/m"

// fixtureDAG is a small block shaped like ADR-0005 rule 13, including an "(anything operation may
// import)" row. The tests that edit the block change this text, never the code.
const fixtureDAG = `# package -> listed packages it may import
tenant          -> (none)
store           -> tenant
audit           -> store, tenant
operation       -> audit, store, tenant
authz           -> audit, store, tenant
authz/actions   -> authz, operation, (anything operation may import)
`

func adrText(block string) string {
	return "---\nstatus: ratified\n---\n# ADR\n\nProse.\n\n```dag\n" + block + "```\n\nMore prose.\n"
}

// tree writes files (path -> content) under a temp root with a go.mod and the ADR.
func tree(t *testing.T, block string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	all := map[string]string{"go.mod": "module " + mod + "\n\ngo 1.27.0\n", DefaultADR: adrText(block)}
	for p, c := range files {
		all[p] = c
	}
	for p, c := range all {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// pkg renders a Go file in internal/platform/<name> importing the given platform packages.
func pkg(name string, imports ...string) (string, string) {
	var b strings.Builder
	b.WriteString("package p\n\nimport (\n")
	for _, i := range imports {
		b.WriteString("\t_ \"" + mod + "/internal/platform/" + i + "\"\n")
	}
	b.WriteString(")\n")
	return "internal/platform/" + name + "/p.go", b.String()
}

func files(spec map[string][]string) map[string]string {
	out := map[string]string{}
	for name, imports := range spec {
		p, c := pkg(name, imports...)
		out[p] = c
	}
	return out
}

func run(t *testing.T, block string, f map[string]string) *Report {
	t.Helper()
	rep, err := Check(tree(t, block, f), DefaultADR)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func wantViolation(t *testing.T, rep *Report, parts ...string) {
	t.Helper()
	for _, v := range rep.Violations {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(v.String(), p)
		}
		if ok {
			return
		}
	}
	t.Fatalf("want a violation containing %q, got %v", parts, rep.Violations)
}

func wantClean(t *testing.T, rep *Report) {
	t.Helper()
	if len(rep.Violations) != 0 {
		t.Fatalf("want no violations, got %v", rep.Violations)
	}
}

func TestAllowedEdgesPass(t *testing.T) {
	rep := run(t, fixtureDAG, files(map[string][]string{
		"tenant": nil, "store": {"tenant"}, "audit": {"store", "tenant"}, "operation": {"audit", "store"},
		"authz/actions": {"authz", "operation", "audit", "tenant"},
	}))
	wantClean(t, rep)
	if rep.Edges != 9 {
		t.Fatalf("want 9 checked edges, got %d", rep.Edges)
	}
}

func TestForbiddenEdgesFailNamingImporterImportedAndRule(t *testing.T) {
	for _, tc := range []struct{ importer, imported string }{{"store", "audit"}, {"tenant", "store"}} {
		rep := run(t, fixtureDAG, files(map[string][]string{"tenant": nil, "store": nil, "audit": nil, tc.importer: {tc.imported}}))
		wantViolation(t, rep, "internal/platform/"+tc.importer+"/p.go:4", "O9", "rule 13", tc.importer+" imports "+tc.imported, tc.importer+" -> "+tc.imported)
	}
}

func TestTestFilesCount(t *testing.T) {
	f := files(map[string][]string{"tenant": nil, "store": nil})
	f["internal/platform/store/p_test.go"] = "package p_test\n\nimport _ \"" + mod + "/internal/platform/audit\"\n"
	rep := run(t, fixtureDAG, f)
	wantViolation(t, rep, "internal/platform/store/p_test.go:3", "store imports audit (test file)")
}

func TestOperationMayImportRows(t *testing.T) {
	// operation may import tenant (and audit, store); authz/actions importing any of them passes.
	rep := run(t, fixtureDAG, files(map[string][]string{"authz/actions": {"tenant", "store", "audit", "authz", "operation"}}))
	wantClean(t, rep)
	// authz is not importable by... authz/actions importing a package operation does not import fails.
	block := fixtureDAG + "extra -> (none)\n"
	rep = run(t, block, files(map[string][]string{"authz/actions": {"extra"}, "extra": nil}))
	wantViolation(t, rep, "authz/actions imports extra", "authz/actions -> extra")
	// A sibling actions package is not something operation imports.
	block = fixtureDAG + "authn/actions -> operation, (anything operation may import)\n"
	rep = run(t, block, files(map[string][]string{"authz/actions": {"authn/actions"}, "authn/actions": nil}))
	wantViolation(t, rep, "authz/actions imports authn/actions")
}

func TestMacroFollowsEditsToTheReferencedRow(t *testing.T) {
	f := files(map[string][]string{"authz/actions": {"tenant"}})
	wantClean(t, run(t, fixtureDAG, f))
	edited := strings.Replace(fixtureDAG, "operation       -> audit, store, tenant", "operation       -> audit, store", 1)
	wantViolation(t, run(t, edited, f), "authz/actions imports tenant")
}

func TestCheckFollowsTheADREditWithNoCodeChange(t *testing.T) {
	f := files(map[string][]string{"tenant": nil, "store": {"tenant"}})
	wantClean(t, run(t, fixtureDAG, f))
	edited := strings.Replace(fixtureDAG, "store           -> tenant", "store           -> (none)", 1)
	wantViolation(t, run(t, edited, f), "store imports tenant")
	// And the other direction: an edge forbidden before the edit is allowed after it.
	g := files(map[string][]string{"tenant": nil, "store": nil, "audit": {"operation"}, "operation": nil})
	wantViolation(t, run(t, fixtureDAG, g), "audit imports operation")
	edited = strings.Replace(fixtureDAG, "audit           -> store, tenant", "audit           -> operation, store, tenant", 1)
	wantClean(t, run(t, edited, g))
}

func TestPendingPackagesAreReportedNotPassed(t *testing.T) {
	rep := run(t, fixtureDAG, files(map[string][]string{"tenant": nil, "store": {"tenant"}}))
	state := map[string]bool{}
	for _, p := range rep.Pkgs {
		state[p.Name] = p.Existing
	}
	if !state["tenant"] || !state["store"] || state["audit"] || state["operation"] || state["authz/actions"] {
		t.Fatalf("existing/pending wrong: %v", state)
	}
	if len(rep.Pkgs) != 6 {
		t.Fatalf("want 6 listed packages, got %d", len(rep.Pkgs))
	}
}

func TestZeroResolvedWhereTheTreeHasSomeFails(t *testing.T) {
	// The packages exist, but not under internal/platform: the mapping would find nothing.
	f := map[string]string{}
	for _, n := range []string{"tenant", "store"} {
		p, c := pkg(n)
		f[strings.Replace(p, "internal/platform/", "internal/kernel/platform/", 1)] = c
	}
	wantViolation(t, run(t, fixtureDAG, f), "self-test", "none of the 6 listed packages resolved", "internal/kernel/platform/store")
	// An empty tree has none of them anywhere: everything is pending and nothing fails.
	rep := run(t, fixtureDAG, nil)
	wantClean(t, rep)
	for _, p := range rep.Pkgs {
		if p.Existing {
			t.Fatalf("%s should be pending", p.Name)
		}
	}
}

func TestUnlistedAndSelfImportsAreNotEdges(t *testing.T) {
	f := files(map[string][]string{"store": {"tenant"}})
	f["internal/platform/store/exempt/e.go"] = "package e\n\nimport _ \"" + mod + "/internal/platform/audit\"\n"
	f["internal/platform/store/q.go"] = "package p\n\nimport (\n\t_ \"" + mod + "/internal/platform/store\"\n\t_ \"fmt\"\n\t_ \"github.com/x/y\"\n\t_ \"" + mod + "/internal/platform/keys\"\n)\n"
	wantClean(t, run(t, fixtureDAG, f))
}

func TestBadBlocksAreErrors(t *testing.T) {
	for name, block := range map[string]string{
		"empty":           "",
		"no arrow":        "tenant (none)\n",
		"dangling import": "tenant -> ghost\n",
		"dangling macro":  "tenant -> (anything ghost may import)\n",
		"duplicate row":   "tenant -> (none)\ntenant -> (none)\n",
		"no imports":      "tenant ->\n",
		"mixed none":      "store -> (none), tenant\ntenant -> (none)\n",
		"macro of macro":  "a -> (none)\nb -> (anything a may import)\nc -> (anything b may import)\n",
		"bad name":        "Tenant -> (none)\n",
	} {
		if _, err := Check(tree(t, block, nil), DefaultADR); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// No block at all, two blocks, and an unclosed block.
	root := tree(t, "", nil)
	for name, text := range map[string]string{
		"none":     "# ADR\nno block\n",
		"two":      adrText("tenant -> (none)\n") + adrText("tenant -> (none)\n"),
		"unclosed": "```dag\ntenant -> (none)\n",
	} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(DefaultADR)), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(root, DefaultADR); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := Check(root, "knowledge/missing.md"); err == nil {
		t.Error("missing ADR: want an error")
	}
}

// TestRealADRBlock pins the shape of the block in the repository's ADR-0005, so a malformed edit of
// it fails here before it fails the job.
func TestRealADRBlock(t *testing.T) {
	d, err := ParseDAGFile(filepath.Join("..", "..", "..", filepath.FromSlash(DefaultADR)))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Order) < 20 {
		t.Fatalf("want at least the 20 packages of rule 13, got %d: %v", len(d.Order), d.Order)
	}
	if !d.Allow["authz/actions"]["jobs"] || d.Allow["authz/actions"]["audit/chain"] || d.Allow["store"]["audit"] || d.Allow["tenant"]["store"] {
		t.Fatalf("the real block resolves unexpectedly: authz/actions=%v", d.allowedList("authz/actions"))
	}
}
