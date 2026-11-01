package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, src string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCheck(t *testing.T) {
	root := t.TempDir()
	write(t, root, definitionFile, "package rbac\ntype Grants struct{}\n// GrantBootstrap doc\nfunc (g *Grants) GrantBootstrap() {}\n")
	write(t, root, callerFile, "package server\nfunc f(g interface{ GrantBootstrap() }) { g.GrantBootstrap() }\n")
	write(t, root, "internal/x/x_test.go", "package x\nfunc f(g interface{ GrantBootstrap() }) { g.GrantBootstrap() }\n")
	got, err := Check(root)
	if err != nil || len(got) != 0 {
		t.Fatalf("allowed tree: got %v, %v; want clean", got, err)
	}

	// AC1: a new reference outside localaccount.go fails.
	write(t, root, "internal/modules/jobs/run.go", "package jobs\nfunc f(g interface{ GrantBootstrap() }) { g.GrantBootstrap() }\n")
	write(t, root, "internal/modules/jobs/refl.go", "package jobs\nvar s = \"GrantBootstrap\"\n")
	// A call inside the definition file other than the declaration is also a violation.
	write(t, root, definitionFile, "package rbac\ntype Grants struct{}\nfunc (g *Grants) GrantBootstrap() {}\nfunc (g *Grants) Other() { g.GrantBootstrap() }\n")
	got, err = Check(root)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]bool{}
	for _, g := range got {
		files[strings.SplitN(g, ":", 2)[0]] = true
	}
	for _, w := range []string{"internal/modules/jobs/refl.go", "internal/modules/jobs/run.go", definitionFile} {
		if !files[w] {
			t.Errorf("no violation reported for %s; got %v", w, got)
		}
	}
	if len(files) != 3 {
		t.Errorf("violations in %d files, want 3: %v", len(files), got)
	}
}

// The real tree must be clean: the same check CI runs.
func TestRepoClean(t *testing.T) {
	got, err := Check("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("GrantBootstrap referenced outside the allow-list: %v", got)
	}
}
