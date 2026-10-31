package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/tools/fitness/internal/boundtest"
)

// binding ties an RP check to the Go test that proves the behaviour. The build ticket that writes
// the test flips Landed and sets Pkg in this table (a review-visible edit). A landed binding fails
// when its test is missing, failed or skipped, so deleting or skipping the test cannot weaken the
// check. A binding that is not landed is listed as pending on every run, never as a pass, and fails
// if its test is already declared (someone landed it without flipping the flag).
type binding struct {
	Check string
	What  string
	Name  string
	// Pkg is the package directory holding the test, "./<dir>". Empty for PerDataset, where the
	// packages are found by declaration (each dataset owner tests its own datasets).
	Pkg string
	// PerDataset makes the job require one passing subtest per report.Dataset literal in the tree,
	// named by the dataset ID.
	PerDataset bool
	Landed     bool
	Owner      string
}

var defaultBindings = []binding{
	{Check: "RP4", Name: "Test_expired_run_is_not_served", Pkg: "./internal/modules/reports/run", Landed: true, Owner: "B4",
		What: "an expired run is not served; the row trigger refuses an insert or update once the run is succeeded, and the state trigger refuses every edge not in reports contract §6.2 (ADR-0010 rules 2 and 5)"},
	{Check: "RP5", Name: "Test_export_digest_equals_run_digest", Pkg: "./internal/modules/reports/export", Owner: "B9",
		What: "an export's digest equals the stored run's digest (ADR-0010 rule 4, AC-50)"},
	{Check: "RP6", Name: "Test_compiled_scope_matches_read_oracle", Pkg: "./internal/directory/inventory", Landed: true, Owner: "B2",
		What: "the compiled scope equals the authz.Evaluator.AuthorizeRead oracle over trees written by the inventory writer with OU moves (FR-07, LF-39)"},
	{Check: "RP8", Name: "Test_derived_columns_match_reference", Pkg: "./internal/directory/inventory", Landed: true, Owner: "B3",
		What: "every derived column matches its reference implementation (FR-09, AC-49)"},
	{Check: "RP9", Name: "Test_run_read_bound_to_runner_and_scope", Pkg: "./internal/modules/reports/run", Landed: true, Owner: "B4",
		What: "a run read is bound to the runner and the scope that produced it (reports contract §6.6; FR-07, FR-30)"},
	{Check: "RP10", Name: "Test_delivery_link_authorised_by_delivery_row", Pkg: "./internal/modules/reports/schedule", Owner: "B11",
		What: "a delivery link is authorised by its Delivery row (reports contract §7.2; FR-24, AC-47)"},
	{Check: "RP11", Name: "Test_dataset_reveals_nothing_outside_scope", PerDataset: true, Landed: true, Owner: "B3, B6",
		What: "a dataset reveals no name, GUID or aggregate from outside the read scope, once per registered dataset (reports contract §3.3; LF-39, FR-07)"},
}

// runBindings runs the landed bindings and lists the others as pending.
func runBindings(ctx context.Context, root string, bs []binding, datasets []string, run boundtest.Runner) ([]Violation, []string, error) {
	declared, err := declaredTests(root)
	if err != nil {
		return nil, nil, err
	}
	var vs []Violation
	var pending []string
	var tests []boundtest.Test
	for _, b := range bs {
		pkgs := declared[b.Name]
		if !b.Landed {
			if len(pkgs) > 0 {
				vs = append(vs, Violation{b.Check, "binding-not-landed", join(pkgs) + " " + b.Name,
					"the bound test is declared but its binding is not marked Landed in tools/fitness/reports/bindings.go: flip it so the job runs it"})
			}
			pending = append(pending, b.Check+" "+b.Name+" (row "+b.Owner+" has not landed it)")
			continue
		}
		t := boundtest.Test{Check: b.Check, What: b.What, Name: b.Name}
		if b.PerDataset {
			if len(pkgs) == 0 {
				vs = append(vs, Violation{b.Check, "test-missing", b.Name, "no package declares the bound test. " + b.What})
				continue
			}
			if len(datasets) == 0 {
				vs = append(vs, Violation{b.Check, "no-datasets", b.Name, "marked Landed but the tree has no report.Dataset literal with a constant ID, so the per-dataset subtests prove nothing"})
				continue
			}
			t.Pkgs = pkgs
			t.Subtests = datasets
		} else {
			t.Pkgs = []string{b.Pkg}
		}
		tests = append(tests, t)
	}
	if len(tests) == 0 {
		return vs, pending, nil
	}
	fails, err := boundtest.Run(ctx, root, tests, run)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range fails {
		vs = append(vs, Violation{f.Check, f.Kind, f.Where, f.Msg})
	}
	return vs, pending, nil
}

// declaredTests maps each top-level Test function name to the "./dir" packages declaring it.
func declaredTests(root string) (map[string][]string, error) {
	out := map[string][]string{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor", "web", "factory", "knowledge", ".activeDIQ-worktrees":
				if p != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		dir := "./" + relSlash(root, filepath.Dir(p))
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && strings.HasPrefix(fd.Name.Name, "Test") {
				if !slices.Contains(out[fd.Name.Name], dir) {
					out[fd.Name.Name] = append(out[fd.Name.Name], dir)
				}
			}
		}
		return nil
	})
	for _, v := range out {
		sort.Strings(v)
	}
	return out, err
}
