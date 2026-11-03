package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"

	"github.com/skenzeriq/activediq/tools/analyzers/connwrite"
	"github.com/skenzeriq/activediq/tools/analyzers/stepescape"
	"github.com/skenzeriq/activediq/tools/fitness/safeprim/scan"
)

// CheckTyped runs the type-aware halves of O1 and O2: closure capture of a step.Step and a step.Step
// passed to a function with no step.Step parameter (analyzer tools/analyzers/stepescape, O1), and
// the generated connector client's Plan/Apply exposed or used outside the Clearance-taking path
// (analyzer tools/analyzers/connwrite, O2). It type-checks the
// main module, tests included, once per ship target and once per lab tag set, so platform-specific
// files get the same gate. It needs the module to build; a package that does not type-check is an
// error (exit 2), never a pass. A tree with no go.mod has nothing to check.
func CheckTyped(root string) ([]Violation, error) {
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return nil, nil
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if r, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = r
	}
	targets := append(append([]scan.Target(nil), scan.Targets...),
		scan.Target{GOOS: "linux", GOARCH: "amd64", Tags: scan.TestTags}, scan.Target{GOOS: "windows", GOARCH: "amd64", Tags: scan.TestTags})
	seen := map[string]bool{}
	var out []Violation
	for _, t := range targets {
		cfg := &packages.Config{
			Env: append(os.Environ(), "GOOS="+t.GOOS, "GOARCH="+t.GOARCH, "CGO_ENABLED=0"),
			Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedTypes |
				packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedModule,
			Dir:   absRoot,
			Tests: true,
		}
		if len(t.Tags) > 0 {
			cfg.BuildFlags = []string{"-tags=" + strings.Join(t.Tags, ",")}
		}
		pkgs, err := packages.Load(cfg, "./...")
		if err != nil {
			return nil, fmt.Errorf("typed O1/O2: loading packages for GOOS=%s: %w", t.GOOS, err)
		}
		var use []*packages.Package
		var loadErr error
		packages.Visit(pkgs, func(p *packages.Package) bool { return p.Module != nil && p.Module.Main }, func(p *packages.Package) {
			if p.Module == nil || !p.Module.Main || (strings.HasSuffix(p.ID, ".test") && len(p.CompiledGoFiles) == 0) {
				return
			}
			if len(p.Errors) > 0 && loadErr == nil {
				loadErr = fmt.Errorf("typed O1/O2: package %s does not type-check (build first): %v", p.PkgPath, p.Errors[0])
			}
			use = append(use, p)
		})
		if loadErr != nil {
			return nil, loadErr
		}
		if len(use) == 0 {
			continue
		}
		g, err := checker.Analyze([]*analysis.Analyzer{stepescape.Analyzer, connwrite.Analyzer}, use, nil)
		if err != nil {
			return nil, err
		}
		for _, act := range g.Roots {
			if act.Err != nil {
				return nil, fmt.Errorf("typed O1/O2: %s on %s: %w", act.Analyzer.Name, act.Package.PkgPath, act.Err)
			}
			for _, d := range act.Diagnostics {
				pos := act.Package.Fset.Position(d.Pos)
				rel, err := filepath.Rel(absRoot, pos.Filename)
				if err != nil {
					rel = pos.Filename
				}
				v := Violation{Check: d.Category, Pos: fmt.Sprintf("%s:%d", filepath.ToSlash(rel), pos.Line), Msg: d.Message}
				if k := v.Pos + v.Msg; !seen[k] {
					seen[k] = true
					out = append(out, v)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pos < out[j].Pos })
	return out, nil
}
