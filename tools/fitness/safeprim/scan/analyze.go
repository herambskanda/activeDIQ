package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"

	"github.com/skenzeriq/activediq/tools/analyzers"
)

// Analyze runs the type-aware FF-SP2 passes (dnstring, sqlconst, secretjson, tmplconst, constdisp) over every
// package under root, tests included, and returns their diagnostics as findings. It needs the module
// to type-check: `make ci` builds before it runs the fitness jobs. A tree with no Go packages has
// nothing to analyse.
func Analyze(root string) ([]Finding, error) {
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return nil, nil
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedTypes |
			packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedModule,
		Dir:   root,
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}
	// ./... skips _x, .x and testdata directories, yet product code can import them and they then
	// ship. Analyse every package of the main module reachable in the import graph, not just the roots.
	var use []*packages.Package
	compiled := map[string]bool{}
	seenPkg := map[string]bool{}
	var firstErr error
	packages.Visit(pkgs, func(p *packages.Package) bool {
		return p.Module != nil && p.Module.Main
	}, func(p *packages.Package) {
		if p.Module == nil || !p.Module.Main || seenPkg[p.ID] {
			return
		}
		seenPkg[p.ID] = true
		for _, f := range p.CompiledGoFiles {
			compiled[filepath.Clean(f)] = true
		}
		if strings.HasSuffix(p.ID, ".test") {
			return // the generated test main
		}
		if len(p.Errors) > 0 && firstErr == nil {
			firstErr = fmt.Errorf("package %s does not type-check (run go build ./... first): %v", p.PkgPath, p.Errors[0])
		}
		use = append(use, p)
	})
	if firstErr != nil {
		return nil, firstErr
	}
	if len(use) == 0 {
		return nil, nil
	}
	g, err := checker.Analyze(analyzers.All(), use, nil)
	if err != nil {
		return nil, err
	}
	var out []Finding
	seen := map[string]bool{}
	for _, act := range g.Roots {
		if act.Err != nil {
			return nil, fmt.Errorf("%s on %s: %w", act.Analyzer.Name, act.Package.PkgPath, act.Err)
		}
		for _, d := range act.Diagnostics {
			pos := act.Package.Fset.Position(d.Pos)
			rel, err := filepath.Rel(root, pos.Filename)
			if err != nil {
				rel = pos.Filename
			}
			msg := d.Message
			// Messages read "FF-SP2 [rule]: text"; keep the text, the rule is the category.
			if i := strings.Index(msg, "]: "); i >= 0 && strings.HasPrefix(msg, "FF-SP2 [") {
				msg = msg[i+3:]
			}
			f := Finding{FF: "FF-SP2", Rule: d.Category, File: filepath.ToSlash(rel), Line: pos.Line, Msg: msg}
			if k := f.String(); !seen[k] {
				seen[k] = true
				out = append(out, f)
			}
		}
	}
	missed, err := unanalysed(root, compiled)
	if err != nil {
		return nil, err
	}
	return append(out, missed...), nil
}

// unanalysed is the fail-closed half: every .go file under the module that no package load compiled
// was never type-checked, so no analyzer saw it (a directory excluded by build constraints on every
// run, a stray file, a package nothing imports). Nested modules and the analyzer fixtures under
// tools/ are exempt.
func unanalysed(root string, compiled map[string]bool) ([]Finding, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if r, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = r // compare equal to the paths go list reports
	}
	var out []Finding
	err = filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(absRoot, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if skipDir(absRoot, rel, d.Name()) && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "testdata") {
				return fs.SkipDir
			}
			if _, serr := os.Stat(filepath.Join(p, "go.mod")); serr == nil {
				return fs.SkipDir // a nested module is not this module's code
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || compiled[filepath.Clean(p)] {
			return nil
		}
		out = append(out, Finding{FF: "FF-SP2", Rule: "build-constrained-unanalysed", File: rel, Line: 1,
			Msg: "no package load compiled this Go file, so no FF-SP2 analyzer type-checked it: excluded by a build constraint on every run, or in a directory nothing imports. Make it analysable or delete it"})
		return nil
	})
	return out, err
}
