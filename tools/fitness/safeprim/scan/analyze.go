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
	absRoot, err := resolvedRoot(root)
	if err != nil {
		return nil, err
	}
	// In scope is the main module and any module a local-path replace points at inside the repository:
	// both ship. The module cache and GOROOT are outside the root and stay out.
	inRepo := func(p *packages.Package) bool {
		return p.Module != nil && moduleDirInside(absRoot, p.Module)
	}
	var use []*packages.Package
	nestedModules := map[string]bool{} // directories of in-scope modules other than the root
	compiled := map[string]bool{}
	seenPkg := map[string]bool{}
	var firstErr error
	packages.Visit(pkgs, inRepo, func(p *packages.Package) {
		if !inRepo(p) || seenPkg[p.ID] {
			return
		}
		seenPkg[p.ID] = true
		if d := moduleDir(p.Module); !p.Module.Main {
			if r, err := filepath.EvalSymlinks(d); err == nil {
				d = r
			}
			nestedModules[d] = true
		}
		for _, f := range p.CompiledGoFiles {
			compiled[filepath.Clean(f)] = true
		}
		if isGeneratedTestMain(absRoot, p) {
			return
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
	missed, err := unanalysed(absRoot, nestedModules, compiled)
	if err != nil {
		return nil, err
	}
	return append(out, missed...), nil
}

// unanalysed is the fail-closed half: every .go file under the module that no package load compiled
// was never type-checked, so no analyzer saw it (a directory excluded by build constraints on every
// run, a stray file, a package nothing imports). Nested modules and the analyzer fixtures under
// tools/ are exempt. A nested module is exempt only while no package of it is in the loaded graph;
// one that product code imports (an in-repo replace) is shipped code and is walked like the rest.
func unanalysed(absRoot string, nestedModules, compiled map[string]bool) ([]Finding, error) {
	var out []Finding
	err := filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, err error) error {
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
			if _, serr := os.Stat(filepath.Join(p, "go.mod")); serr == nil && !nestedModules[p] {
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

// resolvedRoot returns root as an absolute, symlink-free path, comparable to the paths go list reports.
func resolvedRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	return abs, nil
}

// moduleDir is the directory a module's source is read from: the replacement's when replaced.
func moduleDir(m *packages.Module) string {
	if m.Replace != nil && m.Replace.Dir != "" {
		return filepath.Clean(m.Replace.Dir)
	}
	return filepath.Clean(m.Dir)
}

// moduleDirInside reports whether the module's source lives under absRoot (the main module itself,
// or a local-path replace). The module cache is elsewhere.
func moduleDirInside(absRoot string, m *packages.Module) bool {
	if m.Main {
		return true
	}
	d := moduleDir(m)
	if d == "." || d == "" {
		return false
	}
	if r, err := filepath.EvalSymlinks(d); err == nil {
		d = r
	}
	rel, err := filepath.Rel(absRoot, d)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// isGeneratedTestMain reports the synthetic "pkg.test" main go list builds for a package's tests: its
// source sits in the build cache, not under the repository. (A real package may itself be named
// "x.test", so the ID suffix alone is no test.)
func isGeneratedTestMain(absRoot string, p *packages.Package) bool {
	if !strings.HasSuffix(p.ID, ".test") || len(p.CompiledGoFiles) == 0 {
		return false
	}
	for _, f := range p.CompiledGoFiles {
		if rel, err := filepath.Rel(absRoot, f); err == nil && !strings.HasPrefix(rel, "..") {
			return false
		}
	}
	return true
}
