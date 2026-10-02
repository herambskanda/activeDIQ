package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"

	"github.com/skenzeriq/activediq/tools/analyzers"
)

// Analyze runs the type-aware FF-SP2 passes (dnstring, sqlconst, secretjson, tmplconst) over every
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
	var use []*packages.Package
	for _, p := range pkgs {
		if strings.HasSuffix(p.ID, ".test") {
			continue // the generated test main
		}
		if len(p.Errors) > 0 {
			return nil, fmt.Errorf("package %s does not type-check (run go build ./... first): %v", p.PkgPath, p.Errors[0])
		}
		use = append(use, p)
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
	return out, nil
}
