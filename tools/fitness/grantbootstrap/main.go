// Command grantbootstrap is the T-0808 fitness function: rbac.Grants.GrantBootstrap skips the
// "grantor must hold every privilege" check (DM-36.I1) for a system principal, so it is a
// privilege-check bypass primitive. It may be referenced only by the install-time CLI path
// (internal/compose/server/localaccount.go), by its own definition in internal/platform/rbac/grants.go
// and by test files. Any other reference to the name (a call, a method value, an interface method
// that it satisfies, a string for reflection) fails CI. The runtime half is the principal allow-list
// inside GrantBootstrap itself (rbac.BootstrapPrincipal, unit-tested).
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const name = "GrantBootstrap"

// callerFile is the only non-test file that may use GrantBootstrap; definitionFile may declare it.
const (
	callerFile     = "internal/compose/server/localaccount.go"
	definitionFile = "internal/platform/rbac/grants.go"
	selfDir        = "tools/fitness/grantbootstrap/" // this checker names the symbol it hunts
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	v, err := Check(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-grantbootstrap:", err)
		os.Exit(2)
	}
	for _, s := range v {
		fmt.Fprintln(os.Stderr, s)
	}
	if len(v) > 0 {
		fmt.Fprintf(os.Stderr, "fitness-grantbootstrap: FAIL: %d reference(s) to %s outside %s; it bypasses the grantor-holds-the-privilege check (DM-36.I1), use Grants.Grant\n", len(v), name, callerFile)
		os.Exit(1)
	}
	fmt.Println("fitness-grantbootstrap: ok")
}

// Check parses every .go file under root (vendor, node_modules and dot directories skipped) and
// returns one "file:line:col: message" per reference to GrantBootstrap outside the allow-list, sorted.
func Check(root string) ([]string, error) {
	var out []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			n := d.Name()
			if path != root && (strings.HasPrefix(n, ".") || n == "vendor" || n == "node_modules" || n == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == callerFile || strings.HasPrefix(rel, selfDir) {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		decl := map[*ast.Ident]bool{}
		if rel == definitionFile {
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name && fd.Recv != nil {
					decl[fd.Name] = true
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if x.Name == name && !decl[x] {
					out = append(out, pos(fset, rel, x.Pos(), "reference to "+name))
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING && strings.Contains(x.Value, name) {
					out = append(out, pos(fset, rel, x.Pos(), "string mentions "+name+" (reflection or code generation)"))
				}
			}
			return true
		})
		return nil
	})
	sort.Strings(out)
	return out, err
}

func pos(fset *token.FileSet, rel string, p token.Pos, msg string) string {
	pp := fset.Position(p)
	return fmt.Sprintf("%s:%d:%d: %s", rel, pp.Line, pp.Column, msg)
}
