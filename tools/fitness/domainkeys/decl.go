package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// tablekindDir is the package whose literals are the declarations; it is not scanned as a source of them.
const tablekindDir = "internal/platform/tablekind"

// Declaration is one tablekind.Table found in source, with where it was found.
type Declaration struct {
	tablekind.Table
	Pos string // file:line
}

// Source is what the scan learned from the Go tree: declarations, and the top-level test functions
// that the property check looks for.
type Source struct {
	Decls []Declaration
	Tests map[string]string // test function name → file
}

// ScanSource reads every .go file under root/internal and root/cmd. Declarations come from non-test
// files only: a table declared in a test is a fixture, not the product's. Nothing is built or run, so
// the job needs no compilable tree and cannot execute the code it checks.
func ScanSource(root, module string) (*Source, []Violation, error) {
	src := &Source{Tests: map[string]string{}}
	var vs []Violation
	importPath := module + "/" + tablekindDir
	for _, top := range []string{"internal", "cmd"} {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "node_modules" || rel == tablekindDir {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
			if strings.HasSuffix(p, "_test.go") {
				for _, decl := range f.Decls {
					if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
						src.Tests[fn.Name.Name] = rel
					}
				}
				return nil
			}
			ds, fv := scanFile(fset, f, rel, importPath)
			src.Decls = append(src.Decls, ds...)
			vs = append(vs, fv...)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	sort.Slice(src.Decls, func(i, j int) bool { return src.Decls[i].Name < src.Decls[j].Name })
	return src, vs, nil
}

// scanFile finds the tablekind.Declare calls of one file and reads each literal argument.
func scanFile(fset *token.FileSet, f *ast.File, rel, importPath string) ([]Declaration, []Violation) {
	local := ""
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == importPath {
			local = path.Base(p)
			if im.Name != nil {
				local = im.Name.Name
			}
		}
	}
	if local == "" || local == "_" || local == "." {
		return nil, nil
	}
	pos := func(n ast.Node) string { return fmt.Sprintf("%s:%d", rel, fset.Position(n.Pos()).Line) }
	isSel := func(e ast.Expr, name string) bool {
		s, ok := e.(*ast.SelectorExpr)
		if !ok || s.Sel.Name != name {
			return false
		}
		x, ok := s.X.(*ast.Ident)
		return ok && x.Name == local
	}
	var ds []Declaration
	var vs []Violation
	read := map[*ast.CompositeLit]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isSel(call.Fun, "Declare") {
			return true
		}
		if len(call.Args) != 1 {
			vs = append(vs, Violation{"REG", "declaration-literal", pos(call), "tablekind.Declare takes exactly one tablekind.Table literal"})
			return true
		}
		lit, ok := call.Args[0].(*ast.CompositeLit)
		if !ok || !isSel(lit.Type, "Table") {
			vs = append(vs, Violation{"REG", "declaration-literal", pos(call), "the argument of tablekind.Declare must be a tablekind.Table literal: the job reads source and cannot follow a variable or a call"})
			return true
		}
		read[lit] = true
		d, bad := readTable(lit, pos, isSel, local)
		vs = append(vs, bad...)
		if len(bad) == 0 {
			d.Pos = pos(lit)
			ds = append(ds, d)
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.CompositeLit); ok && lit.Type != nil && isSel(lit.Type, "Table") && !read[lit] {
			vs = append(vs, Violation{"REG", "declaration-site", pos(lit), "a tablekind.Table is built only as the argument of tablekind.Declare; anywhere else the job cannot see it"})
		}
		return true
	})
	return ds, vs
}

// readTable reads one literal: string literals, the Kind constants, true/false and []string literals.
func readTable(lit *ast.CompositeLit, pos func(ast.Node) string, isSel func(ast.Expr, string) bool, local string) (Declaration, []Violation) {
	var d Declaration
	var vs []Violation
	bad := func(n ast.Node, msg string) { vs = append(vs, Violation{"REG", "declaration-literal", pos(n), msg}) }
	str := func(e ast.Expr) (string, bool) {
		b, ok := e.(*ast.BasicLit)
		if !ok || b.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(b.Value)
		return s, err == nil
	}
	strs := func(e ast.Expr) ([]string, bool) {
		cl, ok := e.(*ast.CompositeLit)
		if !ok {
			return nil, false
		}
		var out []string
		for _, el := range cl.Elts {
			s, ok := str(el)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	seen := map[string]bool{}
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			bad(el, "name every field of a tablekind.Table literal (Name: …); a positional literal breaks silently when a field is added")
			continue
		}
		key, _ := kv.Key.(*ast.Ident)
		if key == nil {
			bad(kv, "unreadable field name")
			continue
		}
		seen[key.Name] = true
		switch key.Name {
		case "Name", "Entity":
			s, ok := str(kv.Value)
			if !ok {
				bad(kv.Value, key.Name+" must be a string literal")
			} else if key.Name == "Name" {
				d.Name = s
			} else {
				d.Entity = s
			}
		case "Kind":
			switch {
			case isSel(kv.Value, "Platform"):
				d.Kind = tablekind.Platform
			case isSel(kv.Value, "Tenant"):
				d.Kind = tablekind.Tenant
			case isSel(kv.Value, "Directory"):
				d.Kind = tablekind.Directory
			default:
				bad(kv.Value, "Kind must be "+local+".Platform, "+local+".Tenant or "+local+".Directory")
			}
		case "AppendOnly":
			id, ok := kv.Value.(*ast.Ident)
			if !ok || id.Name != "true" && id.Name != "false" {
				bad(kv.Value, "AppendOnly must be the literal true or false")
			} else {
				d.AppendOnly = id.Name == "true"
			}
		case "Sealed", "NameOK":
			l, ok := strs(kv.Value)
			if !ok {
				bad(kv.Value, key.Name+" must be a []string literal of string literals")
			} else if key.Name == "Sealed" {
				d.Sealed = l
			} else {
				d.NameOK = l
			}
		default:
			bad(kv, "unknown field "+key.Name)
		}
	}
	for _, req := range []string{"Name", "Entity", "Kind"} {
		if !seen[req] {
			bad(lit, "the declaration has no "+req)
		}
	}
	if len(vs) == 0 {
		if err := d.Table.Validate(); err != nil {
			bad(lit, err.Error())
		}
	}
	return d, vs
}
