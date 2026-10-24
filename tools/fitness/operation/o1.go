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
	"strconv"
	"strings"
)

// O1 (ADR-0005 rule 2): the step token cannot escape or be forged. This is the syntactic part of the
// check; it needs no build. It fails when, outside internal/platform/operation/step:
//
//   - a step.Step (or *step.Step) is the type of a struct field, a package-level variable, or the
//     element of a map, slice, array or channel;
//   - a step.Step or step.Clearance is built with a composite literal;
//   - step.TakeMinter is referenced anywhere except the package internal/platform/operation itself;
//   - a //go:linkname directive names operation/step.
//
// Closure capture and "passed to a function with no step.Step parameter" need type information; they
// are the go/analysis pass tools/analyzers/stepescape, run by o1types.go.

const (
	stepSuffix = "/internal/platform/operation/step"
	stepDir    = "internal/platform/operation/step"
	opDir      = "internal/platform/operation"
)

// CheckO1 walks every .go file under root (tests included) and returns the O1 violations.
func CheckO1(root string) ([]Violation, error) {
	modPath, err := modulePath(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	stepPath := modPath + stepSuffix
	var out []Violation
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, stepDir+"/") {
			return nil // the step package defines the token
		}
		vs, err := o1File(path, rel, stepPath)
		out = append(out, vs...)
		return err
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Pos < out[j].Pos })
	return out, err
}

func o1File(path, rel, stepPath string) ([]Violation, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	local := ""
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if p != stepPath {
			continue
		}
		local = "step"
		if im.Name != nil {
			local = im.Name.Name
		}
	}
	var out []Violation
	add := func(pos token.Pos, msg string) {
		out = append(out, Violation{Check: "O1", Pos: fmt.Sprintf("%s:%d", rel, fset.Position(pos).Line), Msg: msg})
	}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:linkname") && strings.Contains(c.Text, "operation/step") {
				add(c.Pos(), "a //go:linkname directive targets operation/step")
			}
		}
	}
	if local == "" || local == "_" || local == "." {
		return out, nil
	}
	sel := func(e ast.Expr, names ...string) bool {
		for {
			switch x := e.(type) {
			case *ast.StarExpr:
				e = x.X
				continue
			case *ast.ParenExpr:
				e = x.X
				continue
			case *ast.SelectorExpr:
				id, ok := x.X.(*ast.Ident)
				if !ok || id.Name != local {
					return false
				}
				for _, n := range names {
					if x.Sel.Name == n {
						return true
					}
				}
			}
			return false
		}
	}
	inOperation := filepath.ToSlash(filepath.Dir(rel)) == opDir
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.StructType:
			for _, fld := range x.Fields.List {
				if sel(fld.Type, "Step") {
					add(fld.Pos(), "a step.Step is stored in a struct field; it dies with Apply and must not be kept")
				}
			}
		case *ast.MapType:
			if sel(x.Key, "Step") || sel(x.Value, "Step") {
				add(x.Pos(), "a step.Step is the element of a map")
			}
		case *ast.ArrayType:
			if sel(x.Elt, "Step") {
				add(x.Pos(), "a step.Step is the element of a slice or array")
			}
		case *ast.ChanType:
			if sel(x.Value, "Step") {
				add(x.Pos(), "a step.Step is sent over a channel")
			}
		case *ast.CompositeLit:
			if x.Type != nil && sel(x.Type, "Step", "Clearance") {
				add(x.Pos(), "a step.Step or step.Clearance is constructed outside operation/step")
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == local && x.Sel.Name == "TakeMinter" && !inOperation {
				add(x.Pos(), "step.TakeMinter is referenced outside internal/platform/operation")
			}
			if id, ok := x.X.(*ast.Ident); ok && id.Name == local && x.Sel.Name == "Minter" && !inOperation {
				add(x.Pos(), "step.Minter is referenced outside internal/platform/operation")
			}
		}
		return true
	})
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, sp := range gd.Specs {
			if vs := sp.(*ast.ValueSpec); vs.Type != nil && sel(vs.Type, "Step") {
				add(vs.Pos(), "a step.Step is held in a package-level variable")
			}
		}
	}
	return out, nil
}
