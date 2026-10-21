// Package util holds what the safe-primitives go/analysis passes share: where a package sits in the
// repository, whether a file is a test or tier L, and a walk over a type for a named member.
package util

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
)

// PkgDir is the repository-relative directory of the package under analysis. Under `go vet` and the
// fitness runner it strips the module path; in analysistest layouts (no module) the import path is
// already the directory. A test package's `_test` suffix is dropped.
func PkgDir(pass *analysis.Pass) string {
	return TypesPkgDir(pass, pass.Pkg)
}

// TypesPkgDir is PkgDir for any package the analysis can see, such as the package that declares a type.
func TypesPkgDir(pass *analysis.Pass, pkg *types.Package) string {
	if pkg == nil {
		return ""
	}
	p := strings.TrimSuffix(pkg.Path(), "_test")
	if pass.Module != nil && pass.Module.Path != "" {
		if rel, ok := policy.ModuleRel(p, pass.Module.Path); ok {
			return rel
		}
	}
	return p
}

// IsTestFile reports a Go test file.
func IsTestFile(pass *analysis.Pass, f *ast.File) bool {
	return strings.HasSuffix(pass.Fset.Position(f.Pos()).Filename, "_test.go")
}

// HasHeader reports whether the file's first comment line starts with header.
func HasHeader(f *ast.File, header string) bool {
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, header) {
				return true
			}
		}
	}
	return false
}

// SkipFile reports files the passes do not judge: tests and tier L (lab and tools).
func SkipFile(pass *analysis.Pass, f *ast.File) bool {
	return IsTestFile(pass, f) || policy.IsToolTier(PkgDir(pass))
}

// NamedMatches reports whether t, looking through pointers, slices, arrays, maps, channels and struct
// fields, contains a named type for which match is true. Cycles are cut.
func NamedMatches(t types.Type, match func(*types.Named) bool) bool {
	return namedMatches(t, match, map[types.Type]bool{})
}

func namedMatches(t types.Type, match func(*types.Named) bool, seen map[types.Type]bool) bool {
	if t == nil || seen[t] {
		return false
	}
	seen[t] = true
	switch v := t.(type) {
	case *types.Named:
		if match(v) {
			return true
		}
		return namedMatches(v.Underlying(), match, seen)
	case *types.Alias:
		return namedMatches(types.Unalias(v), match, seen)
	case *types.Pointer:
		return namedMatches(v.Elem(), match, seen)
	case *types.Slice:
		return namedMatches(v.Elem(), match, seen)
	case *types.Array:
		return namedMatches(v.Elem(), match, seen)
	case *types.Map:
		return namedMatches(v.Key(), match, seen) || namedMatches(v.Elem(), match, seen)
	case *types.Chan:
		return namedMatches(v.Elem(), match, seen)
	case *types.Struct:
		for i := 0; i < v.NumFields(); i++ {
			if namedMatches(v.Field(i).Type(), match, seen) {
				return true
			}
		}
	}
	return false
}

// Callee resolves the function or method a call invokes, or nil (conversions, func values).
func Callee(pass *analysis.Pass, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	case *ast.IndexExpr: // generic instantiation
		if s, ok := f.X.(*ast.SelectorExpr); ok {
			id = s.Sel
		} else if i, ok := f.X.(*ast.Ident); ok {
			id = i
		}
	}
	if id == nil {
		return nil
	}
	fn, _ := pass.TypesInfo.Uses[id].(*types.Func)
	return fn
}
