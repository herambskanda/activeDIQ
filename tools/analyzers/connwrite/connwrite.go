// Package connwrite is the type-aware half of fitness-operation O2 (ADR-0005 rule 2): the generated
// connector-contract client's write RPCs (Plan, Apply) are reachable only through a function of
// internal/directory/client that takes a step.Clearance. The syntactic half (tools/fitness/operation/o2.go)
// matches the identifiers ConnectorClient and NewConnectorClient; this half cannot be laundered by an
// alias, a named interface that embeds the client, a struct that embeds it, or a field, parameter,
// result or inferred variable of such a type, because it judges method sets, not spellings:
//
//   - a type "exposes the write RPCs" when its method set (or, for a pointer, slice, array, map,
//     channel, function signature or type parameter, that of what it holds) contains a Plan or Apply
//     with the signature of the generated client's: variadic, taking a *PlanRequest or *ApplyRequest
//     of the connector-contract package. Narrow read-only subsets of the client do not;
//   - outside internal/directory/client (and the generated package, and the test files of the
//     connector and composition roots that drive a fake connector) no declaration and no type
//     expression may have such a type;
//   - inside internal/directory/client an exported type, an exported field and an exported
//     package-level variable may not have such a type (the package's own unexported plumbing may);
//   - a selector that resolves to the generated Plan or Apply (a call, a method value, a method
//     expression, through any interface or embedding) is allowed only in internal/directory/client,
//     in a function with a step.Clearance parameter, or in that package's test files.
package connwrite

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const Name = "connwrite"

const (
	clientDir    = "internal/directory/client"
	protoDir     = "internal/proto"
	connectorDir = "internal/connector"
	composeConn  = "internal/compose/connector"
	composeSrv   = "internal/compose/server"
	connectorPkg = "internal/proto/activediq/connector/v1"
	stepPkg      = "internal/platform/operation/step"
)

var Analyzer = &analysis.Analyzer{
	Name: Name,
	Doc:  "fitness-operation O2 (ADR-0005 rule 2): the generated connector client's Plan/Apply are not exposed or called outside internal/directory/client's Clearance-taking path",
	Run:  run,
}

// rel maps a package path to its path below the module root ("" when it is outside the module). It is
// computed against the module path, never by searching for "/internal/": a nested internal directory
// (cmd/server/internal/proto/...) is idiomatic Go and must not be mistaken for the top-level one.
func rel(mod, path string) string {
	if mod == "" || !strings.HasPrefix(path, mod+"/") {
		return ""
	}
	return strings.TrimPrefix(path, mod+"/")
}

func under(r, dir string) bool { return r == dir || strings.HasPrefix(r, dir+"/") }

// pathIs reports whether p is the package at the module-root-relative path want.
func pathIs(mod string, p *types.Package, want string) bool {
	return p != nil && rel(mod, p.Path()) == want
}

// isGenWrite reports the signature of the generated client's Plan or Apply.
func isGenWrite(mod, name string, sig *types.Signature) bool {
	want := map[string]string{"Plan": "PlanRequest", "Apply": "ApplyRequest"}[name]
	if want == "" || !sig.Variadic() || sig.Params().Len() != 3 {
		return false
	}
	p, ok := types.Unalias(sig.Params().At(1).Type()).(*types.Pointer)
	if !ok {
		return false
	}
	n, ok := types.Unalias(p.Elem()).(*types.Named)
	return ok && n.Obj().Name() == want && pathIs(mod, n.Obj().Pkg(), connectorPkg)
}

type exposer struct {
	mod  string
	memo map[types.Type]bool
}

// exposes reports whether t carries the generated client's write RPCs.
func (e *exposer) exposes(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if v, ok := e.memo[t]; ok {
		return v
	}
	e.memo[t] = false // cycles end here
	v := e.compute(t)
	e.memo[t] = v
	return v
}

func (e *exposer) compute(t types.Type) bool {
	switch x := t.(type) {
	case *types.Pointer:
		return e.exposes(x.Elem()) || e.hasWriteMethods(t)
	case *types.Slice:
		return e.exposes(x.Elem())
	case *types.Array:
		return e.exposes(x.Elem())
	case *types.Chan:
		return e.exposes(x.Elem())
	case *types.Map:
		return e.exposes(x.Key()) || e.exposes(x.Elem())
	case *types.Signature:
		return e.tuple(x.Params()) || e.tuple(x.Results())
	case *types.TypeParam:
		return e.exposes(x.Constraint())
	case *types.Named, *types.Interface, *types.Struct:
		if e.hasWriteMethods(t) || e.hasWriteMethods(types.NewPointer(t)) {
			return true
		}
		if n, ok := t.(*types.Named); ok {
			// A named container (type L []ConnectorClient) holds the client in its underlying type.
			switch n.Underlying().(type) {
			case *types.Slice, *types.Array, *types.Chan, *types.Map, *types.Signature, *types.Pointer:
				return e.exposes(n.Underlying())
			}
		}
	}
	return false
}

func (e *exposer) tuple(t *types.Tuple) bool {
	for i := 0; i < t.Len(); i++ {
		if e.exposes(t.At(i).Type()) {
			return true
		}
	}
	return false
}

func (e *exposer) hasWriteMethods(t types.Type) bool {
	if _, isIface := t.Underlying().(*types.Interface); !isIface {
		if _, isPtr := t.(*types.Pointer); isPtr {
			if _, ptrToIface := t.(*types.Pointer).Elem().Underlying().(*types.Interface); ptrToIface {
				return false
			}
		}
	}
	ms := types.NewMethodSet(t)
	for i := 0; i < ms.Len(); i++ {
		fn, ok := ms.At(i).Obj().(*types.Func)
		if !ok {
			continue
		}
		if sig, ok := fn.Type().(*types.Signature); ok && isGenWrite(e.mod, fn.Name(), sig) {
			return true
		}
	}
	return false
}

// place returns the package's directory below the module root. The import path is used as is: a real
// directory called "proto_test" or "client_test" is that directory, not its sibling. Only a genuine
// external test package (name ends in _test, every file a _test.go, and its files live in the directory
// of the package under test rather than in a directory of that name) is placed at the package under test.
func place(pass *analysis.Pass, mod string) string {
	r := rel(mod, pass.Pkg.Path())
	if r == "" || !strings.HasSuffix(pass.Pkg.Name(), "_test") || !strings.HasSuffix(r, "_test") || len(pass.Files) == 0 {
		return r
	}
	dir := ""
	for _, f := range pass.Files {
		name := pass.Fset.Position(f.Pos()).Filename
		if !isTestFile(name) {
			return r
		}
		d := filepath.ToSlash(filepath.Dir(name))
		if dir != "" && d != dir {
			return r
		}
		dir = d
	}
	if strings.HasSuffix(dir, "/"+r) {
		return r // the directory really is called ..._test
	}
	if base := strings.TrimSuffix(r, "_test"); strings.HasSuffix(dir, "/"+base) {
		return base
	}
	return r
}

func isTestFile(name string) bool { return strings.HasSuffix(name, "_test.go") }

func run(pass *analysis.Pass) (any, error) {
	// Fail closed: without the module path nothing can be placed, and every exemption would be lost
	// or, worse, mis-granted.
	if pass.Module == nil || pass.Module.Path == "" {
		return nil, fmt.Errorf("connwrite: no module path for package %s; cannot place it in the tree", pass.Pkg.Path())
	}
	mod := pass.Module.Path
	r := place(pass, mod)
	if under(r, protoDir) {
		return nil, nil
	}
	inClient := under(r, clientDir)
	e := &exposer{mod: mod, memo: map[types.Type]bool{}}
	info := pass.TypesInfo

	// exempt: test files of the roots that drive a fake connector, as the syntactic half does.
	exemptFile := func(pos token.Pos) bool {
		name := pass.Fset.Position(pos).Filename
		return isTestFile(name) && (under(r, connectorDir) || under(r, composeConn) || under(r, composeSrv))
	}
	report := func(pos token.Pos, msg string) {
		if exemptFile(pos) {
			return
		}
		pass.Report(analysis.Diagnostic{Pos: pos, Category: "O2", Message: msg})
	}

	if inClient {
		// Visible outside: exported types, exported fields, exported package-level variables.
		for id, obj := range info.Defs {
			if obj == nil || !id.IsExported() {
				continue
			}
			switch o := obj.(type) {
			case *types.TypeName:
				if o.Parent() != o.Pkg().Scope() {
					break
				}
				if e.exposes(o.Type()) {
					report(id.Pos(), "exported type "+o.Name()+" is, aliases or embeds the generated connector-contract client (its Plan/Apply write RPCs); a package outside internal/directory/client could hold it and write with no step.Step; expose a narrow read-only interface instead")
					break
				}
				// An exported field of an exported struct type is visible outside; the fields of an
				// unexported struct (a test fake embedding the client) are not.
				if st, ok := o.Type().Underlying().(*types.Struct); ok && !o.IsAlias() {
					for i := 0; i < st.NumFields(); i++ {
						if f := st.Field(i); f.Exported() && e.exposes(f.Type()) {
							report(f.Pos(), "exported field "+f.Name()+" of "+o.Name()+" has a type that carries the generated connector-contract client's Plan/Apply write RPCs; it is visible outside internal/directory/client")
						}
					}
				}
			case *types.Var:
				if !o.IsField() && o.Parent() == o.Pkg().Scope() && e.exposes(o.Type()) {
					report(id.Pos(), "exported variable "+o.Name()+" has a type that carries the generated connector-contract client's Plan/Apply write RPCs; it is visible outside internal/directory/client")
				}
			}
		}
	} else {
		for id, obj := range info.Defs {
			switch o := obj.(type) {
			case *types.TypeName:
				if e.exposes(o.Type()) {
					report(id.Pos(), "type "+o.Name()+" is, aliases or embeds the generated connector-contract client (its Plan/Apply write RPCs); only internal/directory/client may hold it, write RPCs go through client.Write")
				}
			case *types.Var:
				if e.exposes(o.Type()) {
					report(id.Pos(), "variable, field or parameter "+o.Name()+" has a type that carries the generated connector-contract client's Plan/Apply write RPCs; only internal/directory/client may hold it")
				}
			case *types.Func:
				// Unnamed parameters and results have no declaration of their own.
				if sig, ok := o.Type().(*types.Signature); ok && (unnamedExposes(e, sig.Params()) || unnamedExposes(e, sig.Results())) {
					report(id.Pos(), o.Name()+" takes or returns the generated connector-contract client (its Plan/Apply write RPCs); only internal/directory/client may")
				}
			}
		}
		for expr, tv := range info.Types {
			if tv.IsType() && e.exposes(tv.Type) {
				report(expr.Pos(), "a type that carries the generated connector-contract client's Plan/Apply write RPCs is named here; only internal/directory/client may hold it, write RPCs go through client.Write")
			}
		}
	}

	// Every use of the generated Plan or Apply, however the client is named.
	for _, f := range pass.Files {
		fname := pass.Fset.Position(f.Pos()).Filename
		for _, d := range f.Decls {
			ast.Inspect(d, func(n ast.Node) bool {
				se, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				sel := info.Selections[se]
				if sel == nil {
					return true
				}
				fn, ok := sel.Obj().(*types.Func)
				if !ok {
					return true
				}
				if sig, ok := fn.Type().(*types.Signature); !ok || !isGenWrite(mod, fn.Name(), sig) {
					return true
				}
				if inClient && (isTestFile(fname) || hasClearance(mod, info, d)) {
					return true
				}
				report(se.Sel.Pos(), "the generated connector-contract client's "+fn.Name()+" write RPC is used outside a function of internal/directory/client that takes a step.Clearance; write RPCs go through client.Write")
				return true
			})
		}
	}
	return nil, nil
}

func unnamedExposes(e *exposer, t *types.Tuple) bool {
	for i := 0; i < t.Len(); i++ {
		if t.At(i).Name() == "" && e.exposes(t.At(i).Type()) {
			return true
		}
	}
	return false
}

// hasClearance reports whether d is a function declaration with a step.Clearance parameter, judged by
// the parameter's resolved type, not by how it is spelled.
func hasClearance(mod string, info *types.Info, d ast.Decl) bool {
	fd, ok := d.(*ast.FuncDecl)
	if !ok || fd.Type.Params == nil {
		return false
	}
	for _, p := range fd.Type.Params.List {
		t := info.TypeOf(p.Type)
		if t == nil {
			continue
		}
		if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
			t = ptr.Elem()
		}
		if n, ok := types.Unalias(t).(*types.Named); ok && n.Obj().Name() == "Clearance" && pathIs(mod, n.Obj().Pkg(), stepPkg) {
			return true
		}
	}
	return false
}
