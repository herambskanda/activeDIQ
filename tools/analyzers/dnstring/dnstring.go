// Package dnstring is the FF-SP2 pass for safe-primitives §4.6. A DNString is a rendered DN for
// display and for the connector; string operations on it are how authorisation by suffix match gets
// written (`HasSuffix(dn, ou)`), and escaped commas make that wrong. forbidigo matches names and
// cannot see types, so this is a go/analysis pass.
//
// It reports, outside the dn package, the connector included (tests and tier L excepted):
//   - a conversion string(x) or []byte(x) where x has type dn.DNString;
//   - a DNString passed to any function of package strings or bytes;
//   - a DNString operand of `+`, which builds a DN by concatenation.
//
// Inside the connector (the only wire path) it also reports the opposite mistake: any reference to
// dn.DN.String or dn.DN.Render, and any dn.DN converted to an interface (fmt.Sprint(d)). Only ObjectRef.ForRequest enforces NotRequestable for opaque RDNs and the
// MaxDNLen bound on the rendered output, so a request DN is built from ForRequest or not at all.
package dnstring

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
	"github.com/skenzeriq/activediq/tools/analyzers/util"
)

const Name = "dnstring"

var Analyzer = &analysis.Analyzer{
	Name: Name,
	Doc:  "FF-SP2 (safe-primitives §4.6): no string conversion, strings/bytes call or concatenation on a dn.DNString outside dn; no dn.DN.String/Render in the connector",
	Run:  run,
}

func isDNString(pass *analysis.Pass, t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Name() != "DNString" || n.Obj().Pkg() == nil {
		return false
	}
	return policy.Match(util.TypesPkgDir(pass, n.Obj().Pkg()), policy.DN)
}

// isDNMethodFunc reports whether fn is dn.DN.String or dn.DN.Render (value or pointer receiver).
func isDNMethodFunc(pass *analysis.Pass, fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || (fn.Name() != "String" && fn.Name() != "Render") ||
		!policy.Match(util.TypesPkgDir(pass, fn.Pkg()), policy.DN) {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	t := sig.Recv().Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Name() == "DN"
}

// isDNNamed reports the named type dn.DN.
func isDNNamed(pass *analysis.Pass, n *types.Named) bool {
	return n.Obj().Name() == "DN" && n.Obj().Pkg() != nil &&
		policy.Match(util.TypesPkgDir(pass, n.Obj().Pkg()), policy.DN)
}

// isDNType reports a type whose formatting can reach dn.DN.String or Render: dn.DN or *dn.DN, a type
// whose method set promotes either (an embedded dn.DN), and a slice, array, map, channel, pointer or
// struct that contains one (fmt formats elements and exported fields with String).
func isDNType(pass *analysis.Pass, t types.Type) bool {
	if t == nil {
		return false
	}
	for _, name := range []string{"String", "Render"} {
		obj, _, _ := types.LookupFieldOrMethod(t, true, nil, name)
		if fn, ok := obj.(*types.Func); ok && isDNMethodFunc(pass, fn) {
			return true
		}
	}
	return util.NamedMatches(t, func(n *types.Named) bool { return isDNNamed(pass, n) })
}

// isInterface reports a target type that dispatches dynamically: an interface, or a type parameter
// (a generic helper may call String on its argument, whatever the constraint says).
func isInterface(t types.Type) bool {
	if t == nil {
		return false
	}
	if _, ok := types.Unalias(t).(*types.TypeParam); ok {
		return true
	}
	return types.IsInterface(t)
}

// runConnector is the wire-path rule. Every way to obtain a DN's text other than ObjectRef.ForRequest
// is reported: any reference to DN.String or DN.Render (call, method value, method expression,
// promoted method), and any dn.DN or *dn.DN that is implicitly or explicitly converted to an
// interface (fmt.Sprint(d), fmt.Sprintf("%s", &d), fmt.Stringer, slog and error formatting), which
// reaches String through dynamic dispatch.
func runConnector(pass *analysis.Pass) {
	reportIface := func(e ast.Expr, target types.Type) {
		if isInterface(target) && isDNType(pass, pass.TypesInfo.TypeOf(e)) {
			pass.Report(analysis.Diagnostic{Pos: e.Pos(), Category: Name,
				Message: "FF-SP2 [dnstring]: a dn.DN is converted to an interface in the connector, which reaches DN.String by dynamic dispatch: a request DN comes from ObjectRef.ForRequest (§4.6)"})
		}
	}
	for _, f := range pass.Files {
		if util.SkipFile(pass, f) {
			continue
		}
		var sigs []*types.Signature // enclosing function signatures
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				switch top.(type) {
				case *ast.FuncDecl, *ast.FuncLit:
					sigs = sigs[:len(sigs)-1]
				}
				return true
			}
			stack = append(stack, n)
			switch v := n.(type) {
			case *ast.FuncDecl:
				var sig *types.Signature
				if obj := pass.TypesInfo.Defs[v.Name]; obj != nil {
					sig, _ = obj.Type().(*types.Signature)
				}
				sigs = append(sigs, sig)
			case *ast.FuncLit:
				sig, _ := pass.TypesInfo.TypeOf(v).(*types.Signature)
				sigs = append(sigs, sig)
			case *ast.SelectorExpr:
				if fn, ok := pass.TypesInfo.Uses[v.Sel].(*types.Func); ok && isDNMethodFunc(pass, fn) {
					pass.Report(analysis.Diagnostic{Pos: v.Pos(), Category: Name,
						Message: "FF-SP2 [dnstring]: reference to dn.DN." + fn.Name() + " in the connector: a request DN comes from ObjectRef.ForRequest, which enforces NotRequestable and MaxDNLen (§4.6)"})
				}
			case *ast.CallExpr:
				if tv, ok := pass.TypesInfo.Types[v.Fun]; ok && tv.IsType() {
					if len(v.Args) == 1 {
						reportIface(v.Args[0], tv.Type)
					}
					break
				}
				ft := pass.TypesInfo.TypeOf(v.Fun)
				if ft == nil {
					break
				}
				sig, _ := ft.Underlying().(*types.Signature)
				if fn := util.Callee(pass, v); fn != nil && fn.Origin() != nil {
					// the generic signature, so a type-parameter parameter is visible
					if osig, ok := fn.Origin().Type().(*types.Signature); ok && osig.Params().Len() == sig.Params().Len() {
						sig = osig
					}
				}
				if sig == nil {
					break
				}
				for i, a := range v.Args {
					reportIface(a, paramType(sig, i, v.Ellipsis.IsValid()))
				}
			case *ast.AssignStmt:
				if len(v.Lhs) == len(v.Rhs) {
					for i, r := range v.Rhs {
						reportIface(r, pass.TypesInfo.TypeOf(v.Lhs[i]))
					}
				}
			case *ast.ValueSpec:
				if v.Type != nil && len(v.Names) == len(v.Values) {
					for _, e := range v.Values {
						reportIface(e, pass.TypesInfo.TypeOf(v.Type))
					}
				}
			case *ast.ReturnStmt:
				if len(sigs) > 0 && sigs[len(sigs)-1] != nil {
					res := sigs[len(sigs)-1].Results()
					if res.Len() == len(v.Results) {
						for i, e := range v.Results {
							reportIface(e, res.At(i).Type())
						}
					}
				}
			case *ast.SendStmt:
				if ct := pass.TypesInfo.TypeOf(v.Chan); ct != nil {
					if ch, ok := ct.Underlying().(*types.Chan); ok {
						reportIface(v.Value, ch.Elem())
					}
				}
			case *ast.CompositeLit:
				checkComposite(pass, v, reportIface)
			}
			return true
		})
	}
}

// paramType is the parameter type receiving argument i, expanding a variadic tail.
func paramType(sig *types.Signature, i int, ellipsis bool) types.Type {
	ps := sig.Params()
	n := ps.Len()
	if n == 0 {
		return nil
	}
	if sig.Variadic() && i >= n-1 {
		last := ps.At(n - 1).Type()
		if ellipsis {
			return last
		}
		if s, ok := last.(*types.Slice); ok {
			return s.Elem()
		}
		return nil
	}
	if i < n {
		return ps.At(i).Type()
	}
	return nil
}

func checkComposite(pass *analysis.Pass, lit *ast.CompositeLit, report func(ast.Expr, types.Type)) {
	t := pass.TypesInfo.TypeOf(lit)
	if t == nil {
		return
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		for i, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok {
					for j := 0; j < u.NumFields(); j++ {
						if u.Field(j).Name() == id.Name {
							report(kv.Value, u.Field(j).Type())
						}
					}
				}
			} else if i < u.NumFields() {
				report(e, u.Field(i).Type())
			}
		}
	case *types.Slice, *types.Array, *types.Map:
		var key, elem types.Type
		switch c := u.(type) {
		case *types.Slice:
			elem = c.Elem()
		case *types.Array:
			elem = c.Elem()
		case *types.Map:
			key, elem = c.Key(), c.Elem()
		}
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				if key != nil {
					report(kv.Key, key)
				}
				report(kv.Value, elem)
			} else {
				report(e, elem)
			}
		}
	}
}

func run(pass *analysis.Pass) (any, error) {
	dir := util.PkgDir(pass)
	if policy.Match(dir, policy.Connector) {
		runConnector(pass)
	} else if policy.Match(dir, policy.DN) {
		return nil, nil
	}
	for _, f := range pass.Files {
		if util.SkipFile(pass, f) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CallExpr:
				checkCall(pass, v)
			case *ast.BinaryExpr:
				if v.Op == token.ADD && (isDNString(pass, pass.TypesInfo.TypeOf(v.X)) || isDNString(pass, pass.TypesInfo.TypeOf(v.Y))) {
					pass.Report(analysis.Diagnostic{Pos: v.Pos(), Category: Name,
						Message: "FF-SP2 [dnstring]: a DNString is joined with + : build DNs with the dn package, never by concatenation (§4.6)"})
				}
			}
			return true
		})
	}
	return nil, nil
}

func checkCall(pass *analysis.Pass, call *ast.CallExpr) {
	// Conversion: the callee is a type.
	if tv, ok := pass.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
		if len(call.Args) == 1 && isDNString(pass, pass.TypesInfo.TypeOf(call.Args[0])) && !isDNString(pass, tv.Type) {
			pass.Report(analysis.Diagnostic{Pos: call.Pos(), Category: Name,
				Message: "FF-SP2 [dnstring]: conversion of a DNString to " + tv.Type.String() + " outside dn: use dn.Equal, IsDescendantOf or Display (§4.6)"})
		}
		return
	}
	fn := util.Callee(pass, call)
	if fn == nil || fn.Pkg() == nil {
		return
	}
	if p := fn.Pkg().Path(); p == "strings" || p == "bytes" {
		for _, a := range call.Args {
			if isDNString(pass, pass.TypesInfo.TypeOf(a)) {
				pass.Report(analysis.Diagnostic{Pos: call.Pos(), Category: Name,
					Message: "FF-SP2 [dnstring]: a DNString is passed to " + p + "." + fn.Name() + ": string operations on a DN are banned outside dn (§4.6)"})
			}
		}
	}
}
