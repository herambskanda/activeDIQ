// Package nestedtx is the FF-SP2 pass for ADR-0005 rule 11's nested-transaction residual. store.DB
// refuses a nested WithTenant only by a context marker, so a body that opens a second transaction
// with a context that does not descend from its own parameter is not caught at run time. Inside a
// function literal passed as the fn argument of (*store.DB).WithTenant or WithPlatform, the pass
// reports:
//
//   - a direct call of (*store.DB).WithTenant or WithPlatform, and
//   - a call of context.Background or context.TODO.
//
// A call that reaches WithTenant through another function stays an accepted residual (ADR-0005
// rule 11). Tests and tier L are not judged.
package nestedtx

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/util"
)

const Name = "nestedtx"

var Analyzer = &analysis.Analyzer{
	Name: Name,
	Doc:  "FF-SP2 (ADR-0005 rule 11): no WithTenant/WithPlatform and no context.Background/TODO inside the body passed to WithTenant/WithPlatform",
	Run:  run,
}

const storeDir = "internal/platform/store"

func run(pass *analysis.Pass) (any, error) {
	reported := map[token.Pos]bool{}
	for _, f := range pass.Files {
		if util.SkipFile(pass, f) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isStoreTx(pass, call) {
				return true
			}
			for _, arg := range call.Args {
				if lit, ok := arg.(*ast.FuncLit); ok {
					checkBody(pass, lit, reported)
				}
			}
			return true
		})
	}
	return nil, nil
}

func checkBody(pass *analysis.Pass, lit *ast.FuncLit, reported map[token.Pos]bool) {
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || reported[call.Pos()] {
			return true
		}
		switch {
		case isStoreTx(pass, call):
			reported[call.Pos()] = true
			pass.Reportf(call.Pos(), "nested store transaction: %s inside a WithTenant/WithPlatform body opens a second, independent transaction (ADR-0005 rule 11); use the body's own tx and ctx", calleeName(pass, call))
		case isRootContext(pass, call):
			reported[call.Pos()] = true
			pass.Reportf(call.Pos(), "%s inside a WithTenant/WithPlatform body: use the body's own ctx, a fresh root context escapes the transaction (ADR-0005 rule 11)", calleeName(pass, call))
		}
		return true
	})
}

func callee(pass *analysis.Pass, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		id = fun.Sel
	case *ast.Ident:
		id = fun
	default:
		return nil
	}
	fn, _ := pass.TypesInfo.Uses[id].(*types.Func)
	return fn
}

func calleeName(pass *analysis.Pass, call *ast.CallExpr) string {
	if fn := callee(pass, call); fn != nil {
		return fn.Name()
	}
	return "call"
}

// isStoreTx reports a call of the WithTenant or WithPlatform method of store.DB.
func isStoreTx(pass *analysis.Pass, call *ast.CallExpr) bool {
	fn := callee(pass, call)
	if fn == nil || (fn.Name() != "WithTenant" && fn.Name() != "WithPlatform") {
		return false
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil || util.TypesPkgDir(pass, fn.Pkg()) != storeDir {
		return false
	}
	rt := sig.Recv().Type()
	if pt, ok := rt.(*types.Pointer); ok {
		rt = pt.Elem()
	}
	n, ok := types.Unalias(rt).(*types.Named)
	return ok && n.Obj().Name() == "DB"
}

func isRootContext(pass *analysis.Pass, call *ast.CallExpr) bool {
	fn := callee(pass, call)
	return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "context" && (fn.Name() == "Background" || fn.Name() == "TODO")
}
