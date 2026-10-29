// Package stepescape is the type-aware half of fitness-operation O1 (ADR-0005 rule 2): a
// step.Step is never captured by a closure and never passed to a function that has no step.Step
// parameter. The syntactic half (fields, globals, maps, slices, channels, forged literals,
// TakeMinter, linkname) lives in tools/fitness/operation/o1.go and needs no type information.
//
// A call is judged by the signature of what it calls, so a method value, a func-typed variable and an
// interface method are judged like a plain function. A conversion of a Step to any other type
// (any, an interface) is an escape too. The step package itself is not judged.
package stepescape

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const Name = "stepescape"

// stepPkgSuffix is the step package's path below the module (or the whole path in an analysistest layout).
const stepPkgSuffix = "internal/platform/operation/step"

var Analyzer = &analysis.Analyzer{
	Name: Name,
	Doc:  "fitness-operation O1 (ADR-0005 rule 2): a step.Step is not captured by a closure and not passed to a function with no step.Step parameter",
	Run:  run,
}

func isStepPkg(p *types.Package) bool {
	if p == nil {
		return false
	}
	return p.Path() == stepPkgSuffix || strings.HasSuffix(p.Path(), "/"+stepPkgSuffix)
}

// isStep reports step.Step or *step.Step.
func isStep(t types.Type) bool {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Name() == "Step" && isStepPkg(n.Obj().Pkg())
}

// allowDirective exempts one line (or the line after it) in a _test.go file, and needs a reason: the
// few tests that smuggle a Step on purpose to prove the runner revokes it. It is never honoured in
// non-test code.
const allowDirective = "//fitness:allow-step-escape "

func allowed(pass *analysis.Pass, pos token.Pos) bool {
	p := pass.Fset.Position(pos)
	if !strings.HasSuffix(p.Filename, "_test.go") {
		return false
	}
	for _, f := range pass.Files {
		if pass.Fset.Position(f.Pos()).Filename != p.Filename {
			continue
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				rest, ok := strings.CutPrefix(c.Text, allowDirective)
				if !ok || strings.TrimSpace(rest) == "" {
					continue
				}
				if l := pass.Fset.Position(c.Pos()).Line; l == p.Line || l == p.Line-1 {
					return true
				}
			}
		}
	}
	return false
}

func report(pass *analysis.Pass, pos token.Pos, msg string) {
	if allowed(pass, pos) {
		return
	}
	pass.Report(analysis.Diagnostic{Pos: pos, Category: "O1", Message: msg})
}

func run(pass *analysis.Pass) (any, error) {
	if isStepPkg(pass.Pkg) || isStepPkg(pkgOfTest(pass.Pkg)) {
		return nil, nil
	}
	for _, f := range pass.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncLit:
				checkCapture(pass, x)
			case *ast.CallExpr:
				checkCall(pass, x)
			}
			return true
		})
	}
	return nil, nil
}

// pkgOfTest maps "p_test" (external test package) to a package with p's path.
func pkgOfTest(p *types.Package) *types.Package {
	if p != nil && strings.HasSuffix(p.Path(), "_test") {
		return types.NewPackage(strings.TrimSuffix(p.Path(), "_test"), p.Name())
	}
	return nil
}

// checkCapture reports each variable of Step type that the literal uses but does not declare. Package
// level variables are the syntactic check's; fields are reached through a selector, not an ident.
func checkCapture(pass *analysis.Pass, lit *ast.FuncLit) {
	seen := map[types.Object]bool{}
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		v, ok := pass.TypesInfo.Uses[id].(*types.Var)
		if !ok || v.IsField() || seen[v] || !isStep(v.Type()) {
			return true
		}
		if v.Parent() == v.Pkg().Scope() { // package level
			return true
		}
		if v.Pos() >= lit.Pos() && v.Pos() < lit.End() { // declared inside the literal
			return true
		}
		seen[v] = true
		report(pass, id.Pos(), "a step.Step ("+v.Name()+") is captured by a closure; it must be passed as a parameter (ADR-0005 rule 2)")
		return true
	})
}

func checkCall(pass *analysis.Pass, call *ast.CallExpr) {
	tv, ok := pass.TypesInfo.Types[call.Fun]
	if !ok {
		return
	}
	if tv.IsType() { // conversion
		if len(call.Args) == 1 && !isStep(tv.Type) {
			if at, ok := pass.TypesInfo.Types[call.Args[0]]; ok && isStep(at.Type) {
				report(pass, call.Args[0].Pos(), "a step.Step is converted to "+tv.Type.String()+"; it may only be held as a step.Step (ADR-0005 rule 2)")
			}
		}
		return
	}
	if tv.IsBuiltin() { // append, copy, new, ... : the syntactic check bans the containers; a Step into any/print is not reachable here
		if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "print" || id.Name == "println" || id.Name == "panic") {
			for _, a := range call.Args {
				if at, ok := pass.TypesInfo.Types[a]; ok && isStep(at.Type) {
					report(pass, a.Pos(), "a step.Step is passed to builtin "+id.Name+" (ADR-0005 rule 2)")
				}
			}
		}
		return
	}
	sig, ok := types.Unalias(tv.Type).Underlying().(*types.Signature)
	if !ok {
		return
	}
	hasStepParam := false
	for p := range sig.Params().Variables() {
		if isStep(p.Type()) {
			hasStepParam = true
			break
		}
	}
	if hasStepParam {
		return
	}
	for _, a := range call.Args {
		if at, ok := pass.TypesInfo.Types[a]; ok && isStep(at.Type) {
			report(pass, a.Pos(), "a step.Step is passed to a function with no step.Step parameter; only a write API or a helper that takes a step.Step may receive it (ADR-0005 rule 2)")
		}
	}
}
