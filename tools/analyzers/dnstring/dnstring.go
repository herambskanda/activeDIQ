// Package dnstring is the FF-SP2 pass for safe-primitives §4.6. A DNString is a rendered DN for
// display and for the connector; string operations on it are how authorisation by suffix match gets
// written (`HasSuffix(dn, ou)`), and escaped commas make that wrong. forbidigo matches names and
// cannot see types, so this is a go/analysis pass.
//
// It reports, outside the dn package and the connector (tests and tier L excepted):
//   - a conversion string(x) or []byte(x) where x has type dn.DNString;
//   - a DNString passed to any function of package strings or bytes;
//   - a DNString operand of `+`, which builds a DN by concatenation.
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
	Doc:  "FF-SP2 (safe-primitives §4.6): no string conversion, strings/bytes call or concatenation on a dn.DNString outside dn and the connector",
	Run:  run,
}

func isDNString(pass *analysis.Pass, t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Name() != "DNString" || n.Obj().Pkg() == nil {
		return false
	}
	return policy.Match(util.TypesPkgDir(pass, n.Obj().Pkg()), policy.DN)
}

func run(pass *analysis.Pass) (any, error) {
	if policy.MatchAny(util.PkgDir(pass), []string{policy.DN, policy.Connector}) {
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
				Message: "FF-SP2 [dnstring]: conversion of a DNString to " + tv.Type.String() + " outside dn and the connector: use dn.Equal, IsDescendantOf or Display (§4.6)"})
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
