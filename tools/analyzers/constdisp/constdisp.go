// Package constdisp is the FF-SP2 pass for safe-primitives §12.5 rule 5 (HT-18): Content-Disposition
// is set only by httpx.Attachment. The syntactic scan catches the string literal; this pass uses
// go/types to evaluate every constant string expression, so a name assembled from constants
// ("Content-" + "Disposition", a const spread over files or imported from another package, a typed
// const, a conversion) is judged by its folded value. httpx, tests and tier L are not judged.
package constdisp

import (
	"go/ast"
	"go/constant"
	"strings"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
	"github.com/skenzeriq/activediq/tools/analyzers/util"
)

const Name = "constdisp"

// Rule is the category shared with the syntactic literal rule of the same name.
const Rule = "content-disposition-literal"

var Analyzer = &analysis.Analyzer{
	Name: Name,
	Doc:  "FF-SP2 (safe-primitives §12.5 rule 5): Content-Disposition, however the constant is assembled, only in httpx",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	if policy.Match(util.PkgDir(pass), policy.Httpx) {
		return nil, nil
	}
	for _, f := range pass.Files {
		if util.SkipFile(pass, f) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			tv, ok := pass.TypesInfo.Types[e]
			if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
				return true
			}
			if _, lit := e.(*ast.BasicLit); !lit && strings.EqualFold(strings.TrimSpace(constant.StringVal(tv.Value)), "content-disposition") {
				pass.Report(analysis.Diagnostic{Pos: e.Pos(), Category: Rule,
					Message: "FF-SP2 [" + Rule + "]: constant expression folds to Content-Disposition: it is set only by httpx.Attachment (§12.5 rule 5, HT-18)"})
			}
			return false // the outermost constant expression is the judged unit
		})
	}
	return nil, nil
}
