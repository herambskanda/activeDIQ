// Package tmplconst is the FF-SP2 pass for safe-primitives §12.5 rule 3 (HT-07): templates are code,
// so they are parsed only from embed.FS or constant strings. It reports html/template Parse with a
// non-constant argument, ParseFS over anything but an embed.FS, and ParseFiles and ParseGlob (they
// read code from the disk at run time). Tests and tier L are not judged.
package tmplconst

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/util"
)

const Name = "tmplconst"

var Analyzer = &analysis.Analyzer{
	Name: Name,
	Doc:  "FF-SP2 (safe-primitives §12.5 rule 3): html/template is parsed only from constant strings or embed.FS",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	for _, f := range pass.Files {
		if util.SkipFile(pass, f) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn := util.Callee(pass, call)
			if fn == nil || fn.Pkg() == nil || (fn.Pkg().Path() != "html/template" && fn.Pkg().Path() != "text/template") {
				return true
			}
			report := func(msg string) {
				pass.Report(analysis.Diagnostic{Pos: call.Pos(), Category: Name, Message: "FF-SP2 [tmplconst]: " + msg + " (§12.5 rule 3, HT-07)"})
			}
			switch fn.Name() {
			case "Parse":
				if len(call.Args) == 1 && pass.TypesInfo.Types[call.Args[0]].Value == nil {
					report("template.Parse with a non-constant string: templates are code, parse them only from constants or embed.FS")
				}
			case "ParseFS":
				if len(call.Args) > 0 && !isEmbedFS(pass.TypesInfo.TypeOf(call.Args[0])) {
					report("template.ParseFS over something other than an embed.FS")
				}
			case "ParseFiles", "ParseGlob":
				report("template." + fn.Name() + " reads template code from disk at run time: embed the templates and use ParseFS")
			}
			return true
		})
	}
	return nil, nil
}

func isEmbedFS(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Name() == "FS" && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "embed"
}
