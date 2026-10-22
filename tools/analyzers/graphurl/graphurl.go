// Package graphurl is the FF-SP2 pass `graph-url-assembly` of safe-primitives-odata §6. Inside the
// Graph connector (internal/connector/graph and below) every URL is written by odata.Request.URL
// or is a host-pinned @odata.nextLink. The pass reports there:
//   - an assignment to, or a composite literal field of, url.URL Path, RawPath, RawQuery or
//     ForceQuery;
//   - a call of url.PathEscape, url.QueryEscape, url.PathUnescape, url.QueryUnescape or
//     url.Values.Encode;
//   - http.NewRequest or http.NewRequestWithContext whose URL argument is not `x.String()` on a
//     *url.URL (the odata result, or the parsed nextLink checked against the pinned base).
//
// Functions listed in policy.GraphTokenURL (the OAuth token endpoint, which is not OData) are exempt.
// Tests and tier L are not judged.
package graphurl

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
	"github.com/skenzeriq/activediq/tools/analyzers/util"
)

const Name = "graphurl"

// Rule is the finding category, shared with the safe-primitives-odata rule name.
const Rule = "graph-url-assembly"

var Analyzer = &analysis.Analyzer{
	Name: Name,
	Doc:  "FF-SP2 (safe-primitives-odata §6): the Graph connector writes no URL path or query by hand",
	Run:  run,
}

var urlFields = map[string]bool{"Path": true, "RawPath": true, "RawQuery": true, "ForceQuery": true}
var urlFuncs = map[string]bool{"PathEscape": true, "QueryEscape": true, "PathUnescape": true, "QueryUnescape": true}

func isURLType(t types.Type) bool {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "net/url" && n.Obj().Name() == "URL"
}

func run(pass *analysis.Pass) (any, error) {
	dir := util.PkgDir(pass)
	if !policy.Match(dir, policy.Graph) {
		return nil, nil
	}
	for _, f := range pass.Files {
		if util.SkipFile(pass, f) {
			continue
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if ok && policy.IsGraphTokenURL(dir, fd.Name.Name) {
				continue
			}
			check(pass, d)
		}
	}
	return nil, nil
}

func report(pass *analysis.Pass, pos ast.Node, msg string) {
	pass.Report(analysis.Diagnostic{Pos: pos.Pos(), Category: Rule, Message: "FF-SP2 [graph-url-assembly]: " + msg + " (safe-primitives-odata §6)"})
}

func check(pass *analysis.Pass, root ast.Node) {
	ast.Inspect(root, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			for _, l := range v.Lhs {
				if sel, ok := l.(*ast.SelectorExpr); ok && urlFields[sel.Sel.Name] && isURLType(pass.TypesInfo.TypeOf(sel.X)) {
					report(pass, v, "assignment to url.URL."+sel.Sel.Name+": the URL is written by odata.Request.URL only")
				}
			}
		case *ast.CompositeLit:
			if !isURLType(pass.TypesInfo.TypeOf(v)) {
				return true
			}
			for _, el := range v.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if id, ok := kv.Key.(*ast.Ident); ok && urlFields[id.Name] {
						report(pass, kv, "url.URL literal sets "+id.Name+": the URL is written by odata.Request.URL only")
					}
				}
			}
		case *ast.CallExpr:
			fn := util.Callee(pass, v)
			if fn == nil || fn.Pkg() == nil {
				return true
			}
			switch p := fn.Pkg().Path(); {
			case p == "net/url" && urlFuncs[fn.Name()]:
				report(pass, v, "url."+fn.Name()+" in the Graph connector: encoding belongs to the odata primitive")
			case p == "net/url" && fn.Name() == "Encode":
				report(pass, v, "url.Values.Encode in the Graph connector: query encoding belongs to the odata primitive")
			case p == "net/http" && (fn.Name() == "NewRequest" || fn.Name() == "NewRequestWithContext"):
				idx := 1
				if fn.Name() == "NewRequestWithContext" {
					idx = 2
				}
				if len(v.Args) > idx && !isURLString(pass, v.Args[idx]) {
					report(pass, v, "http."+fn.Name()+" with a URL that is not the String() of an odata.Request.URL result or a host-pinned nextLink")
				}
			}
		}
		return true
	})
}

// isURLString reports e of the form x.String() with x a *url.URL.
func isURLString(pass *analysis.Pass, e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "String" && isURLType(pass.TypesInfo.TypeOf(sel.X))
}
