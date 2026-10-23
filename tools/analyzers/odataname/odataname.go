// Package odataname is the FF-SP2 pass for safe-primitives-odata §6 (`odataname`). An odata.Name is an
// entity set, navigation, property or cast identifier that the primitive splices into a URL without
// quoting, so it must be a compile-time constant. The pass reports, outside the odata package:
//   - a conversion to odata.Name from a non-constant expression (OK-10, FX-11);
//   - a call of odata.StringProp, GUIDStringProp, GUIDProp, BoolProp, IntProp or TimeProp outside
//     internal/directory/odata/graphschema, where each property is declared once against $metadata.
//
// Tests and tier L are not judged.
package odataname

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
	"github.com/skenzeriq/activediq/tools/analyzers/util"
)

const Name = "odataname"

var Analyzer = &analysis.Analyzer{
	Name: Name,
	Doc:  "FF-SP2 (safe-primitives-odata §6): odata.Name is converted only from constants, and property declarations live only in graphschema",
	Run:  run,
}

var propCtors = map[string]bool{"StringProp": true, "GUIDStringProp": true, "GUIDProp": true, "BoolProp": true, "IntProp": true, "TimeProp": true}

func inOData(pass *analysis.Pass, pkg *types.Package) bool {
	return pkg != nil && policy.Match(util.TypesPkgDir(pass, pkg), policy.OData)
}

func isODataName(pass *analysis.Pass, t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Name() == "Name" && inOData(pass, n.Obj().Pkg()) && util.TypesPkgDir(pass, n.Obj().Pkg()) == policy.OData
}

func run(pass *analysis.Pass) (any, error) {
	dir := util.PkgDir(pass)
	inHome := policy.Match(dir, policy.OData)
	for _, f := range pass.Files {
		if util.SkipFile(pass, f) {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if tv, ok := pass.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
				if !inHome && len(call.Args) == 1 && isODataName(pass, tv.Type) && pass.TypesInfo.Types[call.Args[0]].Value == nil {
					pass.Report(analysis.Diagnostic{Pos: call.Pos(), Category: Name,
						Message: "FF-SP2 [odataname]: odata.Name converted from a non-constant string: an identifier is spliced into the URL unquoted, so it must be a constant (OK-10)"})
				}
				return true
			}
			fn := util.Callee(pass, call)
			if fn == nil || fn.Pkg() == nil || !propCtors[fn.Name()] || util.TypesPkgDir(pass, fn.Pkg()) != policy.OData {
				return true
			}
			if !policy.Match(dir, policy.GraphSchema) && dir != policy.OData {
				pass.Report(analysis.Diagnostic{Pos: call.Pos(), Category: Name,
					Message: "FF-SP2 [odataname]: odata." + fn.Name() + " outside graphschema: declare each Graph property once, against $metadata, in " + policy.GraphSchema})
			}
			return true
		})
	}
	return nil, nil
}
