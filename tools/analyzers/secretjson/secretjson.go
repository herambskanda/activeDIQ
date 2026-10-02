// Package secretjson is the FF-SP2 pass for safe-primitives §5.6 and ADR-0004 rule 6. A decode into a
// type that contains a Secret must go through secretjson.Decode, because a Secret is read straight
// from the request buffer and never becomes a Go string (which cannot be zeroed). It reports:
//
//  1. a JSON decode (encoding/json, encoding/json/v2, go-json-experiment) whose destination type
//     contains a Secret, anywhere except package secretjson, package secret itself, and the
//     UnmarshalJSONFrom methods of files carrying the tools/gen/api generated header (those nested
//     calls inherit secretjson.Decode's options; ADR-0004 rule 6 step 3);
//  2. a call to secretjson.Decode from any package but apihost, the single caller for API bodies;
//  3. ReadToken, or Token.String, inside a decoder method of a type that contains a Secret: a string
//     token allocates an unzeroable copy. The decoder must use jsontext ReadValue, which aliases the
//     caller's buffer.
//
// Tests and tier L are not judged.
package secretjson

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
	"github.com/skenzeriq/activediq/tools/analyzers/util"
)

const Name = "secretjson"

var Analyzer = &analysis.Analyzer{
	Name: Name,
	Doc:  "FF-SP2 (safe-primitives §5.6, ADR-0004): decode into Secret-bearing types only through secretjson.Decode, called only from apihost; no string tokens in a Secret decoder",
	Run:  run,
}

// SecretJSON is the package of the one decode path.
const SecretJSON = policy.Secret + "/secretjson"

func isSecret(pass *analysis.Pass, n *types.Named) bool {
	return n.Obj().Name() == "Secret" && n.Obj().Pkg() != nil && policy.Match(util.TypesPkgDir(pass, n.Obj().Pkg()), policy.Secret)
}

func containsSecret(pass *analysis.Pass, t types.Type) bool {
	return util.NamedMatches(t, func(n *types.Named) bool { return isSecret(pass, n) })
}

func isJSONPkg(p string) bool {
	return p == "encoding/json" || strings.HasPrefix(p, "encoding/json/") || strings.HasPrefix(p, "github.com/go-json-experiment/json")
}

func isDecoderMethod(name string) bool {
	return name == "UnmarshalJSON" || name == "UnmarshalJSONFrom"
}

func run(pass *analysis.Pass) (any, error) {
	dir := util.PkgDir(pass)
	if policy.Match(dir, SecretJSON) {
		return nil, nil // the one decode path
	}
	for _, f := range pass.Files {
		if util.SkipFile(pass, f) {
			continue
		}
		generated := util.HasHeader(f, policy.GeneratedByAPI)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			inSecretDecoder := false
			inGeneratedDecoder := false
			if fd.Recv != nil && isDecoderMethod(fd.Name.Name) && len(fd.Recv.List) == 1 {
				if containsSecret(pass, pass.TypesInfo.TypeOf(fd.Recv.List[0].Type)) {
					inSecretDecoder = true
				}
				if generated && fd.Name.Name == "UnmarshalJSONFrom" {
					inGeneratedDecoder = true
				}
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn := util.Callee(pass, call)
				if fn == nil || fn.Pkg() == nil {
					return true
				}
				pkgPath := fn.Pkg().Path()
				if policy.Match(util.TypesPkgDir(pass, fn.Pkg()), SecretJSON) && fn.Name() == "Decode" && !policy.Match(dir, policy.APIHost) {
					pass.Report(analysis.Diagnostic{Pos: call.Pos(), Category: Name,
						Message: "FF-SP2 [secretjson]: secretjson.Decode is called outside apihost: apihost is the single caller for API request bodies (ADR-0004 rule 6)"})
					return true
				}
				if !isJSONPkg(pkgPath) {
					return true
				}
				if inSecretDecoder && (fn.Name() == "ReadToken" || (fn.Name() == "String" && recvName(fn) == "Token")) {
					pass.Report(analysis.Diagnostic{Pos: call.Pos(), Category: Name,
						Message: "FF-SP2 [secretjson]: " + fn.Name() + " inside a Secret decoder allocates an unzeroable Go string: read the value with jsontext ReadValue (§5.6)"})
					return true
				}
				if !(strings.HasPrefix(fn.Name(), "Unmarshal") || fn.Name() == "Decode") || inGeneratedDecoder {
					return true
				}
				if policy.Match(dir, policy.Secret) {
					return true // the Secret type's own decoder
				}
				for _, a := range call.Args {
					if containsSecret(pass, pass.TypesInfo.TypeOf(a)) {
						pass.Report(analysis.Diagnostic{Pos: call.Pos(), Category: Name,
							Message: "FF-SP2 [secretjson]: " + fn.Name() + " decodes into a type that contains a Secret: decode only through secretjson.Decode (§5.6, ADR-0004 rule 6)"})
						break
					}
				}
				return true
			})
		}
	}
	return nil, nil
}

func recvName(fn *types.Func) string {
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil {
		return ""
	}
	t := sig.Recv().Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := types.Unalias(t).(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
}
