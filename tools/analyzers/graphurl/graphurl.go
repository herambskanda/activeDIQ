// Package graphurl is the FF-SP2 pass `graph-url-assembly` of safe-primitives-odata §6. Inside the
// Graph connector (internal/connector/graph and below) every URL is written by odata.Request.URL
// or is a host-pinned @odata.nextLink. Function values count as uses. The pass reports there:
//
//   - an assignment to, or a composite literal field of, any url.URL field (Scheme, Opaque, User,
//     Host, Path, RawPath, RawQuery, ForceQuery, Fragment, ...), or an unkeyed url.URL literal;
//
//   - a call of url.PathEscape, url.QueryEscape, url.PathUnescape, url.QueryUnescape or
//     url.Values.Encode;
//
//   - any use of http.NewRequest or http.NewRequestWithContext outside the policy.GraphHTTPSite
//     methods ((*Client).get, (*Client).bearer); there the URL argument must be `x.String()` on a
//     *url.URL (the odata result, or the parsed nextLink checked against the pinned base).
//
//   - outside the same sites: any use of http.Get, Head, Post, PostForm, of (*http.Client).Get,
//     Head, Post, PostForm, any function or method taking a *http.Request and returning a
//     *http.Response (Client.Do, RoundTrip, a doer interface), http.ReadRequest, new(http.Request),
//     any http.Request composite literal, and any write to the URL or
//     Host field of an http.Request. Each would send a request that skips the host pin.
//
//   - a call of url.Parse, url.ParseRequestURI, url.JoinPath, (*url.URL).Parse, (*url.URL).JoinPath
//     or (*url.URL).ResolveReference, which would turn a concatenated string into a URL.
//
// Methods listed in policy.GraphTokenURL (the OAuth token endpoint, which is not OData; receiver and
// name must both match) are exempt from everything; policy.GraphURLParse sites (the constructor's
// config parses, the nextLink parse in list) are exempt from the parse check only.
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

// urlFields are every field of url.URL: writing any of them hand-builds the URL (Opaque and Host
// included, which can redirect the bearer token).
var urlFields = map[string]bool{"Scheme": true, "Opaque": true, "User": true, "Host": true, "Path": true, "RawPath": true,
	"OmitHost": true, "ForceQuery": true, "RawQuery": true, "Fragment": true, "RawFragment": true}
var urlFuncs = map[string]bool{"PathEscape": true, "QueryEscape": true, "PathUnescape": true, "QueryUnescape": true}

func isURLType(t types.Type) bool {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "net/url" && n.Obj().Name() == "URL"
}

var httpFuncs = map[string]bool{"Get": true, "Head": true, "Post": true, "PostForm": true}

// isHTTPNamed reports t (or *t) as the named type net/http.<name>.
func isHTTPNamed(t types.Type, name string) bool {
	if t == nil {
		return false
	}
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "net/http" && n.Obj().Name() == name
}

// isHTTPSend reports fn as a package-level http.Get/Head/Post/PostForm or a method
// Get/Head/Post/PostForm of *http.Client (http.Header.Get and the like are not matched), or any
// function or method (Client.Do, RoundTripper.RoundTrip, Transport.RoundTrip, a user-defined doer
// interface, a wrapper) that takes a *http.Request and returns a *http.Response.
func isHTTPSend(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	if sig.Recv() == nil && fn.Pkg() != nil && fn.Pkg().Path() == "net/http" && httpFuncs[fn.Name()] {
		return true
	}
	if sig.Recv() != nil && isHTTPNamed(sig.Recv().Type(), "Client") && httpFuncs[fn.Name()] {
		return true
	}
	return takesRequestReturnsResponse(sig)
}

func takesRequestReturnsResponse(sig *types.Signature) bool {
	var req, resp bool
	for i := 0; i < sig.Params().Len(); i++ {
		req = req || isHTTPNamed(sig.Params().At(i).Type(), "Request")
	}
	for i := 0; i < sig.Results().Len(); i++ {
		resp = resp || isHTTPNamed(sig.Results().At(i).Type(), "Response")
	}
	return req && resp
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
			var tok, parse, httpOK bool
			if fd, ok := d.(*ast.FuncDecl); ok {
				recv := recvName(fd)
				tok = policy.IsGraphTokenURL(dir, recv, fd.Name.Name)
				parse = policy.IsGraphURLParse(dir, recv, fd.Name.Name)
				httpOK = policy.IsGraphHTTPSite(dir, recv, fd.Name.Name)
			}
			check(pass, d, tok, parse, httpOK)
		}
	}
	return nil, nil
}

func report(pass *analysis.Pass, pos ast.Node, msg string) {
	pass.Report(analysis.Diagnostic{Pos: pos.Pos(), Category: Rule, Message: "FF-SP2 [graph-url-assembly]: " + msg + " (safe-primitives-odata §6)"})
}

// recvName is the receiver type name of fd, or "" for a plain function.
func recvName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	for {
		switch v := t.(type) {
		case *ast.StarExpr:
			t = v.X
		case *ast.ParenExpr:
			t = v.X
		case *ast.IndexExpr:
			t = v.X
		case *ast.IndexListExpr:
			t = v.X
		case *ast.Ident:
			return v.Name
		default:
			return "?"
		}
	}
}

// parseFuncs are the net/url functions and methods that turn text or segments into a URL.
var parseFuncs = map[string]bool{"Parse": true, "ParseRequestURI": true, "JoinPath": true, "ResolveReference": true}

// check inspects one declaration. tok exempts the token-endpoint encoders (bearer); parse exempts
// the URL-parsing calls (the constructor's config parses and the nextLink parse in list).
func check(pass *analysis.Pass, root ast.Node, tok, parse, httpOK bool) {
	if tok {
		return
	}
	ast.Inspect(root, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			for _, l := range v.Lhs {
				if sel, ok := l.(*ast.SelectorExpr); ok && !httpOK && (sel.Sel.Name == "URL" || sel.Sel.Name == "Host") && isHTTPNamed(pass.TypesInfo.TypeOf(sel.X), "Request") {
					report(pass, v, "assignment to http.Request."+sel.Sel.Name+" outside policy.GraphHTTPSite: a request is created only where the host is pinned")
				}
				if sel, ok := l.(*ast.SelectorExpr); ok && urlFields[sel.Sel.Name] && isURLType(pass.TypesInfo.TypeOf(sel.X)) {
					report(pass, v, "assignment to url.URL."+sel.Sel.Name+": the URL is written by odata.Request.URL only")
				}
			}
		case *ast.CompositeLit:
			if !httpOK && isHTTPNamed(pass.TypesInfo.TypeOf(v), "Request") {
				report(pass, v, "http.Request literal outside policy.GraphHTTPSite: a request is created only where the host is pinned")
			}
			if !isURLType(pass.TypesInfo.TypeOf(v)) {
				return true
			}
			for _, el := range v.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					report(pass, el, "unkeyed url.URL literal: the URL is written by odata.Request.URL only")
					break
				}
				if id, ok := kv.Key.(*ast.Ident); ok && urlFields[id.Name] {
					report(pass, kv, "url.URL literal sets "+id.Name+": the URL is written by odata.Request.URL only")
				}
			}
		case *ast.Ident:
			// Any use, not only a call: `p := url.Parse; p(x)` is the same hand-built URL.
			fn, ok := pass.TypesInfo.Uses[v].(*types.Func)
			if !ok || fn.Pkg() == nil {
				return true
			}
			switch p := fn.Pkg().Path(); {
			case isHTTPSend(fn) && !httpOK:
				report(pass, v, "http client send "+fn.Name()+" outside policy.GraphHTTPSite: a request is sent only where the host is pinned")
			case p == "net/url" && urlFuncs[fn.Name()]:
				report(pass, v, "url."+fn.Name()+" in the Graph connector: encoding belongs to the odata primitive")
			case p == "net/url" && parseFuncs[fn.Name()] && !parse:
				report(pass, v, "url."+fn.Name()+" in the Graph connector: a URL is made by odata.Request.URL, or is a host-pinned nextLink or configured base (policy.GraphURLParse)")
			case p == "net/url" && fn.Name() == "Encode":
				report(pass, v, "url.Values.Encode in the Graph connector: query encoding belongs to the odata primitive")
			case p == "net/http" && (fn.Name() == "NewRequest" || fn.Name() == "NewRequestWithContext" || fn.Name() == "ReadRequest") && !httpOK:
				report(pass, v, "http."+fn.Name()+" outside policy.GraphHTTPSite: a request is created only where the host is pinned")
			}
		case *ast.CallExpr:
			if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "new" && len(v.Args) == 1 && !httpOK {
				if _, isBuiltin := pass.TypesInfo.Uses[id].(*types.Builtin); isBuiltin && isHTTPNamed(pass.TypesInfo.TypeOf(v.Args[0]), "Request") {
					report(pass, v, "new(http.Request) outside policy.GraphHTTPSite: a request is created only where the host is pinned")
				}
			}
			fn := util.Callee(pass, v)
			if fn == nil || fn.Pkg() == nil || !httpOK || fn.Pkg().Path() != "net/http" {
				return true
			}
			if fn.Name() == "NewRequest" || fn.Name() == "NewRequestWithContext" {
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
