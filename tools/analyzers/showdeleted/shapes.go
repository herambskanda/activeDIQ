package showdeleted

import (
	"go/ast"
	"go/constant"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/util"
)

// calleeObj resolves the function a call expression names.
func calleeObj(pass *analysis.Pass, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch f := call.Fun.(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	default:
		return nil
	}
	fn, _ := pass.TypesInfo.Uses[id].(*types.Func)
	return fn
}

func calls(pass *analysis.Pass, body *ast.BlockStmt) (out []*ast.CallExpr) {
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			out = append(out, c)
		}
		return true
	})
	return out
}

// isCall reports whether e is a call of the function name in the package at dir.
func isCall(pass *analysis.Pass, e ast.Expr, dir, name string) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	fn := calleeObj(pass, c)
	return fn != nil && fn.Name() == name && fn.Pkg() != nil && util.TypesPkgDir(pass, fn.Pkg()) == dir
}

// isPkgVar reports whether e names the package-level variable name of this package.
func isPkgVar(pass *analysis.Pass, e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	if !ok || id.Name != name {
		return false
	}
	v, ok := pass.TypesInfo.Uses[id].(*types.Var)
	return ok && v.Parent() == v.Pkg().Scope()
}

// optionsLiteral returns the keys of a ReadOptions composite literal and its elements by key.
func optionsLiteral(pass *analysis.Pass, e ast.Expr) (map[string]ast.Expr, bool) {
	cl, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	t := pass.TypesInfo.TypeOf(cl)
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Name() != "ReadOptions" {
		return nil, false
	}
	m := map[string]ast.Expr{}
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			return nil, false
		}
		id, ok := kv.Key.(*ast.Ident)
		if !ok {
			return nil, false
		}
		m[id.Name] = kv.Value
	}
	return m, true
}

func isTrue(pass *analysis.Pass, e ast.Expr) bool {
	tv, ok := pass.TypesInfo.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.Bool && constant.BoolVal(tv.Value)
}

// readCalls are the calls that can reach the wire with a search: Read, any search*, any paged helper.
func readCalls(pass *analysis.Pass, fd *ast.FuncDecl) (out []*ast.CallExpr) {
	for _, c := range calls(pass, fd.Body) {
		fn := calleeObj(pass, c)
		if fn == nil {
			continue
		}
		n := strings.ToLower(fn.Name())
		if n == "read" || strings.Contains(n, "search") || strings.Contains(n, "pag") || strings.Contains(n, "modify") {
			out = append(out, c)
		}
	}
	return out
}

// fixedRead checks the one Session.Read call of (b1) and (b3): <GUID=…> from dn.GUIDRef, the named
// attribute variable, and a ReadOptions literal with exactly the given keys.
func fixedRead(pass *analysis.Pass, fd *ast.FuncDecl, role, attrsVar string, keys map[string]string) {
	rc := readCalls(pass, fd)
	if len(rc) != 1 {
		pass.Reportf(fd.Name.Pos(), "%s (%s) must make exactly one base read; it makes %d search-like calls (TM-F-RIGHTS (b))", fd.Name.Name, role, len(rc))
		return
	}
	c := rc[0]
	if fn := calleeObj(pass, c); fn == nil || fn.Name() != "Read" || len(c.Args) != 4 {
		pass.Reportf(c.Pos(), "%s (%s): the read is not Session.Read(ctx, ref, attrs, options) (TM-F-RIGHTS (b))", fd.Name.Name, role)
		return
	}
	if !isCall(pass, c.Args[1], dnDir, "GUIDRef") {
		pass.Reportf(c.Args[1].Pos(), "%s (%s): the base must be dn.GUIDRef(guid), the typed GUID reference, not a string or a DN (TM-F-RIGHTS (b))", fd.Name.Name, role)
	}
	if !isPkgVar(pass, c.Args[2], attrsVar) {
		pass.Reportf(c.Args[2].Pos(), "%s (%s): the attribute list must be the fixed %s (TM-F-RIGHTS (b))", fd.Name.Name, role, attrsVar)
	}
	lit, ok := optionsLiteral(pass, c.Args[3])
	if !ok {
		pass.Reportf(c.Args[3].Pos(), "%s (%s): the options must be a ReadOptions literal (TM-F-RIGHTS (b))", fd.Name.Name, role)
		return
	}
	for k, v := range lit {
		want, okk := keys[k]
		switch {
		case !okk:
			pass.Reportf(c.Args[3].Pos(), "%s (%s): ReadOptions.%s is not part of the fixed shape (TM-F-RIGHTS (b))", fd.Name.Name, role, k)
		case want == "true" && !isTrue(pass, v):
			pass.Reportf(v.Pos(), "%s (%s): ReadOptions.%s must be true (TM-F-RIGHTS (b))", fd.Name.Name, role, k)
		case want != "true" && !isCall(pass, v, adDir, want):
			pass.Reportf(v.Pos(), "%s (%s): ReadOptions.%s must be %s() (TM-F-RIGHTS (b))", fd.Name.Name, role, k, want)
		}
	}
	for k := range keys {
		if _, ok := lit[k]; !ok {
			pass.Reportf(c.Args[3].Pos(), "%s (%s): ReadOptions.%s is missing from the fixed shape (TM-F-RIGHTS (b))", fd.Name.Name, role, k)
		}
	}
}

// (b1): critical 417 + 2065 + SD_FLAGS (default 0x7) + extended DN, attribute list deletedTargetAttrs.
func shapeB1(pass *analysis.Pass, fd *ast.FuncDecl) {
	fixedRead(pass, fd, "b1", "deletedTargetAttrs", map[string]string{
		"showDeleted": "true", "ShowDeactivatedLink": "true", "ExtendedDN": "true", "SD": "DefaultSDFlags"})
}

// (b3): 417 only, attribute list stateAttrs.
func shapeB3(pass *analysis.Pass, fd *ast.FuncDecl) {
	fixedRead(pass, fd, "b3", "stateAttrs", map[string]string{"showDeleted": "true"})
}

// (b2): one searchOnceLocked, base scope, objectClassPresent filter, exactly nTSecurityDescriptor, controls
// exactly {SD flags owner+DACL, scope.ShowDeleted()}, no paged results; the container DN comes from
// wellKnownDN with the Deleted Objects WKGUID; the only other read is the domain head's wellKnownObjects.
func shapeB2(pass *analysis.Pass, fd *ast.FuncDecl) {
	var search *ast.CallExpr
	for _, c := range readCalls(pass, fd) {
		fn := calleeObj(pass, c)
		switch fn.Name() {
		case "searchOnceLocked":
			if search != nil {
				pass.Reportf(c.Pos(), "(b2) makes a second search (TM-F-RIGHTS (b))")
			}
			search = c
		case "Read":
			if !headRead(pass, c) {
				pass.Reportf(c.Pos(), "(b2): the only other read is the domain head's wellKnownObjects with empty options (TM-F-RIGHTS (b))")
			}
		default:
			pass.Reportf(c.Pos(), "(b2) calls %s: no paged, subtree or other search belongs in the container descriptor read (TM-F-RIGHTS (b))", fn.Name())
		}
	}
	if search == nil {
		pass.Reportf(fd.Name.Pos(), "(b2) DeletedContainerDescriptor has no searchOnceLocked call (TM-F-RIGHTS (b))")
		return
	}
	if len(search.Args) != 6 {
		pass.Reportf(search.Pos(), "(b2): searchOnceLocked has an unexpected signature (TM-F-RIGHTS (b))")
		return
	}
	// args: ctx, base, scope, filter, attrs, controls
	if !isScopeBase(pass, search.Args[2]) {
		pass.Reportf(search.Args[2].Pos(), "(b2): the search must be base scope (ldap.ScopeBaseObject) (TM-F-RIGHTS (b))")
	}
	if !isNTSDOnly(pass, search.Args[4]) {
		pass.Reportf(search.Args[4].Pos(), "(b2): the attribute list must be exactly []string{\"nTSecurityDescriptor\"} (TM-F-RIGHTS (b))")
	}
	if !wkguidBase(pass, fd, search.Args[1]) {
		pass.Reportf(search.Args[1].Pos(), "(b2): the base must be the container DN resolved by wellKnownDN with WKGUIDDeletedObjects (TM-F-RIGHTS (b))")
	}
	cl, ok := search.Args[5].(*ast.CompositeLit)
	if !ok || len(cl.Elts) != 2 {
		pass.Reportf(search.Args[5].Pos(), "(b2): the controls must be exactly the SD flags control and scope.ShowDeleted() (TM-F-RIGHTS (b))")
		return
	}
	if !isCall(pass, cl.Elts[1], scopeDir, "ShowDeleted") {
		pass.Reportf(cl.Elts[1].Pos(), "(b2): the second control must be scope.ShowDeleted() (TM-F-RIGHTS (b))")
	}
	if !sdFlagsOwnerDACL(pass, fd, cl.Elts[0]) {
		pass.Reportf(cl.Elts[0].Pos(), "(b2): SD_FLAGS must be NewSDFlags(SDOwner, SDDACL), 0x5 exactly (TM-F-RIGHTS (b))")
	}
}

func headRead(pass *analysis.Pass, c *ast.CallExpr) bool {
	if len(c.Args) != 4 || !isCall(pass, c.Args[1], dnDir, "DNRef") {
		return false
	}
	cl, ok := c.Args[2].(*ast.CompositeLit)
	if !ok || len(cl.Elts) != 1 || strLit(pass, cl.Elts[0]) != "wellKnownObjects" {
		return false
	}
	lit, ok := optionsLiteral(pass, c.Args[3])
	return ok && len(lit) == 0
}

func strLit(pass *analysis.Pass, e ast.Expr) string {
	tv, ok := pass.TypesInfo.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "\x00"
	}
	return constant.StringVal(tv.Value)
}

func isScopeBase(pass *analysis.Pass, e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "ScopeBaseObject"
}

func isNTSDOnly(pass *analysis.Pass, e ast.Expr) bool {
	cl, ok := e.(*ast.CompositeLit)
	return ok && len(cl.Elts) == 1 && strLit(pass, cl.Elts[0]) == "nTSecurityDescriptor"
}

// wkguidBase: the base argument is <container>.String() where container was assigned from a
// wellKnownDN call whose second argument is the constant WKGUIDDeletedObjects.
func wkguidBase(pass *analysis.Pass, fd *ast.FuncDecl, base ast.Expr) bool {
	c, ok := base.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "String" {
		return false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := calleeObj(pass, call)
		if fn == nil || fn.Name() != "wellKnownDN" || len(call.Args) != 2 {
			return true
		}
		id, ok := call.Args[1].(*ast.Ident)
		if !ok || id.Name != "WKGUIDDeletedObjects" {
			return true
		}
		if k, ok := pass.TypesInfo.Uses[id].(*types.Const); !ok || k.Pkg() != pass.Pkg {
			return true
		}
		for _, l := range as.Lhs {
			if li, ok := l.(*ast.Ident); ok && li.Name == recv.Name {
				found = true
			}
		}
		return true
	})
	return found
}

// sdFlagsOwnerDACL: the element is <v>.control() and <v> was assigned from NewSDFlags whose
// constant part arguments are exactly owner (1) and DACL (4).
func sdFlagsOwnerDACL(pass *analysis.Pass, fd *ast.FuncDecl, e ast.Expr) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "control" {
		return false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	good, bad := false, false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
			return true
		}
		li, ok := as.Lhs[0].(*ast.Ident)
		if !ok || li.Name != recv.Name {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || !isCall(pass, call, adDir, "NewSDFlags") {
			bad = true
			return true
		}
		var sum int64
		for _, a := range call.Args {
			tv, ok := pass.TypesInfo.Types[a]
			if !ok || tv.Value == nil {
				bad = true
				return true
			}
			v, _ := constant.Int64Val(constant.ToInt(tv.Value))
			sum |= v
		}
		if sum == 0x5 {
			good = true
		} else {
			bad = true
		}
		return true
	})
	return good && !bad
}
