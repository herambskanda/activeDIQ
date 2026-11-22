// Package showdeleted is TM-F-RIGHTS (b) of the threat model (§6.3 TM-D33 "Fitness functions", T-2074):
// the show-deleted control (1.2.840.113556.1.4.417) is constructible only inside named connector
// functions, each with a fixed shape and each reachable only from an explicit caller allow-list.
//
// The named sites (internal/connector/ad), by role:
//
//   - (b1) Session.ReadDeletedTarget: base read of <GUID=…> built by dn.GUIDRef, controls 417, 2065,
//     extended DN and the default SD flags, attribute list exactly deletedTargetAttrs. Caller: the kind 6
//     step 7 classification (write.SessionObjects.DeletedTarget).
//   - (b2) Session.DeletedContainerDescriptor: base read of the container resolved by the Deleted
//     Objects WKGUID, attribute list exactly nTSecurityDescriptor, SD flags owner+DACL (0x5), no paged
//     results. Callers: kind 6 step 7's grant check (write.SessionObjects.DeletedContainer).
//   - (b3) Session.DeletedObjectState: base read of <GUID=…> with stateAttrs and 417 only.
//   - (w) Session.RestoreObject and its locked re-check readDeletedLocked: the undelete Modify itself.
//   - Pre-existing, listed so they cannot widen: dirSyncControls (tombstones for DirSync) and
//     Tx.ReadDeleted (kind 3's "already deleted" exemption).
//
// The pass reports:
//
//   - any reference to scope.ShowDeleted, outside a named construction site;
//   - any ReadOptions.showDeleted set other than false, outside (b1) and (b3);
//   - the control's OID spelled as a string literal outside the scope package;
//   - a call or reference to a named function from a function that is not on its caller allow-list;
//   - a named function (b1, b2, b3) whose body leaves its fixed shape: another search, a scope other
//     than base, an attribute list other than the fixed one, another control, paged results, a DN that
//     is not the typed GUID reference, SD flags other than the fixed ones;
//   - a caller of (b2) that also issues a modify (an owner or DACL write on the container).
//
// Tests and tier L are not judged. VerifyConnection R15 (b) (T-1735) extends the (b2) caller list
// when it lands.
package showdeleted

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/util"
)

const Name = "showdeleted"

var Analyzer = &analysis.Analyzer{
	Name: Name,
	Doc:  "TM-F-RIGHTS (b): the show-deleted control is constructed only in the named, fixed-shape connector functions and called only from their allow-lists",
	Run:  run,
}

var (
	adDir    = "internal/connector/ad"
	writeDir = "internal/connector/write"
)

func init() {
	Analyzer.Flags.StringVar(&adDir, "ad", adDir, "directory of the connector package that holds the named sites")
	Analyzer.Flags.StringVar(&writeDir, "write", writeDir, "directory of the package that holds the caller allow-list")
}

const (
	scopeDir = "internal/connector/ad/scope"
	dnDir    = "internal/directory/dn"
	oidShow  = "1.2.840.113556.1.4.417"
)

// ctorSites may reference scope.ShowDeleted.
var ctorSites = map[string]bool{
	"visibilityControls":                 true, // builds the controls of ReadOptions; sinks are (b1) and (b3)
	"Session.DeletedContainerDescriptor": true, // (b2)
	"Session.readDeletedLocked":          true, // (w) re-check
	"Session.RestoreObject":              true, // (w)
	"dirSyncControls":                    true, // DirSync tombstones
	"Tx.ReadDeleted":                     true, // kind 3 step 7 exemption
}

// optionSites may set ReadOptions.showDeleted.
var optionSites = map[string]bool{"Session.ReadDeletedTarget": true, "Session.DeletedObjectState": true}

// callers maps a guarded function (by name, package role) to the functions allowed to use it.
// Keys are "ad:<name>" or "write:<name>"; values are "ad:<func>" or "write:<func>".
var callers = map[string][]string{
	"ad:ReadDeletedTarget":                      {"write:SessionObjects.DeletedTarget"},
	"ad:DeletedContainerDescriptor":             {"write:SessionObjects.DeletedContainer"},
	"ad:DeletedObjectState":                     {"write:SessionObjects.DeletedState"},
	"ad:RestoreObject":                          {"write:SessionObjects.Restore"},
	"ad:readDeletedLocked":                      {"ad:Session.RestoreObject"},
	"ad:ReadDeleted":                            {"write:targetDeleted", "write:readForDelete"},
	"write:StructureDirectory.DeletedTarget":    {"write:ADProvider.classifyDeleted"},
	"write:StructureDirectory.DeletedContainer": {"write:ADProvider.proveListContents"},
	"write:StructureDirectory.DeletedState":     {"write:restoreState", "write:applyRestore"},
	"write:StructureDirectory.Restore":          {"write:applyRestore"},
}

func run(pass *analysis.Pass) (any, error) {
	dir := util.PkgDir(pass)
	for _, f := range pass.Files {
		if util.SkipFile(pass, f) {
			continue
		}
		role := roleOf(dir)
		checkLiterals(pass, f, dir)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				checkTop(pass, d, role)
				continue
			}
			key := funcKey(fd)
			checkBody(pass, fd, role, key)
			noContainerWrite(pass, fd)
			if role == "ad" {
				switch key {
				case "Session.ReadDeletedTarget":
					shapeB1(pass, fd)
				case "Session.DeletedContainerDescriptor":
					shapeB2(pass, fd)
				case "Session.DeletedObjectState":
					shapeB3(pass, fd)
				}
			}
		}
	}
	return nil, nil
}

func roleOf(dir string) string {
	switch dir {
	case adDir:
		return "ad"
	case writeDir:
		return "write"
	}
	return ""
}

func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return recvName(fd.Recv.List[0].Type) + "." + fd.Name.Name
}

func recvName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvName(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return recvName(x.X)
	}
	return "?"
}

// checkTop judges package-level declarations (variable initialisers): no named site is a var.
func checkTop(pass *analysis.Pass, d ast.Decl, role string) {
	check(pass, d, role, "", true)
}

func checkBody(pass *analysis.Pass, fd *ast.FuncDecl, role, key string) {
	check(pass, fd.Body, role, key, false)
}

func check(pass *analysis.Pass, root ast.Node, role, key string, top bool) {
	ast.Inspect(root, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			use(pass, x, role, key, top)
		case *ast.KeyValueExpr:
			if id, ok := x.Key.(*ast.Ident); ok && isShowDeletedField(pass, id) && !isFalse(pass, x.Value) {
				if !(role == "ad" && optionSites[key]) {
					pass.Reportf(id.Pos(), "ReadOptions.showDeleted set outside (b1) ReadDeletedTarget and (b3) DeletedObjectState: Session.Read must not gain the show-deleted control (TM-F-RIGHTS (b))")
				}
			}
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if sel, ok := l.(*ast.SelectorExpr); ok && isShowDeletedField(pass, sel.Sel) {
					pass.Reportf(sel.Pos(), "ReadOptions.showDeleted assigned: it is set only by a literal in (b1) and (b3) (TM-F-RIGHTS (b))")
				}
			}
		}
		return true
	})
}

func isShowDeletedField(pass *analysis.Pass, id *ast.Ident) bool {
	if id.Name != "showDeleted" {
		return false
	}
	v, ok := pass.TypesInfo.Uses[id].(*types.Var)
	// Only the connector's ReadOptions field; another struct's field of the same name is not the control.
	return ok && v.IsField() && v.Pkg() != nil && util.TypesPkgDir(pass, v.Pkg()) == adDir
}

func isFalse(pass *analysis.Pass, e ast.Expr) bool {
	tv, ok := pass.TypesInfo.Types[e]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.Bool && !constant.BoolVal(tv.Value)
}

// use judges one identifier that resolves to a guarded function or the control constructor.
func use(pass *analysis.Pass, id *ast.Ident, role, key string, top bool) {
	obj := pass.TypesInfo.Uses[id]
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return
	}
	pdir := util.TypesPkgDir(pass, fn.Pkg())
	if pdir == scopeDir && fn.Name() == "ShowDeleted" {
		if !(role == "ad" && ctorSites[key]) {
			pass.Reportf(id.Pos(), "scope.ShowDeleted outside a named construction site (%s): the show-deleted control exists only in the fixed-shape deleted reads (TM-F-RIGHTS (b))", sitesList())
		}
		return
	}
	var g string
	switch {
	case pdir == adDir:
		g = "ad:" + fn.Name()
	case pdir == writeDir && isDeleteTxMethod(fn) && fn.Name() == "ReadDeleted":
		g = "ad:ReadDeleted"
	case pdir == writeDir:
		g = "write:" + wrapperName(fn)
	default:
		return
	}
	allowed, guarded := callers[g]
	if !guarded {
		return
	}
	// Methods on other types that merely share the name are not guarded.
	if g == "ad:ReadDeleted" && !isTxMethod(fn) && !isDeleteTxMethod(fn) {
		return
	}
	if !top && role != "" {
		me := role + ":" + key
		for _, a := range allowed {
			if a == me {
				return
			}
		}
	}
	pass.Reportf(id.Pos(), "%s is on the show-deleted caller allow-list (%s); %s is not on it (TM-F-RIGHTS (b))", fn.Name(), strings.Join(allowed, ", "), nameOf(role, key))
}

func nameOf(role, key string) string {
	if key == "" {
		return "a package-level declaration"
	}
	return key
}

func sitesList() string {
	var s []string
	for k := range ctorSites {
		s = append(s, k)
	}
	// deterministic order for the message
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	return strings.Join(s, ", ")
}

// wrapperName is "StructureDirectory.DeletedTarget" for a method of the kind-6 directory interface or
// of its session implementation, else the plain name.
func wrapperName(fn *types.Func) string {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return fn.Name()
	}
	t := sig.Recv().Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := types.Unalias(t).(*types.Named); ok && (n.Obj().Name() == "StructureDirectory" || n.Obj().Name() == "SessionObjects") {
		return "StructureDirectory." + fn.Name()
	}
	return fn.Name()
}

func isTxMethod(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	t := sig.Recv().Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Name() == "Tx"
}

func isDeleteTxMethod(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	n, ok := types.Unalias(sig.Recv().Type()).(*types.Named)
	return ok && n.Obj().Name() == "deleteTx"
}

// checkLiterals reports the OID spelled out anywhere but the scope package.
func checkLiterals(pass *analysis.Pass, f *ast.File, dir string) {
	if dir == scopeDir {
		return
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING && strings.Contains(bl.Value, oidShow) {
			pass.Reportf(bl.Pos(), "the show-deleted OID is spelled out: only scope.ShowDeleted builds the control (TM-F-RIGHTS (b))")
		}
		return true
	})
}

// noContainerWrite: a function that reads the Deleted Objects container's descriptor (b2, directly
// or through the kind-6 directory interface) issues no modify and no owner or DACL write; the
// container's owner and DACL are never ours to change (TM-D33 rule 4).
func noContainerWrite(pass *analysis.Pass, fd *ast.FuncDecl) {
	reads := false
	var writes []*ast.CallExpr
	for _, c := range calls(pass, fd.Body) {
		fn := calleeObj(pass, c)
		if fn == nil {
			continue
		}
		if fn.Name() == "DeletedContainerDescriptor" || fn.Name() == "DeletedContainer" {
			reads = true
		}
		n := strings.ToLower(fn.Name())
		sdish := strings.Contains(n, "sd") || strings.Contains(n, "owner") || strings.Contains(n, "dacl") || strings.Contains(n, "descriptor")
		if strings.Contains(n, "modify") || (sdish && (strings.HasPrefix(n, "set") || strings.HasPrefix(n, "write") || strings.HasPrefix(n, "replace") || strings.HasPrefix(n, "apply"))) {
			writes = append(writes, c)
		}
	}
	if reads {
		for _, w := range writes {
			pass.Reportf(w.Pos(), "%s reads the Deleted Objects container descriptor and also writes: no owner or DACL write on the container (TM-F-RIGHTS (b))", funcKey(fd))
		}
	}
}
