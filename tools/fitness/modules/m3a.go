package main

// M3a, TG2, TG3 and OW1 (ADR-0015). M3a is the first cut of ADR-0003 M3 (ADR-0015 D3):
//
//   - a module package imported outside the generated list of compose/server or compose/agent
//     (reported from checkImportRules as rule M3a);
//   - a module list that lacks the generated header, or differs from what tools/gen/modules produces;
//   - a module with no architecture page, or a page with no module.
//
// TG2, TG3 and OW1 are ADR-0015's template-gate and ownership rules. Each has a failing fixture in
// check_test.go. Debts that exist on the day a rule lands are listed in m3a-baseline.txt, one line each with
// the ticket that clears it; a baseline line that no longer matches a violation fails the build, so the
// file can only shrink.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/tools/gen/modules/modlist"
)

const (
	pagesDir      = "knowledge/development/architecture/modules"
	baselinePath  = "tools/fitness/modules/m3a-baseline.txt"
	tg3AllowPath  = "tools/fitness/modules/tg3-allowlist.txt"
	objectsPkg    = "internal/modules/objects"
	rbacPkg       = "internal/platform/rbac"
	moduleIDShape = `^[a-z][a-z0-9]{1,30}$`
)

var moduleID = regexp.MustCompile(moduleIDShape)

// readList reads a config file of `key # comment` lines; a missing file is an empty list.
func readList(root, rel string) (map[string]bool, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if os.IsNotExist(err) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line != "" {
			out[line] = true
		}
	}
	return out, nil
}

// checkM3a runs every rule of this file and applies the baseline.
func checkM3a(root, modPath string) ([]Violation, error) {
	base, err := readList(root, baselinePath)
	if err != nil {
		return nil, err
	}
	var all []Violation
	for _, f := range []func(string, string) ([]Violation, error){checkLists, checkPages, checkTG2, checkOW1} {
		vs, err := f(root, modPath)
		if err != nil {
			return nil, err
		}
		all = append(all, vs...)
	}
	// Baseline: a violation whose key is listed is a known debt; a listed key with no violation is stale.
	used := map[string]bool{}
	var out []Violation
	for _, v := range all {
		if k := baselineKey(v); k != "" && base[k] {
			used[k] = true
			continue
		}
		out = append(out, v)
	}
	var stale []string
	for k := range base {
		if !used[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	for _, k := range stale {
		out = append(out, Violation{Rule: "M3a", Pos: baselinePath, Msg: fmt.Sprintf("baseline entry %q matches no violation any more; delete the line (the baseline only shrinks)", k)})
	}
	tg3, err := checkTG3(root, modPath)
	if err != nil {
		return nil, err
	}
	return append(out, tg3...), nil
}

// baselineKey is the stable identity of a baselinable violation; "" means it cannot be baselined.
func baselineKey(v Violation) string {
	switch v.Rule {
	case "M3a-page":
		return "no-page " + v.Pos
	case "M3a-orphan":
		return "no-module " + v.Pos
	case "TG2":
		return "tg2 " + v.Pos
	}
	return ""
}

// checkLists is the header and regeneration half of M3a.
func checkLists(root, modPath string) ([]Violation, error) {
	l, err := modlist.Discover(root)
	if err != nil {
		return nil, err
	}
	server, agent := modlist.Render(modPath, l)
	var vs []Violation
	for _, f := range []struct {
		rel  string
		want []byte
		n    int
	}{{modlist.ServerFile, server, len(l.Server)}, {modlist.AgentFile, agent, len(l.Agent)}} {
		have, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.rel)))
		if os.IsNotExist(err) {
			if f.n > 0 {
				vs = append(vs, Violation{Rule: "M3a", Pos: f.rel, Msg: fmt.Sprintf("the module list is missing but %d module(s) exist; run `make gen-modules`", f.n)})
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		first, _, _ := bytes.Cut(have, []byte("\n"))
		if string(first) != modlist.Header {
			vs = append(vs, Violation{Rule: "M3a", Pos: f.rel + ":1", Msg: fmt.Sprintf("a module list must start with the generated header %q; hand-maintained lists are not allowed", modlist.Header)})
		}
		if !bytes.Equal(have, f.want) {
			vs = append(vs, Violation{Rule: "M3a", Pos: f.rel, Msg: "the module list is stale or hand-edited: it differs from what internal/modules and internal/agentmodules produce (run `make gen-modules`)"})
		}
	}
	return vs, nil
}

// moduleDirs returns the module IDs (directories holding Go code) under a root such as internal/modules.
func moduleDirs(root, dir string) ([]string, error) {
	es, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		if !e.IsDir() {
			continue
		}
		ok, err := hasGo(filepath.Join(root, filepath.FromSlash(dir), e.Name()))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// checkPages is module-has-page and page-has-module. Pages whose name is not a module ID (README, and
// the platform pages such as operation-persistence) are not module pages and are ignored.
func checkPages(root, _ string) ([]Violation, error) {
	have := map[string]string{} // id -> "server" | "agent"
	for _, r := range []struct{ dir, tier string }{{"internal/modules", "server"}, {"internal/agentmodules", "agent"}} {
		ids, err := moduleDirs(root, r.dir)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			have[id] = r.dir + "/" + id
		}
	}
	pages := map[string]bool{}
	es, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(pagesDir)))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range es {
		id, ok := strings.CutSuffix(e.Name(), ".md")
		if e.IsDir() || !ok || !moduleID.MatchString(id) {
			continue
		}
		pages[id] = true
	}
	if len(have) == 0 && len(pages) == 0 {
		return nil, nil
	}
	var vs []Violation
	for id, dir := range have {
		if !pages[id] {
			vs = append(vs, Violation{Rule: "M3a-page", Pos: id, Msg: fmt.Sprintf("module %s has no architecture page %s/%s.md", dir, pagesDir, id)})
		}
	}
	for id := range pages {
		if _, ok := have[id]; !ok {
			vs = append(vs, Violation{Rule: "M3a-orphan", Pos: id, Msg: fmt.Sprintf("%s/%s.md has no module internal/modules/%s or internal/agentmodules/%s", pagesDir, id, id, id)})
		}
	}
	return vs, nil
}

// parsedFile is one non-test Go file under internal/modules, fully parsed.
type parsedFile struct {
	rel  string
	pkg  string // repository-relative directory
	file *ast.File
	fset *token.FileSet
}

func loadModuleFiles(root string) ([]parsedFile, error) {
	var out []parsedFile
	base := filepath.Join(root, "internal", "modules")
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return nil, nil
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		out = append(out, parsedFile{rel: rel, pkg: path.Dir(rel), file: f, fset: fset})
		return nil
	})
	return out, err
}

// importName returns the local name a file gives to the import whose path ends with suffix, or "".
func importName(f *ast.File, suffix string) string {
	for _, is := range f.Imports {
		p, _ := strconv.Unquote(is.Path.Value)
		if p == suffix || strings.HasSuffix(p, "/"+suffix) {
			if is.Name != nil {
				return is.Name.Name
			}
			return path.Base(p)
		}
	}
	return ""
}

// fnInfo is what TG2 needs to know about one function (or Plan literal) that takes a PlanContext.
type fnInfo struct {
	name        string
	pos         token.Pos
	refsTpl     bool        // names objects.Template, objects.Templates or TemplateRef
	gatePos     token.Pos   // first Templates.CheckTemplate call, or NoPos
	guardedAt   []token.Pos // calls to CheckInput or Facts
	calls       []callSite  // calls of package-level functions by plain name
	hasPlanCtx  bool
	litInDecl   bool
	file        string
	fset        *token.FileSet
	transFacts  bool
	transTplRef bool
}

type callSite struct {
	name string
	pos  token.Pos
}

func hasPlanContextParam(ft *ast.FuncType) bool {
	if ft.Params == nil {
		return false
	}
	for _, p := range ft.Params.List {
		switch t := p.Type.(type) {
		case *ast.SelectorExpr:
			if t.Sel.Name == "PlanContext" {
				return true
			}
		case *ast.Ident:
			if t.Name == "PlanContext" {
				return true
			}
		}
	}
	return false
}

func analyse(pf parsedFile, name string, body *ast.BlockStmt, pos token.Pos, objName string) fnInfo {
	fi := fnInfo{name: name, pos: pos, hasPlanCtx: true, file: pf.rel, fset: pf.fset, gatePos: token.NoPos}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && objName != "" && id.Name == objName && (x.Sel.Name == "Template" || x.Sel.Name == "Templates") {
				fi.refsTpl = true
			}
			if x.Sel.Name == "TemplateRef" {
				fi.refsTpl = true
			}
		case *ast.Ident:
			if x.Name == "TemplateRef" {
				fi.refsTpl = true
			}
		case *ast.CallExpr:
			switch fn := x.Fun.(type) {
			case *ast.SelectorExpr:
				switch fn.Sel.Name {
				case "CheckTemplate":
					if inner, ok := fn.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "Templates" {
						if fi.gatePos == token.NoPos || x.Pos() < fi.gatePos {
							fi.gatePos = x.Pos()
						}
					}
				case "CheckInput", "Facts":
					fi.guardedAt = append(fi.guardedAt, x.Pos())
				}
			case *ast.Ident:
				fi.calls = append(fi.calls, callSite{fn.Name, x.Pos()})
			}
		}
		return true
	})
	return fi
}

// checkTG2: a Plan that touches a Template must call Templates.CheckTemplate before CheckInput or the
// first Facts (ADR-0015 D1 order). A "Plan" is a function or function literal with a PlanContext
// parameter that no other PlanContext function of its package calls by name; the helpers it calls
// (loadTemplate, deriveNames, readUser …) count as part of it, and a call to one that reaches Facts,
// CheckInput or a Template counts as that use at the call site.
func checkTG2(root, _ string) ([]Violation, error) {
	files, err := loadModuleFiles(root)
	if err != nil {
		return nil, err
	}
	byPkg := map[string][]parsedFile{}
	for _, pf := range files {
		byPkg[pf.pkg] = append(byPkg[pf.pkg], pf)
	}
	var vs []Violation
	for pkg, pfs := range byPkg {
		decls := map[string]*fnInfo{}
		var lits []*fnInfo
		for _, pf := range pfs {
			objName := importName(pf.file, objectsPkg)
			for _, d := range pf.file.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				if hasPlanContextParam(fd.Type) {
					fi := analyse(pf, fd.Name.Name, fd.Body, fd.Pos(), objName)
					if fd.Recv == nil {
						decls[fd.Name.Name] = &fi
					} else {
						lits = append(lits, &fi) // a method is its own root
					}
				}
			}
			// Plan func literals inside composite literals and calls: `Plan: func(ctx, pc operation.PlanContext, ...)`.
			ast.Inspect(pf.file, func(n ast.Node) bool {
				if kv, ok := n.(*ast.KeyValueExpr); ok {
					if lit, ok := kv.Value.(*ast.FuncLit); ok && hasPlanContextParam(lit.Type) {
						fi := analyse(pf, "Plan", lit.Body, lit.Pos(), objName)
						lits = append(lits, &fi)
					}
				}
				return true
			})
		}
		// Transitive reach through same-package PlanContext helpers.
		var reach func(name string, seen map[string]bool) (tpl, facts bool)
		reach = func(name string, seen map[string]bool) (bool, bool) {
			fi := decls[name]
			if fi == nil || seen[name] {
				return false, false
			}
			seen[name] = true
			tpl, facts := fi.refsTpl, len(fi.guardedAt) > 0
			for _, c := range fi.calls {
				t, f := reach(c.name, seen)
				tpl, facts = tpl || t, facts || f
			}
			return tpl, facts
		}
		called := map[string]bool{}
		for _, fi := range decls {
			for _, c := range fi.calls {
				if _, ok := decls[c.name]; ok {
					called[c.name] = true
				}
			}
		}
		for _, fi := range lits {
			for _, c := range fi.calls {
				if _, ok := decls[c.name]; ok {
					called[c.name] = true
				}
			}
		}
		roots := append([]*fnInfo{}, lits...)
		for name, fi := range decls {
			if !called[name] {
				roots = append(roots, fi)
			}
		}
		for _, fi := range roots {
			tpl := fi.refsTpl
			first := token.NoPos // first use that must come after the gate
			consider := func(p token.Pos) {
				if first == token.NoPos || p < first {
					first = p
				}
			}
			for _, p := range fi.guardedAt {
				consider(p)
			}
			for _, c := range fi.calls {
				t, f := reach(c.name, map[string]bool{})
				tpl = tpl || t
				if f || t {
					consider(c.pos)
				}
			}
			if !tpl {
				continue
			}
			pos := fi.fset.Position(fi.pos)
			where := fmt.Sprintf("%s:%s", fi.file, fi.name)
			switch {
			case fi.gatePos == token.NoPos:
				vs = append(vs, Violation{Rule: "TG2", Pos: where, Msg: fmt.Sprintf("%s:%d: %s uses a Template but never calls pc.Templates.CheckTemplate (ADR-0015 D1: TemplateGate, then CheckInput, then Render, then the first read)", fi.file, pos.Line, fi.name)})
			case first != token.NoPos && first < fi.gatePos:
				vs = append(vs, Violation{Rule: "TG2", Pos: where, Msg: fmt.Sprintf("%s:%d: %s calls CheckTemplate after a CheckInput, Facts or helper that reads (ADR-0015 D1 order)", fi.file, pos.Line, fi.name)})
			}
		}
		_ = pkg
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].Pos < vs[j].Pos })
	return vs, nil
}

// checkTG3: ad, objects and any module that imports objects must not import platform/rbac in non-test
// code, except the allowlisted rbac-wiring modules (tools/fitness/modules/tg3-allowlist.txt; adding to it
// needs an ADR amendment). ad and objects can never be allowlisted.
func checkTG3(root, modPath string) ([]Violation, error) {
	allow, err := readList(root, tg3AllowPath)
	if err != nil {
		return nil, err
	}
	pkgs, err := loadPackages(root, modPath)
	if err != nil {
		return nil, err
	}
	var vs []Violation
	for _, a := range []string{"ad", "objects"} {
		if allow[a] {
			vs = append(vs, Violation{Rule: "TG3", Pos: tg3AllowPath, Msg: fmt.Sprintf("module %s is a Template consumer or owner and cannot be on the TG3 allowlist", a)})
		}
	}
	scoped := map[string]string{"ad": "a Template consumer", "objects": "the Template owner"}
	for dir, pk := range pkgs {
		if !under(dir, "internal/modules") {
			continue
		}
		id := moduleOf(dir, "internal/modules")
		if id == "" || id == "objects" {
			continue
		}
		for _, ip := range pk.nonTest {
			if to := local(ip, modPath); under(to, objectsPkg) {
				if _, ok := scoped[id]; !ok && !allow[id] {
					scoped[id] = "a module that imports internal/modules/objects"
				}
			}
		}
	}
	for dir, pk := range pkgs {
		if !under(dir, "internal/modules") {
			continue
		}
		id := moduleOf(dir, "internal/modules")
		why, ok := scoped[id]
		if !ok || (allow[id] && id != "ad" && id != "objects") {
			continue
		}
		for _, i := range pk.imports {
			if i.test {
				continue
			}
			if under(local(i.path, modPath), rbacPkg) {
				vs = append(vs, Violation{Rule: "TG3", Pos: i.pos, Msg: fmt.Sprintf("module %s (%s) imports %s; a Template consumer authorises through pc.Templates, which compose/server binds to rbac (ADR-0015 D1)", id, why, rbacPkg)})
			}
		}
	}
	return vs, nil
}

// checkOW1: an Action whose ID starts with `objects.`, and every Descriptor in internal/modules/objects,
// must target the store (ADR-0015 D2: objects owns only store Actions on its own tables).
func checkOW1(root, _ string) ([]Violation, error) {
	files, err := loadModuleFiles(root)
	if err != nil {
		return nil, err
	}
	// package-level string constants, per directory, so `const idX = "objects.template.create"` resolves.
	consts := map[string]map[string]string{}
	for _, pf := range files {
		m := consts[pf.pkg]
		if m == nil {
			m = map[string]string{}
			consts[pf.pkg] = m
		}
		for _, d := range pf.file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if v, ok := stringValue(vs.Values[i], nil); ok {
							m[n.Name] = v
						}
					}
				}
			}
		}
	}
	var vs []Violation
	for _, pf := range files {
		inObjects := under(pf.pkg, objectsPkg)
		ast.Inspect(pf.file, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || !isDescriptorType(cl.Type) {
				return true
			}
			var id string
			hasID, store := false, false
			for _, el := range cl.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				switch key, _ := kv.Key.(*ast.Ident); {
				case key == nil:
				case key.Name == "ID":
					id, hasID = stringValue(kv.Value, consts[pf.pkg])
				case key.Name == "Target":
					if sel, ok := kv.Value.(*ast.SelectorExpr); ok && sel.Sel.Name == "TargetStore" {
						store = true
					}
				}
			}
			if (inObjects || (hasID && strings.HasPrefix(id, "objects."))) && !store {
				line := pf.fset.Position(cl.Pos()).Line
				vs = append(vs, Violation{Rule: "OW1", Pos: fmt.Sprintf("%s:%d", pf.rel, line), Msg: "an Action in the objects module (or with an objects.* ID) must declare Target: operation.TargetStore; the Actions that write a directory live with the module that owns the target (ADR-0015 D2)"})
			}
			return true
		})
	}
	return vs, nil
}

func isDescriptorType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		return t.Sel.Name == "Descriptor"
	case *ast.Ident:
		return t.Name == "Descriptor"
	}
	return false
}

// stringValue resolves a string literal, a conversion of one (ActionID("x")), a known constant, or a
// concatenation of those. consts may be nil.
func stringValue(e ast.Expr, consts map[string]string) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			s, err := strconv.Unquote(x.Value)
			return s, err == nil
		}
	case *ast.Ident:
		s, ok := consts[x.Name]
		return s, ok
	case *ast.ParenExpr:
		return stringValue(x.X, consts)
	case *ast.CallExpr:
		if len(x.Args) == 1 {
			return stringValue(x.Args[0], consts)
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			l, ok1 := stringValue(x.X, consts)
			r, ok2 := stringValue(x.Y, consts)
			if ok1 && ok2 {
				return l + r, true
			}
			if ok1 { // a known prefix is enough for the ID-prefix test
				return l, true
			}
		}
	}
	return "", false
}
