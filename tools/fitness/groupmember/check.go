package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Violation struct{ Check, Where, Msg string }

func (v Violation) String() string { return fmt.Sprintf("%s %s: %s", v.Where, v.Check, v.Msg) }

// Generated is what the compiled proto says.
type Generated struct{ Kinds, Arms map[string]int32 }

const (
	docPath     = "knowledge/development/architecture/connector-contract.md"
	tmPath      = "knowledge/development/architecture/threat-model.md"
	kindTblPath = "internal/directory/client/write.go"
	closedTest  = "internal/directory/client/write_test.go"
	reservedT   = "internal/proto/activediq/connector/v1/reserved_test.go"
)

var groupPerms = map[string]bool{"objects.group.add_member": true, "objects.group.nest": true, "objects.group.remove_member": true}

const computerPerm = "objects.computer.reset_account"

type docKind struct {
	Num      int32
	Kind     string // OBJECT_CREATE
	Arm      string // object_create
	DigestID string // ad.object.create
}

var rowRE = regexp.MustCompile("^\\| (\\d+) \\| `([A-Z_]+)` / `([a-z_]+)` \\| `([^`]+)` \\|")

func parseDoc(root string) ([]docKind, error) {
	b, err := os.ReadFile(filepath.Join(root, docPath))
	if err != nil {
		return nil, err
	}
	var out []docKind
	for _, l := range strings.Split(string(b), "\n") {
		if m := rowRE.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			out = append(out, docKind{int32(n), m[2], m[3], m[4]})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no §8.10.1 kind rows found", docPath)
	}
	return out, nil
}

func parseFile(path string) (*ast.File, *token.FileSet, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	return f, fset, err
}

func line(fset *token.FileSet, p token.Pos, rel string) string {
	return rel + ":" + strconv.Itoa(fset.Position(p).Line)
}

// Run executes GM1-GM4 against the tree at root.
func Run(root string, gen Generated) (vs []Violation, pending []string, err error) {
	kinds, err := parseDoc(root)
	if err != nil {
		return nil, nil, err
	}
	v4, err := gm4(root, kinds, gen)
	if err != nil {
		return nil, nil, err
	}
	v2, err := gm2(root, kinds)
	if err != nil {
		return nil, nil, err
	}
	v3, p3, err := gm3(root)
	if err != nil {
		return nil, nil, err
	}
	v1, p1, err := gm1(root)
	if err != nil {
		return nil, nil, err
	}
	vs = append(append(append(v1, v2...), v3...), v4...)
	return vs, append(p1, p3...), nil
}

// GM4: enum and oneof arms against §8.10.1, and the reserved_test.go list against §8.10.1.
func gm4(root string, kinds []docKind, gen Generated) ([]Violation, error) {
	var vs []Violation
	for _, k := range kinds {
		if n, ok := gen.Kinds["WRITE_KIND_"+k.Kind]; !ok || n != k.Num {
			vs = append(vs, Violation{"GM4", docPath, fmt.Sprintf("WriteKind WRITE_KIND_%s must be %d (§8.10.1 row %d), generated enum has %d (present: %v)", k.Kind, k.Num, k.Num, n, ok)})
		}
		if n, ok := gen.Arms[k.Arm]; !ok || n != k.Num {
			vs = append(vs, Violation{"GM4", docPath, fmt.Sprintf("WriteKind %s has no WriteChange arm %q numbered %d", k.Kind, k.Arm, k.Num)})
		}
	}
	docKinds := map[string]bool{}
	for _, k := range kinds {
		docKinds["WRITE_KIND_"+k.Kind] = true
	}
	for name, n := range gen.Kinds {
		if n != 0 && !docKinds[name] {
			vs = append(vs, Violation{"GM4", docPath, fmt.Sprintf("generated %s=%d has no §8.10.1 row; no WriteChange arm of that number is listed", name, n)})
		}
	}
	f, fset, err := parseFile(filepath.Join(root, reservedT))
	if err != nil {
		return nil, err
	}
	got := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "TestWriteKindList" {
			return true
		}
		ast.Inspect(fd, func(m ast.Node) bool {
			kv, ok := m.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			sel, ok1 := kv.Key.(*ast.SelectorExpr)
			lit, ok2 := kv.Value.(*ast.BasicLit)
			if ok1 && ok2 && strings.HasPrefix(sel.Sel.Name, "WriteKind_WRITE_KIND_") {
				s, _ := strconv.Unquote(lit.Value)
				got[strings.TrimPrefix(sel.Sel.Name, "WriteKind_WRITE_KIND_")] = s
			}
			return true
		})
		return false
	})
	if len(got) == 0 {
		vs = append(vs, Violation{"GM4", reservedT, "TestWriteKindList (the pinned kind list) not found"})
	}
	_ = fset
	for _, k := range kinds {
		if got[k.Kind] != k.Arm {
			vs = append(vs, Violation{"GM4", reservedT, fmt.Sprintf("TestWriteKindList lacks %s -> %q from §8.10.1", k.Kind, k.Arm)})
		}
	}
	docByKind := map[string]bool{}
	for _, k := range kinds {
		docByKind[k.Kind] = true
	}
	for k := range got {
		if !docByKind[k] {
			vs = append(vs, Violation{"GM4", reservedT, "TestWriteKindList lists " + k + ", which is not in §8.10.1"})
		}
	}
	return vs, nil
}

var wiredKinds = []struct{ Const, Key string }{
	{"WriteKind_WRITE_KIND_GROUP_MEMBER_ADD", "ad.group.addMember"},
	{"WriteKind_WRITE_KIND_GROUP_MEMBER_REMOVE", "ad.group.removeMember"},
	{"WriteKind_WRITE_KIND_COMPUTER_ACCOUNT_RESET", "ad.computer.resetAccount"},
}

// GM2: TestKindTableClosed lists exactly the §8.10.1 keys; a wired kind 11-13 has a kindTable row with a class.
func gm2(root string, kinds []docKind) ([]Violation, error) {
	var vs []Violation
	f, fset, err := parseFile(filepath.Join(root, closedTest))
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "TestKindTableClosed" {
			return true
		}
		found = true
		ast.Inspect(fd, func(m ast.Node) bool {
			if lit, ok := m.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				s, _ := strconv.Unquote(lit.Value)
				if strings.HasPrefix(s, "ad.") {
					allowed[s] = true
				}
			}
			return true
		})
		return false
	})
	if !found {
		return append(vs, Violation{"GM2", closedTest, "TestKindTableClosed not found"}), nil
	}
	_ = fset
	want := map[string]bool{}
	for _, k := range kinds {
		want[k.DigestID] = true
		if !allowed[k.DigestID] {
			vs = append(vs, Violation{"GM2", closedTest, fmt.Sprintf("TestKindTableClosed's list lacks %q (§8.10.1 row %d)", k.DigestID, k.Num)})
		}
	}
	for k := range allowed {
		if !want[k] {
			vs = append(vs, Violation{"GM2", closedTest, fmt.Sprintf("TestKindTableClosed accepts %q, which is outside the %d keys of §8.10.1", k, len(kinds))})
		}
	}
	// Wired: the WriteKind constant is used by non-test, non-generated code outside the table itself.
	wired := map[string]bool{}
	err = walkGo(root, func(rel string, f *ast.File, fset *token.FileSet) {
		if strings.HasSuffix(rel, "_test.go") || strings.HasSuffix(rel, ".pb.go") || rel == kindTblPath ||
			strings.HasPrefix(rel, "internal/proto/") || strings.HasPrefix(rel, "tools/") {
			return
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok {
				for _, w := range wiredKinds {
					if s.Sel.Name == w.Const {
						wired[w.Const] = true
					}
				}
			}
			return true
		})
	})
	if err != nil {
		return nil, err
	}
	tf, tfset, err := parseFile(filepath.Join(root, kindTblPath))
	if err != nil {
		return nil, err
	}
	rows := map[string]bool{}    // WriteKind constants with a Class in kindTable
	noClass := map[string]bool{} // rows with no class
	ast.Inspect(tf, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		kind, class := "", false
		for _, e := range cl.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok {
					switch id.Name {
					case "Kind":
						if s, ok := kv.Value.(*ast.SelectorExpr); ok {
							kind = s.Sel.Name
						}
					case "Class":
						class = true
						if l, ok := kv.Value.(*ast.BasicLit); ok && (l.Value == `""`) {
							class = false
						}
					}
				}
			}
		}
		if kind != "" {
			if class {
				rows[kind] = true
			} else {
				noClass[kind] = true
			}
		}
		return true
	})
	// Kind 13 gets its row from the init loop over accountkind.Specs(); its TM-D28 class is the
	// kindClass entry keyed accountkind.KeyComputerReset, so a non-empty class there is the row's class.
	ast.Inspect(tf, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if sel, ok := kv.Key.(*ast.SelectorExpr); ok && sel.Sel.Name == "KeyComputerReset" {
				if l, ok := kv.Value.(*ast.BasicLit); ok && l.Value != `""` {
					rows["WriteKind_WRITE_KIND_COMPUTER_ACCOUNT_RESET"] = true
				}
			}
		}
		return true
	})
	for _, w := range wiredKinds {
		switch {
		case noClass[w.Const]:
			vs = append(vs, Violation{"GM2", kindTblPath, fmt.Sprintf("kindTable row for %s has no class (TM §6.9 rule 4)", w.Key)})
		case wired[w.Const] && !rows[w.Const]:
			vs = append(vs, Violation{"GM2", kindTblPath, fmt.Sprintf("%s is wired (used outside the table) but kindTable has no row for %s", w.Const, w.Key)})
		}
	}
	_ = tfset
	return vs, nil
}

var guardedRE = regexp.MustCompile("(?s)```guarded-v1\n(.*?)```")

// GM3: the document block carries the B1 keys; B4 for ComputerReset; Go table pending until it lands.
func gm3(root string) ([]Violation, []string, error) {
	var vs []Violation
	var pending []string
	b, err := os.ReadFile(filepath.Join(root, tmPath))
	if err != nil {
		return nil, nil, err
	}
	m := guardedRE.FindSubmatch(b)
	if m == nil {
		return []Violation{{"GM3", tmPath, "no guarded-v1 block"}}, nil, nil
	}
	classes := map[string]string{}
	for _, l := range strings.Split(string(m[1]), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok {
			classes[strings.TrimSpace(k)] = v
		}
	}
	if !strings.Contains(classes["reset_password"], "unicodePwd[user]") {
		vs = append(vs, Violation{"GM3", tmPath, "guarded-v1: reset_password must key unicodePwd[user] (B1 key with target class)"})
	}
	if strings.TrimSpace(classes["reset_computer"]) != "unicodePwd[computer]" {
		vs = append(vs, Violation{"GM3", tmPath, "guarded-v1: reset_computer must be exactly unicodePwd[computer] (B1 key with target class)"})
	}
	for c, v := range classes {
		if c != "reset_password" && strings.Contains(v, "unicodePwd") && c != "reset_computer" {
			vs = append(vs, Violation{"GM3", tmPath, "guarded-v1: unicodePwd appears under class " + c})
		}
	}
	if _, err := os.Stat(filepath.Join(root, "internal/directory/guarded")); err != nil {
		pending = append(pending, "GM3 Go table == guarded-v1 (internal/directory/guarded not landed)")
		return vs, pending, nil
	}
	// The Go side: the table must spell both keys.
	var src strings.Builder
	_ = walkGo(root, func(rel string, f *ast.File, fset *token.FileSet) {
		if strings.HasPrefix(rel, "internal/directory/guarded/") && !strings.HasSuffix(rel, "_test.go") {
			ast.Inspect(f, func(n ast.Node) bool {
				if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING {
					src.WriteString(l.Value + "\n")
				}
				return true
			})
		}
	})
	for _, key := range []string{"unicodePwd[user]", "unicodePwd[computer]"} {
		if !strings.Contains(src.String(), key) {
			vs = append(vs, Violation{"GM3", "internal/directory/guarded", "Go table lacks the key " + key + " that guarded-v1 carries"})
		}
	}
	// B4: a file that calls ComputerReset declares objects.computer.reset_account and no other permission.
	err = walkGo(root, func(rel string, f *ast.File, fset *token.FileSet) {
		if strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "internal/directory/guarded/") || strings.HasPrefix(rel, "tools/") {
			return
		}
		var call token.Pos
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "ComputerReset" {
					call = c.Pos()
				}
			}
			return true
		})
		if call == token.NoPos {
			return
		}
		perms := descriptorPerms(root, f)
		if len(perms) == 0 || len(perms) > 1 || perms[0] != computerPerm {
			vs = append(vs, Violation{"GM3", line(fset, call, rel), fmt.Sprintf("guarded.ComputerReset() reached by an Action declaring %v, want exactly [%s] (B4)", perms, computerPerm)})
		}
	})
	return vs, pending, err
}

// constStrings resolves package-level string constants of one directory (and the file) by identifier name.
func constStrings(dir string) map[string]string {
	out := map[string]string{}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, _, err := parseFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vsp := sp.(*ast.ValueSpec)
				for i, nm := range vsp.Names {
					if i < len(vsp.Values) {
						if l, ok := vsp.Values[i].(*ast.BasicLit); ok && l.Kind == token.STRING {
							out[nm.Name], _ = strconv.Unquote(l.Value)
						}
					}
				}
			}
		}
	}
	return out
}

func strOf(e ast.Expr, consts map[string]string) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			s, _ := strconv.Unquote(x.Value)
			return s, true
		}
	case *ast.Ident:
		s, ok := consts[x.Name]
		return s, ok
	case *ast.SelectorExpr:
		s, ok := consts[x.Sel.Name]
		return s, ok
	case *ast.CallExpr: // authz.Permission("...")
		if len(x.Args) == 1 {
			return strOf(x.Args[0], consts)
		}
	}
	return "", false
}

// descriptorPerms returns the Permission values of Descriptor literals in f; unresolvable ones are "<unresolved>".
// Constants are resolved from the file's own directory and, for a qualified name, by identifier across the tree.
func descriptorPerms(root string, f *ast.File) []string {
	consts := allConsts(root)
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || !isNamed(cl.Type, "Descriptor") {
			return true
		}
		for _, e := range cl.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Permission" {
					if s, ok := strOf(kv.Value, consts); ok {
						out = append(out, s)
					} else {
						out = append(out, "<unresolved>")
					}
				}
			}
		}
		return true
	})
	sort.Strings(out)
	return out
}

var constCache = map[string]map[string]string{}

func allConsts(root string) map[string]string {
	if c, ok := constCache[root]; ok {
		return c
	}
	out := map[string]string{}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skip(d.Name()) && p != root {
				return filepath.SkipDir
			}
			for k, v := range constStrings(p) {
				out[k] = v
			}
		}
		return nil
	})
	constCache[root] = out
	return out
}

func isNamed(e ast.Expr, name string) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == name
	case *ast.SelectorExpr:
		return t.Sel.Name == name
	}
	return false
}

func skip(n string) bool {
	return n == ".git" || n == "node_modules" || n == "vendor" || n == "testdata" || n == "web" || n == "factory" || n == "knowledge" || n == ".activeDIQ-worktrees"
}

func walkGo(root string, fn func(rel string, f *ast.File, fset *token.FileSet)) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip(d.Name()) && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, fset, err := parseFile(p)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		rel, _ := filepath.Rel(root, p)
		fn(filepath.ToSlash(rel), f, fset)
		return nil
	})
}

// GM1: a file registering ad.group.addMember / removeMember keeps to the group permissions, and every step it
// builds has the same authz Target expression as the WriteOp it emits, never one spelled for the member.
func gm1(root string) ([]Violation, []string, error) {
	var vs []Violation
	seen := false
	err := walkGo(root, func(rel string, f *ast.File, fset *token.FileSet) {
		if strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "tools/") || strings.HasPrefix(rel, "internal/directory/client/") ||
			strings.HasPrefix(rel, "internal/proto/") {
			return
		}
		has := false
		ast.Inspect(f, func(n ast.Node) bool {
			if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING {
				if s, _ := strconv.Unquote(l.Value); s == "ad.group.addMember" || s == "ad.group.removeMember" {
					has = true
				}
			}
			return true
		})
		if !has {
			return
		}
		// Only a file that registers an Action (an operation Descriptor or a WriteOp) is an Action
		// registration; the writechange codec and the like merely mention the keys.
		registers := false
		ast.Inspect(f, func(n ast.Node) bool {
			if cl, ok := n.(*ast.CompositeLit); ok {
				if strings.HasSuffix(exprText(cl.Type), "Descriptor") {
					registers = true
				}
				for _, e := range cl.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "DigestKind" {
							registers = true
						}
					}
				}
			}
			return true
		})
		if !registers {
			return
		}
		seen = true
		perms := descriptorPerms(root, f)
		if len(perms) == 0 {
			vs = append(vs, Violation{"GM1", rel, "file registers a group-member kind but declares no Descriptor Permission"})
		}
		for _, p := range perms {
			if !groupPerms[p] {
				vs = append(vs, Violation{"GM1", rel, fmt.Sprintf("Descriptor Permission %q is outside {objects.group.add_member, objects.group.nest, objects.group.remove_member}", p)})
			}
		}
		// Target: every `Target:` of a StepPlan-like literal and of a WriteOp must be one expression, and not the member.
		var stepT, opT []string
		var at []token.Pos
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			var tgt ast.Expr
			isOp, isStep := false, false
			for _, e := range cl.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				id, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch id.Name {
				case "Target":
					tgt = kv.Value
				case "DigestKind":
					isOp = true
				case "Kind", "Reversibility":
					isStep = true
				}
			}
			if tgt != nil && (isOp || isStep) {
				txt := exprText(tgt)
				if isOp {
					opT = append(opT, txt)
				} else {
					stepT = append(stepT, txt)
				}
				at = append(at, tgt.Pos())
				if strings.Contains(strings.ToLower(txt), "member") {
					vs = append(vs, Violation{"GM1", line(fset, tgt.Pos(), rel), fmt.Sprintf("authz Target %q names the member; it must be the group (the argument that becomes target)", txt)})
				}
			}
			return true
		})
		if len(stepT) == 0 || len(opT) == 0 {
			vs = append(vs, Violation{"GM1", rel, "cannot find both the step Target and the WriteOp Target to compare"})
			return
		}
		for _, s := range stepT {
			for _, o := range opT {
				if s != o {
					vs = append(vs, Violation{"GM1", rel, fmt.Sprintf("step Target %q differs from WriteOp Target %q", s, o)})
				}
			}
		}
	})
	var pending []string
	if !seen {
		pending = append(pending, "GM1 group-member Actions (no Action registers ad.group.addMember/removeMember yet)")
	}
	return vs, pending, err
}

func exprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprText(x.X) + "." + x.Sel.Name
	case *ast.CallExpr:
		s := exprText(x.Fun) + "("
		for i, a := range x.Args {
			if i > 0 {
				s += ","
			}
			s += exprText(a)
		}
		return s + ")"
	case *ast.BasicLit:
		return x.Value
	}
	return "?"
}
