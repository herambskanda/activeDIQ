package prochardening

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// exempt lists cmd programs that hold no secrets. Adding one needs a reason and a security review.
var exempt = map[string]string{
	"auditverify": "offline auditor tool, stdlib-only by ADR-0005 rule 11, runs on the auditor's machine with no secrets",
}

const (
	pkgPath = `"github.com/skenzeriq/activediq/internal/platform/prochardening"`
	errForm = "main must start with `if err := prochardening.Apply(os.Getenv); err != nil { ...; os.Exit(non-zero) }` (TM-TB16-T6)"
)

// TestEveryMainHardensFirst is the fitness check for TM-TB16-T6: every main package under cmd/...
// (any depth, main declared in any file) must make prochardening.Apply(os.Getenv) the first statement
// of main, failing closed with os.Exit(non-zero), so no secret is loaded before dumps are disabled.
func TestEveryMainHardensFirst(t *testing.T) {
	found, err := checkTree("../../../cmd", func(dir string) {
		if reason, ok := exempt[exemptKey("../../../cmd", dir)]; ok {
			t.Logf("exempt: %s: %s", dir, reason)
		}
	})
	if len(found) < 5 { // server, connector, edge, agent, auditverify
		t.Fatalf("found only %d main packages %v; expected at least 5", len(found), found)
	}
	if err != nil {
		t.Error(err)
	}
}

// checkTree walks root, and for every directory holding a non-test `package main` it finds the file that
// declares func main and checks it. A main package without func main is a failure, not a skip.
// onExempt is called for exempt directories. It returns the main package dirs found.
func checkTree(root string, onExempt func(dir string)) ([]string, error) {
	var found []string
	var errs []error
	werr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		fset := token.NewFileSet()
		pkgs, perr := parser.ParseDir(fset, p, func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
		if perr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, perr))
			return nil
		}
		pkg, ok := pkgs["main"]
		if !ok {
			return nil
		}
		found = append(found, p)
		if _, ex := exempt[exemptKey(root, p)]; ex {
			if onExempt != nil {
				onExempt(p)
			}
			return nil
		}
		for name, f := range pkg.Files {
			if ierr := checkPreMain(f); ierr != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, ierr))
			}
		}
		checked := false
		for name, f := range pkg.Files {
			if !declaresMain(f) {
				continue
			}
			checked = true
			src, rerr := os.ReadFile(name)
			if rerr != nil {
				errs = append(errs, rerr)
				continue
			}
			if cerr := checkSource(name, src); cerr != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, cerr))
			}
		}
		if !checked {
			errs = append(errs, fmt.Errorf("%s: package main without func main", p))
		}
		return nil
	})
	if werr != nil {
		errs = append(errs, werr)
	}
	return found, errors.Join(errs...)
}

// exemptKey is the slash path of dir relative to the cmd root, so only cmd/<key> itself is exempt, never a
// nested directory that happens to share the name.
func exemptKey(root, dir string) string {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return dir
	}
	return filepath.ToSlash(rel)
}

// checkPreMain rejects code that runs before main: any func init, and any package-level var whose
// initialiser contains a call (including conversions; use a literal or set it inside main after Apply).
func checkPreMain(f *ast.File) error {
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Name.Name == "init" && d.Recv == nil {
				return errors.New("func init runs before main hardening (TM-TB16-T6); move it into main after Apply")
			}
		case *ast.GenDecl:
			if d.Tok != token.VAR {
				continue
			}
			for _, sp := range d.Specs {
				vs := sp.(*ast.ValueSpec)
				for _, v := range vs.Values {
					var call bool
					ast.Inspect(v, func(n ast.Node) bool {
						if _, ok := n.(*ast.CallExpr); ok {
							call = true
						}
						return !call
					})
					if call {
						return errors.New("package-level var with a call initialiser runs before main hardening (TM-TB16-T6)")
					}
				}
			}
		}
	}
	return nil
}

func declaresMain(f *ast.File) bool {
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "main" && fn.Recv == nil {
			return true
		}
	}
	return false
}

func importName(f *ast.File, path, def string) string {
	for _, imp := range f.Imports {
		if imp.Path.Value == path {
			if imp.Name != nil {
				return imp.Name.Name
			}
			return def
		}
	}
	return ""
}

func isSel(e ast.Expr, x, sel string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != sel {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == x
}

func checkSource(name string, src []byte) error {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		return err
	}
	ph := importName(f, pkgPath, "prochardening")
	osName := importName(f, `"os"`, "os")
	if ph == "" || osName == "" || ph == "_" || ph == "." || osName == "_" || osName == "." {
		return errors.New(errForm)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" || fn.Recv != nil || fn.Body == nil || len(fn.Body.List) == 0 {
			continue
		}
		ifs, ok := fn.Body.List[0].(*ast.IfStmt)
		if !ok || ifs.Else != nil {
			return errors.New(errForm)
		}
		as, ok := ifs.Init.(*ast.AssignStmt)
		if !ok || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return errors.New(errForm)
		}
		lhs, ok := as.Lhs[0].(*ast.Ident)
		if !ok || lhs.Name == "_" {
			return errors.New(errForm)
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || !isSel(call.Fun, ph, "Apply") || len(call.Args) != 1 || !isSel(call.Args[0], osName, "Getenv") {
			return errors.New(errForm)
		}
		// condition: lhs != nil
		cond, ok := ifs.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ {
			return errors.New(errForm)
		}
		x, xok := cond.X.(*ast.Ident)
		y, yok := cond.Y.(*ast.Ident)
		if !xok || !yok || x.Name != lhs.Name || y.Name != "nil" {
			return errors.New(errForm)
		}
		// body must end in os.Exit(non-zero literal)
		if len(ifs.Body.List) == 0 {
			return errors.New(errForm)
		}
		last, ok := ifs.Body.List[len(ifs.Body.List)-1].(*ast.ExprStmt)
		if !ok {
			return errors.New(errForm)
		}
		exit, ok := last.X.(*ast.CallExpr)
		if !ok || !isSel(exit.Fun, osName, "Exit") || len(exit.Args) != 1 {
			return errors.New(errForm)
		}
		lit, ok := exit.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.INT {
			return errors.New(errForm)
		}
		if n, cerr := strconv.Atoi(lit.Value); cerr != nil || n == 0 {
			return errors.New(errForm)
		}
		return nil
	}
	return errors.New(errForm)
}

func TestCheckSourceRejects(t *testing.T) {
	const imp = "package main\nimport (\"os\"\n\"github.com/skenzeriq/activediq/internal/platform/prochardening\")\n"
	body := func(init, cond, inner string) string {
		return imp + "func main() { if " + init + "; " + cond + " { " + inner + " }; _ = 1 }"
	}
	const ap = "err := prochardening.Apply(os.Getenv)"
	good := body(ap, "err != nil", "println(err); os.Exit(2)")
	bad := map[string]string{
		"no import":      "package main\nfunc main() {}",
		"not first":      imp + "func main() { _ = 1; if err := prochardening.Apply(os.Getenv); err != nil { os.Exit(2) } }",
		"empty main":     imp + "func main() {}",
		"wrong func":     body("err := prochardening.Other(os.Getenv)", "err != nil", "os.Exit(2)"),
		"fail-open body": body(ap, "err != nil", "println(err)"),
		"empty body":     body(ap, "err != nil", ""),
		"getenv stub":    body("err := prochardening.Apply(func(string) string { return \"\" })", "err != nil", "os.Exit(2)"),
		"err == nil":     body(ap, "err == nil", "os.Exit(2)"),
		"exit zero":      body(ap, "err != nil", "os.Exit(0)"),
		"other variable": body(ap, "other != nil", "os.Exit(2)"),
		"exit not last":  body(ap, "err != nil", "os.Exit(2); println(err)"),
	}
	if err := checkSource("good.go", []byte(good)); err != nil {
		t.Fatalf("good rejected: %v", err)
	}
	for n, s := range bad {
		if checkSource(n, []byte(s)) == nil {
			t.Errorf("%s: accepted", n)
		}
	}
}

func TestCheckTreeFindsMainInAnyFileAndDepth(t *testing.T) {
	const imp = "package main\nimport (\"os\"\n\"github.com/skenzeriq/activediq/internal/platform/prochardening\")\n"
	goodMain := imp + "func main() { if err := prochardening.Apply(os.Getenv); err != nil { os.Exit(2) } }"
	write := func(root, rel, s string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	write(root, "ok/run.go", goodMain)
	if _, err := checkTree(root, nil); err != nil {
		t.Fatalf("good tree rejected: %v", err)
	}
	// main in run.go (not main.go), unhardened
	write(root, "foo/run.go", "package main\nfunc main() {}")
	if _, err := checkTree(root, nil); err == nil {
		t.Error("unhardened main in run.go accepted")
	}
	os.RemoveAll(filepath.Join(root, "foo"))
	// nested
	write(root, "tools/bar/main.go", "package main\nfunc main() {}")
	if _, err := checkTree(root, nil); err == nil {
		t.Error("unhardened nested main accepted")
	}
	os.RemoveAll(filepath.Join(root, "tools"))
	// package main without func main
	write(root, "nomain/x.go", "package main\nfunc helper() {}")
	if _, err := checkTree(root, nil); err == nil {
		t.Error("package main without func main accepted")
	}
}

func TestCheckPreMainAndExemptKey(t *testing.T) {
	good := "package main\nvar a = 1\nvar b = []string{\"x\"}\nfunc main() {}"
	bad := map[string]string{
		"init func":     "package main\nfunc init() { println() }\nfunc main() {}",
		"call var init": "package main\nvar s = load()\nfunc load() string { return \"\" }\nfunc main() {}",
		"nested call":   "package main\nvar s = []string{load()}\nfunc load() string { return \"\" }\nfunc main() {}",
	}
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	if err := checkPreMain(parse(good)); err != nil {
		t.Fatalf("good rejected: %v", err)
	}
	for n, s := range bad {
		if checkPreMain(parse(s)) == nil {
			t.Errorf("%s: accepted", n)
		}
	}
	if exemptKey("cmd", filepath.Join("cmd", "tools", "auditverify")) == "auditverify" {
		t.Error("nested auditverify keyed as exempt")
	}
	if exemptKey("cmd", filepath.Join("cmd", "auditverify")) != "auditverify" {
		t.Error("top-level auditverify not keyed")
	}
}

func TestCheckTreeRejectsPreMainAndNestedExempt(t *testing.T) {
	const imp = "package main\nimport (\"os\"\n\"github.com/skenzeriq/activediq/internal/platform/prochardening\")\n"
	goodMain := imp + "func main() { if err := prochardening.Apply(os.Getenv); err != nil { os.Exit(2) } }"
	cases := map[string]map[string]string{
		"init in main file":    {"a/main.go": goodMain + "\nfunc init() { println() }"},
		"init in sibling file": {"a/main.go": goodMain, "a/b.go": "package main\nfunc init() { println() }"},
		"var call initialiser": {"a/main.go": goodMain + "\nvar s = os.Getenv(\"X\")"},
		"nested auditverify":   {"tools/auditverify/main.go": "package main\nfunc main() {}"},
	}
	for n, files := range cases {
		root := t.TempDir()
		for rel, s := range files {
			p := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := checkTree(root, nil); err == nil {
			t.Errorf("%s: accepted", n)
		}
	}
}
