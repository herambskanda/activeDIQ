package prochardening

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// TestEveryMainHardensFirst is the fitness check for TM-TB16-T6: every cmd/*/main.go must make
// prochardening.Apply the first statement of main (as `if err := prochardening.Apply(...); err != nil`),
// so no secret is loaded before dumps are disabled. A new cmd/* that skips it fails here.
// exempt lists cmd/* programs that hold no secrets. Adding one needs a reason and a security review.
var exempt = map[string]string{
	"auditverify": "offline auditor tool, stdlib-only by ADR-0005 rule 11, runs on the auditor's machine with no secrets",
}

func TestEveryMainHardensFirst(t *testing.T) {
	mains, err := filepath.Glob("../../../cmd/*/main.go")
	if err != nil || len(mains) < 4 {
		t.Fatalf("found %d cmd mains (err %v); expected at least server, connector, edge, agent", len(mains), err)
	}
	for _, path := range mains {
		if reason, ok := exempt[filepath.Base(filepath.Dir(path))]; ok {
			_ = reason
			continue
		}
		if err := checkMain(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func checkMain(path string) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return checkSource(path, src)
}

func checkSource(name string, src []byte) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return err
	}
	// local name of the prochardening import
	local := ""
	for _, imp := range f.Imports {
		if imp.Path.Value == `"github.com/skenzeriq/activediq/internal/platform/prochardening"` {
			local = "prochardening"
			if imp.Name != nil {
				local = imp.Name.Name
			}
		}
	}
	if local == "" {
		return errMissing
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" || fn.Recv != nil {
			continue
		}
		if len(fn.Body.List) == 0 {
			return errMissing
		}
		ifs, ok := fn.Body.List[0].(*ast.IfStmt)
		if !ok {
			return errMissing
		}
		as, ok := ifs.Init.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return errMissing
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return errMissing
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Apply" {
			return errMissing
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != local {
			return errMissing
		}
		return nil
	}
	return errMissing
}

type fitnessError string

func (e fitnessError) Error() string { return string(e) }

const errMissing = fitnessError("main must start with `if err := prochardening.Apply(os.Getenv); err != nil { ... }` (TM-TB16-T6)")

func TestCheckSourceRejects(t *testing.T) {
	const imp = "package main\nimport \"github.com/skenzeriq/activediq/internal/platform/prochardening\"\n"
	good := imp + "func main() { if err := prochardening.Apply(nil); err != nil { return } ; _ = 1 }"
	bad := map[string]string{
		"no import":  "package main\nfunc main() {}",
		"not first":  imp + "func main() { _ = 1; if err := prochardening.Apply(nil); err != nil { return } }",
		"empty main": imp + "func main() {}",
		"wrong func": imp + "func main() { if err := prochardening.Other(nil); err != nil { return } }",
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
