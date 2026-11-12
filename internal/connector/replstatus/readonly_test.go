package replstatus

// Acceptance 5 / rule 6: no code path of this call writes, sends an LDAP control or asks for a
// privilege. Checked on the source of the packages the call runs through.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestCallHasNoWriteControlOrPrivilege(t *testing.T) {
	fset := token.NewFileSet()
	forbiddenCalls := map[string]bool{"Add": true, "Modify": true, "ModifyDN": true, "ModifyWithResult": true, "Del": true,
		"PasswordModify": true, "Compare": true, "ExternalBind": true, "UnauthenticatedBind": true, "NewControl": true}
	for _, path := range []string{"handler.go", "decode.go", "bound.go", "capability.go", "server.go", "../ad/replread.go"} {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if p := strings.Trim(imp.Path.Value, `"`); strings.Contains(p, "ldap") && !strings.HasSuffix(path, "replread.go") {
				t.Errorf("%s imports %s", path, p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "wg" {
					return true // sync.WaitGroup.Add
				}
				if forbiddenCalls[x.Sel.Name] {
					t.Errorf("%s: %s", path, x.Sel.Name)
				}
				if strings.Contains(x.Sel.Name, "Control") && strings.HasSuffix(path, "replread.go") {
					t.Errorf("%s: %s", path, x.Sel.Name)
				}
			case *ast.BasicLit:
				if strings.Contains(strings.ToLower(x.Value), "privilege") {
					t.Errorf("%s: %s", path, x.Value)
				}
			}
			return true
		})
	}
}
