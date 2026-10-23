package write

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TM-F-T0GUARD: no directory or Graph write is reachable except through the guard. The guard hands
// an Authorised token to operation bodies in the operation table (ops.go) and nowhere else, so the
// rule is structural: in non-test code under internal/connector, a write call may appear only in
// the directory internal/connector/write/ops (the bodies of the table), and that package may be
// imported only by this one. In this ticket the table is empty and the directory does not exist, so
// the test asserts that there is no write call anywhere.

var ldapWriteFuncs = map[string]bool{"NewAddRequest": true, "NewModifyRequest": true, "NewDelRequest": true,
	"NewModifyDNRequest": true, "NewPasswordModifyRequest": true, "NewModifyRequestWithControls": true}

var ldapWriteMethods = map[string]bool{"Add": true, "Modify": true, "ModifyWithResult": true, "Del": true,
	"ModifyDN": true, "ModifyDNWithResult": true, "PasswordModify": true, "ModifyAsync": true}

var httpWriteMethods = map[string]bool{"MethodPost": true, "MethodPut": true, "MethodPatch": true, "MethodDelete": true}

// tokenEndpointFile is the one non-read request of the connector: the OAuth client-credentials POST
// to the token endpoint. It writes nothing to the directory.
const tokenEndpointFile = "internal/connector/graph/client.go"

func TestNoWriteCallOutsideTheGuard(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	base := filepath.Join(root, "internal", "connector")
	fset := token.NewFileSet()
	var found []string
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "internal/connector/write/ops/") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ldapName := importName(f, "github.com/go-ldap/ldap/v3")
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pos := fset.Position(sel.Pos()).String()
			if x, ok := sel.X.(*ast.Ident); ok {
				switch {
				case ldapName != "" && x.Name == ldapName && ldapWriteFuncs[sel.Sel.Name]:
					found = append(found, pos+": ldap."+sel.Sel.Name)
				case x.Name == "http" && httpWriteMethods[sel.Sel.Name] && rel != tokenEndpointFile:
					found = append(found, pos+": http."+sel.Sel.Name)
				}
			}
			return true
		})
		// Method calls on an LDAP connection: only files that import go-ldap can hold one.
		if ldapName != "" {
			ast.Inspect(f, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && ldapWriteMethods[sel.Sel.Name] {
						if x, ok := sel.X.(*ast.Ident); ok && x.Name == ldapName {
							return true
						}
						found = append(found, fset.Position(sel.Pos()).String()+": ."+sel.Sel.Name+" on an LDAP connection")
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Errorf("write call outside internal/connector/write/ops: %s", f)
	}
}

// Nothing may import the operation bodies except the guard's own package.
func TestOpsPackageImportedOnlyByGuard(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	const opsPath = `"github.com/skenzeriq/activediq/internal/connector/write/ops"`
	fset := token.NewFileSet()
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if filepath.ToSlash(filepath.Dir(rel)) == "internal/connector/write" || strings.HasPrefix(rel, "internal/connector/write/ops/") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			if im.Path.Value == opsPath {
				t.Errorf("%s imports the operation bodies; only internal/connector/write may", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// CC-WRITE-22: the three limits have one source. No code under internal/connector reads an
// environment variable, flag or registry value whose name mentions them.
func TestLimitsHaveNoSetting(t *testing.T) {
	root := filepath.Join("..", "..", "..", "internal", "connector")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				s := strings.ToLower(bl.Value)
				for _, w := range []string{"max_verification_age", "maxverificationage", "max_statement_age", "maxstatementage", "future_skew"} {
					if strings.Contains(s, w) {
						t.Errorf("%s: a string names a limit (%s): limits are constants, not settings", fset.Position(bl.Pos()), w)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func importName(f *ast.File, path string) string {
	for _, im := range f.Imports {
		if strings.Trim(im.Path.Value, `"`) == path {
			if im.Name != nil {
				return im.Name.Name
			}
			return "ldap"
		}
	}
	return ""
}
