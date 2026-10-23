package ad

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TM-F-NTLM (directory half), static layer: the connector authenticates with a simple bind over
// LDAPS only. It must never reference an NTLM/GSSAPI/SSPI bind (go-ldap ships NTLMBind*, and
// go-ntlmssp is an indirect dependency) and must never dial anything but the configured DCs
// (no net/http, no SMB, no path-opening of attribute values such as homeDirectory).
var forbiddenCalls = map[string]string{
	"NTLMBind": "NTLM bind", "NTLMChallengeBind": "NTLM bind", "NTLMUnauthenticatedBind": "NTLM bind",
	"NTLMBindWithHash": "NTLM bind", "UnauthenticatedBind": "anonymous bind", "ExternalBind": "SASL EXTERNAL",
	"MD5Bind": "digest bind", "GSSAPIBind": "GSSAPI bind", "GSSAPIBindRequest": "GSSAPI bind",
	"DigestMD5Bind": "digest bind", "DialURL": "unmanaged dial (use dial())", "Dial": "unmanaged dial",
	"Open": "file open of directory-supplied path", "ReadFile": "file read of directory-supplied path",
	"Stat": "stat of directory-supplied path", "Get": "http fetch",
}

var forbiddenImports = []string{"net/http", "github.com/Azure/go-ntlmssp", "github.com/hirochachacha/go-smb2",
	"github.com/jcmturner/gokrb5", "os/exec", "github.com/go-ldap/ldap/v3/gssapi"}

func TestNTLMStaticGuard(t *testing.T) {
	fset := token.NewFileSet()
	files, err := parseNonTestFiles(fset)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no source files parsed")
	}
	for name, f := range files {
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			for _, bad := range forbiddenImports {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Errorf("%s imports %s", name, p)
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if why, bad := forbiddenCalls[sel.Sel.Name]; bad {
				// Bind-method names are unique to go-ldap: flag them on any receiver. Generic
				// names (Open, Get, Dial…) only when package-qualified, since Session.Open is ours.
				id, qualified := sel.X.(*ast.Ident)
				pkg := qualified && (id.Name == "ldap" || id.Name == "os" || id.Name == "http" || id.Name == "ioutil")
				if pkg || strings.Contains(why, "bind") || strings.Contains(why, "SASL") {
					t.Errorf("%s: %s — %s", fset.Position(sel.Pos()), sel.Sel.Name, why)
				}
			}
			return true
		})
	}
}

func parseNonTestFiles(fset *token.FileSet) (map[string]*ast.File, error) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		return nil, err
	}
	out := map[string]*ast.File{}
	for _, n := range names {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		if _, err := os.Stat(n); err != nil {
			return nil, err
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			return nil, err
		}
		out[n] = f
	}
	return out, nil
}
