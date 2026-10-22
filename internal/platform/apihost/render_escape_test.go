package apihost

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// ---- response escaping (safe-primitives §12.5 rule 7; T-0047) ----

type marshalerBody struct{ S string }

func (m marshalerBody) MarshalJSONTo(e *jsontext.Encoder) error {
	return json.MarshalEncode(e, map[string]string{"s": m.S})
}

const hostile = "</script><img src=x onerror=alert(1)>&\u2028\u2029"

func assertEscaped(t *testing.T, body []byte) {
	t.Helper()
	for _, raw := range []string{"<", ">", "&", "\u2028", "\u2029"} {
		if strings.Contains(string(body), raw) {
			t.Errorf("body contains raw %q: %s", raw, body)
		}
	}
	for _, esc := range []string{"\\u003c", "\\u003e", "\\u0026", "\\u2028", "\\u2029"} {
		if !strings.Contains(string(body), esc) {
			t.Errorf("body lacks %s: %s", esc, body)
		}
	}
}

func TestMarshalResponseEscapes(t *testing.T) {
	raw := jsontext.Value(`{"s":"` + hostile + `"}`)
	for name, v := range map[string]any{
		"map":         map[string]string{"s": hostile},
		"marshaler":   marshalerBody{S: hostile},
		"jsontext":    raw,
		"in a struct": struct{ V jsontext.Value }{raw},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := marshalResponse(v)
			if err != nil {
				t.Fatal(err)
			}
			assertEscaped(t, b)
		})
	}
}

func TestWriteProblemEscapes(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/x", nil)
	p := apitypes.Internal(hostile)
	p.Title = hostile
	writeProblem(rec, req, p, slog.New(slog.DiscardHandler))
	assertEscaped(t, rec.Body.Bytes())
}

// TestEveryEncodeSiteUsesResponseOptions (HT-29): any JSON encode call in apihost outside
// marshalResponse fails CI, so no site can skip responseOpts.
func TestEveryEncodeSiteUsesResponseOptions(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	encode := map[string]bool{"Marshal": true, "MarshalWrite": true, "MarshalEncode": true, "NewEncoder": true}
	for _, pkg := range pkgs {
		for fname, f := range pkg.Files {
			jsonNames := map[string]bool{}
			for _, is := range f.Imports {
				switch strings.Trim(is.Path.Value, `"`) {
				case "encoding/json/v2", "encoding/json", "encoding/json/jsontext":
					n := "json"
					if is.Name != nil {
						n = is.Name.Name
					} else if strings.HasSuffix(is.Path.Value, `jsontext"`) {
						n = "jsontext"
					}
					jsonNames[n] = true
				}
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				allowed := ok && fd.Recv == nil && fd.Name.Name == "marshalResponse"
				ast.Inspect(d, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok || !encode[sel.Sel.Name] {
						return true
					}
					if id, ok := sel.X.(*ast.Ident); ok && jsonNames[id.Name] && !allowed {
						t.Errorf("%s: %s.%s outside marshalResponse; route it through marshalResponse so responseOpts apply", fname, id.Name, sel.Sel.Name)
					}
					return true
				})
			}
		}
	}
}
