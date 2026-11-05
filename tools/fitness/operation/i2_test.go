package main

import (
	"strings"
	"testing"
)

const changeImport = `import "` + mod + `/internal/platform/operation"` + "\n"

func TestI2Violations(t *testing.T) {
	cases := map[string]struct{ file, src, want string }{
		"requester in After": {"internal/modules/a/a.go", "package a\n" + changeImport + "func f(c operation.Chain) { _ = operation.Change{Attribute: \"description\", After: []string{string(c.Requester.ID)}} }\n", "Requester"},
		"token in Before":    {"internal/modules/a/a.go", "package a\nfunc f(s S) { _ = Change{Attribute: \"info\", Before: []string{s.TokenID}} }\n", "TokenID"},
		"via through call":   {"internal/platform/x/x.go", "package x\nfunc f(c C) { _ = Change{After: []string{fmt.Sprint(c.Via)}} }\n", "Via"},
		"proto field":        {"proto/activediq/connector/v1/write.proto", "message AttributeEdit {\n  string attribute = 1;\n  string requester_id = 2;\n}\n", "requester_id"},
	}
	for name, c := range cases {
		vs := runCheck(t, CheckI2, map[string]string{c.file: c.src})
		if len(vs) != 1 || vs[0].Check != "I2" || !strings.Contains(vs[0].Msg, c.want) || !strings.Contains(vs[0].String(), "I-2") {
			t.Errorf("%s: %v, want one containing %q", name, vs, c.want)
		}
	}
}

func TestI2Clean(t *testing.T) {
	files := map[string]string{
		"internal/modules/a/a.go":                  "package a\nfunc f(in In, c Chain) { _ = Change{Attribute: \"description\", Before: in.Old, After: []string{in.Description}}; _ = c.Requester }\n",
		"internal/modules/a/a_test.go":             "package a\nfunc g(c Chain) { _ = Change{After: []string{c.Requester}} }\n",
		"proto/activediq/connector/v1/write.proto": "message ActingPrincipal {\n  Guid account_id = 1;\n  Guid api_token_id = 2;\n}\nmessage ApplyRequest {\n  ActingPrincipal acting_principal = 10;\n}\nmessage AttributeEdit {\n  string attribute = 1; // not a principal field\n}\n",
	}
	if vs := runCheck(t, CheckI2, files); len(vs) != 0 {
		t.Errorf("clean tree: %v", vs)
	}
}
