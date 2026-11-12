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

func TestI2ExemptDirective(t *testing.T) {
	src := "package a\nfunc f(c Chain) {\n\t// i2:exempt grantee of a store action\n\t_ = []Change{{After: []string{c.Requester}}}\n}\n"
	if vs := runCheck(t, CheckI2, map[string]string{"internal/modules/a/a.go": src}); len(vs) != 0 {
		t.Errorf("exempt line flagged: %v", vs)
	}
	src = "package a\nfunc f(c Chain) {\n\t// not an exemption\n\t_ = []Change{{After: []string{c.Requester}}}\n}\n"
	if vs := runCheck(t, CheckI2, map[string]string{"internal/modules/a/a.go": src}); len(vs) != 1 {
		t.Errorf("plain comment suppressed the check: %v", vs)
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

// The bypasses a hand-written check must not allow (security-architect review of T-1629).
func TestI2Bypasses(t *testing.T) {
	cases := map[string]string{
		"elided element of []Change":       "package a\nfunc f(c Chain) { _ = Plan{Diff: []operation.Change{{Attribute: \"x\", After: []string{c.Requester}}}} }\n",
		"elided element of map":            "package a\nfunc f(c Chain) { _ = map[string]Change{\"k\": {After: []string{c.Requester}}} }\n",
		"positional fields":                "package a\nfunc f(c Chain) { _ = Change{\"x\", nil, []string{c.Requester}, false} }\n",
		"field assignment":                 "package a\n" + changeImport + "func f(c Chain, ch *operation.Change) { ch.After = []string{c.Requester} }\n",
		"append to field":                  "package a\n" + changeImport + "func f(c Chain, ch *operation.Change) { ch.Before = append(ch.Before, c.Requester) }\n",
		"local variable indirection":       "package a\nfunc f(c Chain) { who := c.Requester; id := string(who); _ = Change{After: []string{id}} }\n",
		"helper returning the requester":   "package a\nfunc who(c Chain) string { return c.Requester }\nfunc f(c Chain) { _ = Change{After: []string{who(c)}} }\n",
		"helper through another helper":    "package a\nfunc who(c Chain) string { return c.Requester }\nfunc who2(c Chain) string { return who(c) }\nfunc g(c Chain) { _ = []Change{{After: []string{who2(c)}}} }\n",
		"parameter named like an identity": "package a\nfunc f(Requester string) { _ = []Change{{After: []string{Requester}}} }\n",
	}
	for name, src := range cases {
		vs := runCheck(t, CheckI2, map[string]string{"internal/modules/a/a.go": src})
		if len(vs) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
}

// The repository itself is clean under the (now thorough) check.
func TestI2RealTree(t *testing.T) {
	vs, err := CheckI2("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		t.Errorf("%s", v)
	}
}
