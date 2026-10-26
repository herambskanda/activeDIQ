package main

import (
	"strings"
	"testing"
)

const (
	connImport = `import connectorv1 "` + mod + `/internal/proto/activediq/connector/v1"` + "\n"
	clientPath = "internal/directory/client/c.go"
)

func runCheck(t *testing.T, f func(string) ([]Violation, error), files map[string]string) []Violation {
	t.Helper()
	vs, err := f(tree(t, fixtureDAG, files))
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

func TestO2Violations(t *testing.T) {
	cases := map[string]struct{ file, src, want string }{
		"exported write without Step":             {clientPath, "package client\ntype C struct{ transport T }\nfunc (c *C) Do() { c.sendApply() }\nfunc (c *C) sendApply() {}\n", "no step.Step parameter"},
		"direct transport call without Clearance": {clientPath, "package client\n" + stepImport + "type C struct{ transport T }\nfunc (c *C) send(s step.Step) { c.transport.Apply() }\n", "no step.Clearance parameter"},
		"generated client outside client":         {"internal/modules/a/a.go", "package a\n" + connImport + "var _ = connectorv1.NewConnectorClient\n", "generated connector-contract client"},
		"generated client in connector non-test":  {"internal/connector/x/x.go", "package x\n" + connImport + "var _ connectorv1.ConnectorClient\n", "generated connector-contract client"},
		"ldap outside connector":                  {"internal/modules/a/a.go", "package a\nimport _ \"github.com/go-ldap/ldap/v3\"\n", "directory protocol library"},
		"graph outside connector":                 {"internal/directory/x/x.go", "package x\nimport _ \"github.com/microsoftgraph/msgraph-sdk-go\"\n", "directory protocol library"},
	}
	for name, c := range cases {
		vs := runCheck(t, CheckO2, map[string]string{c.file: c.src})
		if len(vs) != 1 || vs[0].Check != "O2" || !strings.Contains(vs[0].Msg, c.want) || !strings.Contains(vs[0].String(), "O2 [rule 2]") {
			t.Errorf("%s: %v, want one containing %q", name, vs, c.want)
		}
	}
}

func TestO2Allowed(t *testing.T) {
	vs := runCheck(t, CheckO2, map[string]string{
		clientPath: "package client\n" + stepImport + "type C struct{ transport T }\n" +
			"func (c *C) Write(s step.Step) { c.sendApply(s) }\n" +
			"func (c *C) sendApply(s step.Step, clr step.Clearance) { c.transport.Apply() }\nfunc (c *C) Facts() {}\n",
		"internal/connector/x/x_test.go": "package x\n" + connImport + "var _ connectorv1.ConnectorClient\n",
		"internal/connector/ldap/l.go":   "package ldap\nimport _ \"github.com/go-ldap/ldap/v3\"\n",
		"internal/modules/a/a.go":        "package a\ntype C struct{}\nfunc (C) Apply() {}\nfunc (C) Do(c C) { c.Apply() }\n",
	})
	if len(vs) != 0 {
		t.Fatalf("violations = %v", vs)
	}
}

func TestO4Violations(t *testing.T) {
	bad := []string{
		"UPDATE public.operations SET state = $1 WHERE id = $2",
		"update operation_steps set attempt = 1, state='applying' where id=1",
		"UPDATE operation_items SET updated_at = now(), state = $1",
	}
	for _, q := range bad {
		vs := runCheck(t, CheckO4, map[string]string{"internal/modules/a/a.go": "package a\nconst q = `" + q + "`\n"})
		if len(vs) != 1 || !strings.Contains(vs[0].String(), "O4 [rule 3]") {
			t.Errorf("%q: %v", q, vs)
		}
	}
}

func TestO4Allowed(t *testing.T) {
	vs := runCheck(t, CheckO4, map[string]string{
		transitionFile:                 "package operation\nconst q = `UPDATE public.operations SET state = $1`\n",
		"internal/modules/a/a.go":      "package a\nconst q = `UPDATE public.operations SET updated_at = now() WHERE state = 'x'`\nconst r = `UPDATE other SET state = 1`\n",
		"internal/modules/a/a_test.go": "package a\nconst q = `UPDATE operations SET state = 1`\n",
	})
	if len(vs) != 0 {
		t.Fatalf("violations = %v", vs)
	}
}

func TestO2O4OnTheRepository(t *testing.T) {
	for name, f := range map[string]func(string) ([]Violation, error){"O2": CheckO2, "O4": CheckO4} {
		vs, err := f("../../..")
		if err != nil || len(vs) != 0 {
			t.Errorf("%s on the repository: %v %v", name, vs, err)
		}
	}
}
