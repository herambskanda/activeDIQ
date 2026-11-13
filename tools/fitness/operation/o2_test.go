package main

import (
	"fmt"
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
		"exported write without Step":                      {clientPath, "package client\ntype C struct{ transport T }\nfunc (c *C) Do() { c.sendApply() }\nfunc (c *C) sendApply() {}\n", "no step.Step parameter"},
		"direct transport call without Clearance":          {clientPath, "package client\n" + stepImport + "type C struct{ transport T }\nfunc (c *C) send(s step.Step) { c.transport.Apply() }\n", "no step.Clearance parameter"},
		"generated client outside client":                  {"internal/modules/a/a.go", "package a\n" + connImport + "var _ = connectorv1.NewConnectorClient\n", "generated connector-contract client"},
		"generated client in compose/server non-test":      {"internal/compose/server/x.go", "package x\n" + connImport + "var _ connectorv1.ConnectorClient\n", "generated connector-contract client"},
		"generated client in compose test of another root": {"internal/compose/agent/x_test.go", "package x\n" + connImport + "var _ connectorv1.ConnectorClient\n", "generated connector-contract client"},
		"generated client in connector non-test":           {"internal/connector/x/x.go", "package x\n" + connImport + "var _ connectorv1.ConnectorClient\n", "generated connector-contract client"},
		"ldap outside connector":                           {"internal/modules/a/a.go", "package a\nimport _ \"github.com/go-ldap/ldap/v3\"\n", "directory protocol library"},
		"graph outside connector":                          {"internal/directory/x/x.go", "package x\nimport _ \"github.com/microsoftgraph/msgraph-sdk-go\"\n", "directory protocol library"},
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
		"internal/connector/x/x_test.go":       "package x\n" + connImport + "var _ connectorv1.ConnectorClient\n",
		"internal/compose/connector/m_test.go": "package x\n" + connImport + "var _ connectorv1.ConnectorClient\n",
		"internal/compose/server/p_test.go":    "package x\n" + connImport + "var _ connectorv1.ConnectorClient\n",
		"internal/connector/ldap/l.go":         "package ldap\nimport _ \"github.com/go-ldap/ldap/v3\"\n",
		"internal/modules/a/a.go":              "package a\ntype C struct{}\nfunc (C) Apply() {}\nfunc (C) Do(c C) { c.Apply() }\n",
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

// The type-aware half of O2 (analyzer tools/analyzers/connwrite). The fixtures type-check: a fake
// connector-contract package with the generated client's shape, and a step package with a Clearance.

const (
	fakeConnector = "internal/proto/activediq/connector/v1/v1.go"
	fakeStep      = "internal/platform/operation/step/s.go"
	clientImport  = `import client "` + mod + `/internal/directory/client"` + "\n"
	ctxImport     = "import \"context\"\n"
)

var typedBase = map[string]string{
	fakeConnector: `package connectorv1
import "context"
type CallOption interface{}
type DescribeRequest struct{}
type DescribeResponse struct{}
type PlanRequest struct{}
type PlanResponse struct{}
type ApplyRequest struct{}
type ApplyResponse struct{}
type ConnectorClient interface {
	Describe(ctx context.Context, in *DescribeRequest, opts ...CallOption) (*DescribeResponse, error)
	Plan(ctx context.Context, in *PlanRequest, opts ...CallOption) (*PlanResponse, error)
	Apply(ctx context.Context, in *ApplyRequest, opts ...CallOption) (*ApplyResponse, error)
}
`,
	fakeStep: "package step\ntype Step struct{ s *int }\ntype Clearance struct{ c *int }\n",
}

func typedO2(t *testing.T, files map[string]string) []Violation {
	t.Helper()
	all := map[string]string{}
	for p, c := range typedBase {
		all[p] = c
	}
	for p, c := range files {
		all[p] = c
	}
	vs, err := CheckTyped(tree(t, fixtureDAG, all))
	if err != nil {
		t.Fatal(err)
	}
	var o2 []Violation
	for _, v := range vs {
		if v.Check == "O2" {
			o2 = append(o2, v)
		}
	}
	return o2
}

// wantAt fails unless some violation is at file:line and contains msg.
func wantAt(t *testing.T, name string, vs []Violation, file string, line int, msg string) {
	t.Helper()
	for _, v := range vs {
		if v.Pos == fmt.Sprintf("%s:%d", file, line) && strings.Contains(v.Msg, msg) {
			return
		}
	}
	t.Errorf("%s: no violation at %s:%d containing %q in %v", name, file, line, msg, vs)
}

const (
	aliasClient = "package client\n" + connImport + "type Connector = connectorv1.ConnectorClient\n" // line 3
	connPkgStub = "package a\n" + clientImport + ctxImport
)

func TestO2TypedExportedAliasAndItsUse(t *testing.T) {
	vs := typedO2(t, map[string]string{
		clientPath:                "package client\n" + connImport + "type Connector = connectorv1.ConnectorClient\n",
		"internal/modules/a/a.go": "package a\n" + clientImport + "type Holder struct{ C client.Connector }\n",
	})
	wantAt(t, "alias", vs, clientPath, 3, "exported type Connector")
	wantAt(t, "use", vs, "internal/modules/a/a.go", 3, "named here")
	wantAt(t, "field", vs, "internal/modules/a/a.go", 3, "has a type that carries")
}

func TestO2TypedViolations(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		file  string
		line  int
		want  string
	}{
		"exported named interface embedding the client": {
			map[string]string{clientPath: "package client\n" + connImport + "type RW interface{ connectorv1.ConnectorClient }\n"},
			clientPath, 3, "exported type RW"},
		"exported interface redeclaring Apply, no mention of the client": {
			map[string]string{clientPath: "package client\n" + connImport + ctxImport + "type W interface{ Apply(context.Context, *connectorv1.ApplyRequest, ...connectorv1.CallOption) (*connectorv1.ApplyResponse, error) }\n"},
			clientPath, 4, "exported type W"},
		"exported struct embedding the client": {
			map[string]string{clientPath: "package client\n" + connImport + "type S struct{ connectorv1.ConnectorClient }\n"},
			clientPath, 3, "exported type S"},
		"exported field of the client": {
			map[string]string{clientPath: "package client\n" + connImport + "type S struct{ C connectorv1.ConnectorClient }\n"},
			clientPath, 3, "exported field C of S"},
		"exported variable of a slice of the client": {
			map[string]string{clientPath: "package client\n" + connImport + "var All []connectorv1.ConnectorClient\n"},
			clientPath, 3, "exported variable All"},
		"exported variable of a map of the client": {
			map[string]string{clientPath: "package client\n" + connImport + "var All2 map[string]connectorv1.ConnectorClient\n"},
			clientPath, 3, "exported variable All2"},
		"struct field of the aliased type in another package": {
			map[string]string{clientPath: aliasClient, "internal/modules/a/a.go": "package a\n" + clientImport + "type H struct{ c client.Connector }\n"},
			"internal/modules/a/a.go", 3, "variable, field or parameter c"},
		"direct Apply through the alias": {
			map[string]string{clientPath: aliasClient, "internal/directory/sync/s.go": "package sync\n" + clientImport + ctxImport + "import connectorv1 \"" + mod + "/internal/proto/activediq/connector/v1\"\nfunc f(c client.Connector) { c.Apply(context.Background(), &connectorv1.ApplyRequest{}) }\n"},
			"internal/directory/sync/s.go", 5, "Apply write RPC"},
		"direct Plan through an embedding interface": {
			map[string]string{clientPath: aliasClient, "internal/modules/a/a.go": "package a\n" + clientImport + ctxImport + "type I interface{ client.Connector }\nfunc f(i I) { i.Plan(context.Background(), nil) }\n"},
			"internal/modules/a/a.go", 5, "Plan write RPC"},
		"Apply on an inferred variable, no identifier of the client named": {
			map[string]string{
				clientPath:                "package client\n" + connImport + ctxImport + "type Source interface{ Connector(ctx context.Context) (connectorv1.ConnectorClient, error) }\n",
				"internal/modules/a/a.go": "package a\n" + clientImport + ctxImport + "func f(s client.Source) { cc, _ := s.Connector(context.Background()); cc.Apply(context.Background(), nil) }\n"},
			"internal/modules/a/a.go", 4, "Apply write RPC"},
		"Apply method value": {
			map[string]string{clientPath: aliasClient, "internal/modules/a/a.go": "package a\n" + clientImport + "func f(c client.Connector) any { return c.Apply }\n"},
			"internal/modules/a/a.go", 3, "Apply write RPC"},
		"Apply in the client package without a Clearance": {
			map[string]string{clientPath: "package client\n" + connImport + ctxImport + "type t struct{ c connectorv1.ConnectorClient }\nfunc (x t) send() { x.c.Apply(context.Background(), nil) }\n"},
			clientPath, 5, "Apply write RPC"},
		"generic constraint carrying the client": {
			map[string]string{"internal/modules/a/a.go": "package a\n" + connImport + "func f[T connectorv1.ConnectorClient](t T) {}\n"},
			"internal/modules/a/a.go", 3, "type that carries"},
		"function returning the client in a non-exempt test dir": {
			map[string]string{"internal/compose/agent/x_test.go": "package x\n" + connImport + "func mk() (connectorv1.ConnectorClient, error) { return nil, nil }\n"},
			"internal/compose/agent/x_test.go", 3, "takes or returns"},
	}
	for name, c := range cases {
		vs := typedO2(t, c.files)
		wantAt(t, name, vs, c.file, c.line, c.want)
	}
}

// A nested internal directory (idiomatic under cmd/) is not the top-level one: the package's place is
// its path below the module root, never what follows the first "/internal/" (security review of T-1408).
func TestO2TypedNestedInternalDirsGetNoExemption(t *testing.T) {
	src := "package client\n" + connImport + ctxImport + "type Source interface{ Connector(ctx context.Context) (connectorv1.ConnectorClient, error) }\n"
	cases := map[string]struct {
		files map[string]string
		file  string
		line  int
		want  string
	}{
		"Apply on an inferred variable under cmd/x/internal/proto": {
			map[string]string{clientPath: src, "cmd/x/internal/proto/evil/e.go": "package evil\n" + clientImport + ctxImport + "func f(s client.Source) { cc, _ := s.Connector(context.Background()); cc.Apply(context.Background(), nil) }\n"},
			"cmd/x/internal/proto/evil/e.go", 4, "Apply write RPC"},
		"the client held under cmd/x/internal/proto": {
			map[string]string{clientPath: src, "cmd/x/internal/proto/evil/e.go": "package evil\n" + clientImport + ctxImport + "func f(s client.Source) { cc, _ := s.Connector(context.Background()); _ = cc }\n"},
			"cmd/x/internal/proto/evil/e.go", 4, "variable, field or parameter cc"},
		"unexported holder and Apply with a Clearance under cmd/x/internal/directory/client": {
			map[string]string{"cmd/x/internal/directory/client/y/y.go": "package y\n" + connImport + ctxImport + stepImport +
				"type h struct{ c connectorv1.ConnectorClient }\nfunc (x h) send(clr step.Clearance) { x.c.Apply(context.Background(), nil) }\n"},
			"cmd/x/internal/directory/client/y/y.go", 5, "variable, field or parameter c"},
		"Apply with a Clearance under cmd/x/internal/directory/client": {
			map[string]string{"cmd/x/internal/directory/client/y/y.go": "package y\n" + connImport + ctxImport + stepImport +
				"func send(c interface{ Apply(context.Context, *connectorv1.ApplyRequest, ...connectorv1.CallOption) (*connectorv1.ApplyResponse, error) }, clr step.Clearance) { c.Apply(context.Background(), nil) }\n"},
			"cmd/x/internal/directory/client/y/y.go", 5, "Apply write RPC"},
		"Clearance of a look-alike step package elsewhere does not open the send path": {
			map[string]string{
				"internal/modules/fakestep/step/s.go": "package step\ntype Clearance struct{}\n",
				clientPath:                            "package client\n" + connImport + ctxImport + "import step \"" + mod + "/internal/modules/fakestep/step\"\ntype t struct{ c connectorv1.ConnectorClient }\nfunc (x t) send(clr step.Clearance) { x.c.Apply(context.Background(), nil) }\n"},
			clientPath, 6, "Apply write RPC"},
	}
	for name, c := range cases {
		wantAt(t, name, typedO2(t, c.files), c.file, c.line, c.want)
	}
}

// A real directory whose name ends in _test is that directory, not its sibling: only a genuine external
// test package (package x_test, _test.go files only, in the directory of x) is placed at x (security review of T-1408).
func TestO2TypedTestSuffixDirsGetNoExemption(t *testing.T) {
	src := "package client\n" + connImport + ctxImport + "type Source interface{ Connector(ctx context.Context) (connectorv1.ConnectorClient, error) }\n"
	cases := map[string]struct {
		files map[string]string
		file  string
		line  int
		want  string
	}{
		"identifier-free Apply under a real internal/proto_test dir": {
			map[string]string{clientPath: src, "internal/proto_test/e.go": "package evil\n" + clientImport + ctxImport + "func f(s client.Source) { cc, _ := s.Connector(context.Background()); cc.Apply(context.Background(), nil) }\n"},
			"internal/proto_test/e.go", 4, "Apply write RPC"},
		"the client held under a real internal/proto_test dir": {
			map[string]string{clientPath: src, "internal/proto_test/e.go": "package evil\n" + clientImport + ctxImport + "func f(s client.Source) { cc, _ := s.Connector(context.Background()); _ = cc }\n"},
			"internal/proto_test/e.go", 4, "variable, field or parameter cc"},
		"unexported holder and Apply with a Clearance under internal/directory/client_test": {
			map[string]string{"internal/directory/client_test/y.go": "package y\n" + connImport + ctxImport + stepImport +
				"type h struct{ c connectorv1.ConnectorClient }\nfunc (x h) send(clr step.Clearance) { x.c.Apply(context.Background(), nil) }\n"},
			"internal/directory/client_test/y.go", 5, "variable, field or parameter c"},
		"test-only package proto_test in a real internal/proto_test dir": {
			map[string]string{clientPath: src, "internal/proto_test/e_test.go": "package proto_test\n" + clientImport + ctxImport + "func f(s client.Source) { cc, _ := s.Connector(context.Background()); cc.Apply(context.Background(), nil) }\n"},
			"internal/proto_test/e_test.go", 4, "Apply write RPC"},
	}
	for name, c := range cases {
		wantAt(t, name, typedO2(t, c.files), c.file, c.line, c.want)
	}
	// The genuine external test package of directory/client keeps the client package's test allowance.
	vs := typedO2(t, map[string]string{
		clientPath:                            src,
		"internal/directory/client/x_test.go": "package client_test\n" + connImport + ctxImport + "func tf(c connectorv1.ConnectorClient) { c.Apply(context.Background(), nil) }\n",
	})
	for _, v := range vs {
		if strings.HasPrefix(v.Pos, "internal/directory/client/x_test.go") {
			t.Errorf("external test package of directory/client lost its allowance: %v", v)
		}
	}
}

// A //line directive renames a file in positions; it must never grant a _test.go allowance. Every file-based
// exemption reads the real filename (security review of T-1408).
func TestO2TypedLineDirectiveGetsNoExemption(t *testing.T) {
	src := "package client\n" + connImport + ctxImport + "type Source interface{ Connector(ctx context.Context) (connectorv1.ConnectorClient, error) }\n"
	const dir = "//line zz_evil_test.go:1\n"
	cases := map[string]struct {
		files map[string]string
		file  string
		line  int
		want  string
	}{
		"identifier-free Apply in a non-test compose/server file posing as a test": {
			map[string]string{clientPath: src, "internal/compose/server/zz_evil.go": dir + "package server\n" + clientImport + ctxImport + "func f(s client.Source) { cc, _ := s.Connector(context.Background()); cc.Apply(context.Background(), nil) }\n"},
			"internal/compose/server/zz_evil.go", 5, "Apply write RPC"},
		"the client held in that file": {
			map[string]string{clientPath: src, "internal/compose/server/zz_evil.go": dir + "package server\n" + clientImport + ctxImport + "func f(s client.Source) { cc, _ := s.Connector(context.Background()); _ = cc }\n"},
			"internal/compose/server/zz_evil.go", 5, "variable, field or parameter cc"},
		"Apply without a Clearance in a non-test directory/client file posing as a test": {
			map[string]string{"internal/directory/client/zz_evil.go": dir + "package client\n" + connImport + ctxImport + "func zzEvil(cc connectorv1.ConnectorClient) { cc.Apply(context.Background(), nil) }\n"},
			"internal/directory/client/zz_evil.go", 5, "Apply write RPC"},
	}
	for name, c := range cases {
		wantAt(t, name, typedO2(t, c.files), c.file, c.line, c.want)
	}
	// The genuine _test.go fake of compose/server keeps its allowance.
	vs := typedO2(t, map[string]string{
		clientPath:                          src,
		"internal/compose/server/p_test.go": "package server\n" + connImport + "type fake struct{ c connectorv1.ConnectorClient }\n",
	})
	if len(vs) != 0 {
		t.Fatalf("violations = %v", vs)
	}
}

func TestO2TypedAllowed(t *testing.T) {
	vs := typedO2(t, map[string]string{
		clientPath: "package client\n" + connImport + ctxImport + stepImport +
			"type Reader interface{ Describe(ctx context.Context, in *connectorv1.DescribeRequest, opts ...connectorv1.CallOption) (*connectorv1.DescribeResponse, error) }\n" +
			"type Source interface{ Connector(ctx context.Context) (connectorv1.ConnectorClient, error) }\n" +
			"type t struct{ c connectorv1.ConnectorClient }\n" +
			"type alias = connectorv1.ConnectorClient\n" +
			"type fake struct{ connectorv1.ConnectorClient }\n" +
			"func (x t) send(clr step.Clearance) { x.c.Apply(context.Background(), nil); x.c.Plan(context.Background(), nil) }\n" +
			"func Describe(c connectorv1.ConnectorClient) Reader { return c }\n",
		"internal/directory/client/c_test.go": "package client\n" + connImport + ctxImport + "func tf(c connectorv1.ConnectorClient) { c.Apply(context.Background(), nil) }\n",
		"internal/modules/a/a.go":             "package a\n" + clientImport + ctxImport + connImport + "func f(r client.Reader) { r.Describe(context.Background(), &connectorv1.DescribeRequest{}) }\n",
		"internal/compose/server/p_test.go":   "package x\n" + connImport + "var _ connectorv1.ConnectorClient\ntype fake struct{ c connectorv1.ConnectorClient }\nfunc (fake) Connector() (connectorv1.ConnectorClient, error) { return nil, nil }\n",
		"internal/connector/x/x_test.go":      "package x\n" + connImport + "var _ []connectorv1.ConnectorClient\n",
		"internal/modules/b/b.go":             "package b\ntype Step struct{}\ntype T interface{ Apply() }\nfunc f(t T) { t.Apply() }\n",
	})
	if len(vs) != 0 {
		t.Fatalf("violations = %v", vs)
	}
}

func TestO2TypedOnTheRepository(t *testing.T) {
	vs, err := CheckTyped("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.Check == "O2" {
			t.Errorf("O2 type-aware on the repository: %v", v)
		}
	}
}
