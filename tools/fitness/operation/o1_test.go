package main

import (
	"strings"
	"testing"
)

const stepImport = `import "` + mod + `/internal/platform/operation/step"` + "\n"

func o1(t *testing.T, files map[string]string) []Violation {
	t.Helper()
	root := tree(t, fixtureDAG, files)
	vs, err := CheckO1(root)
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

func TestO1Violations(t *testing.T) {
	cases := map[string]struct{ file, src, want string }{
		"struct field":                {"internal/modules/a/a.go", "package a\n" + stepImport + "type T struct{ s step.Step }\n", "struct field"},
		"pointer field":               {"internal/modules/a/a.go", "package a\n" + stepImport + "type T struct{ s *step.Step }\n", "struct field"},
		"global":                      {"internal/modules/a/a.go", "package a\n" + stepImport + "var kept step.Step\n", "package-level variable"},
		"slice":                       {"internal/modules/a/a.go", "package a\n" + stepImport + "func f(x []step.Step) {}\n", "slice or array"},
		"map":                         {"internal/modules/a/a.go", "package a\n" + stepImport + "var m map[string]step.Step\n", "map"},
		"chan":                        {"internal/modules/a/a.go", "package a\n" + stepImport + "var c chan step.Step\n", "channel"},
		"literal":                     {"internal/modules/a/a.go", "package a\n" + stepImport + "var _ = step.Step{}\n", "constructed"},
		"clearance":                   {"internal/modules/a/a.go", "package a\n" + stepImport + "var _ = step.Clearance{}\n", "constructed"},
		"minter":                      {"internal/modules/a/a.go", "package a\n" + stepImport + "var _, _ = step.TakeMinter()\n", "TakeMinter"},
		"minter type var":             {"internal/modules/a/a.go", "package a\n" + stepImport + "func f() { var m step.Minter; _ = m }\n", "step.Minter"},
		"minter new":                  {"internal/modules/a/a.go", "package a\n" + stepImport + "func f() { _ = new(step.Minter) }\n", "step.Minter"},
		"minter in operation subtree": {"internal/platform/operation/sub/a.go", "package a\n" + stepImport + "var _, _ = step.TakeMinter()\n", "TakeMinter"},
		"renamed import":              {"internal/modules/a/a.go", "package a\nimport s \"" + mod + "/internal/platform/operation/step\"\nvar _, _ = s.TakeMinter()\n", "TakeMinter"},
		"linkname":                    {"internal/modules/a/a.go", "package a\nimport _ \"unsafe\"\n//go:linkname x " + mod + "/internal/platform/operation/step.x\nvar x int\n", "linkname"},
		"test file":                   {"internal/modules/a/a_test.go", "package a\n" + stepImport + "var kept step.Step\n", "package-level variable"},
	}
	for name, c := range cases {
		vs := o1(t, map[string]string{c.file: c.src})
		if len(vs) != 1 || !strings.Contains(vs[0].Msg, c.want) || vs[0].Check != "O1" || !strings.HasPrefix(vs[0].Pos, c.file+":") {
			t.Errorf("%s: violations = %v, want one containing %q", name, vs, c.want)
		}
	}
}

func TestO1Allowed(t *testing.T) {
	vs := o1(t, map[string]string{
		"internal/platform/operation/a.go":      "package operation\n" + stepImport + "var m, _ = step.TakeMinter()\nfunc f(s step.Step) error { return s.Valid() }\n",
		"internal/platform/operation/step/s.go": "package step\ntype Step struct{ s *int }\nvar _ = Step{}\n",
		"internal/modules/a/a.go":               "package a\n" + stepImport + "func write(s step.Step, k step.Key) error { return s.Valid() }\ntype T struct{ k step.Key }\n",
		"internal/modules/b/b.go":               "package b\ntype Step struct{}\ntype T struct{ s Step }\n",
	})
	if len(vs) != 0 {
		t.Fatalf("violations = %v", vs)
	}
}

func TestO1OnTheRepository(t *testing.T) {
	vs, err := CheckO1("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 0 {
		t.Fatalf("violations = %v", vs)
	}
}
