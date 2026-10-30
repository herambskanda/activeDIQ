package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasLine(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// repoRoot is the real tree: the checker must be green on main, which is also what `make fitness-sso` says.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Join(wd, "..", "..", "..")
}

func TestRealTreeImportsAndFloors(t *testing.T) {
	imp, err := CheckImports(repoRoot(t))
	if err != nil || len(imp) != 0 {
		t.Fatalf("imports: %v %v", imp, err)
	}
	mod, err := CheckModule(repoRoot(t))
	if err != nil || len(mod) != 0 {
		t.Fatalf("module: %v %v", mod, err)
	}
}

func TestRealSpecChecks(t *testing.T) {
	got, err := SpecChecks(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	n := map[string]int{}
	for _, c := range got {
		n[c[:4]]++
	}
	if n["OIDC"] != 17 || n["SAML"] != 19 {
		t.Fatalf("spec checks %v; §4 has OIDC-1..17 and §5 SAML-1..19", n)
	}
}

func TestFenceBoundaries(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module m\n\ngo 1.27.3\n")
	// inside the fence, including the test IdP subpackage: allowed
	write(t, root, samlDir+"/a.go", "package saml\nimport _ \"github.com/beevik/etree\"\nimport _ \"encoding/xml\"\n")
	write(t, root, samlDir+"/samltest/b.go", "package samltest\nimport _ \"github.com/russellhaering/goxmldsig\"\n")
	write(t, root, oidcDir+"/c.go", "package oidc\nimport _ \"github.com/go-jose/go-jose/v4\"\n")
	// a sibling whose name merely starts with the fence's name is outside it
	write(t, root, samlDir+"x/d.go", "package samlx\nimport _ \"github.com/beevik/etree\"\n")
	// SAML library from the OIDC package, JOSE from the SAML package
	write(t, root, oidcDir+"/e.go", "package oidc\nimport _ \"github.com/russellhaering/goxmldsig\"\n")
	write(t, root, samlDir+"/f.go", "package saml\nimport _ \"github.com/go-jose/go-jose/v4/jwt\"\n")
	// encoding/xml: banned under authn, allowed elsewhere; testdata and dot directories are not compiled
	write(t, root, authnDir+"/session/g.go", "package session\nimport _ \"encoding/xml\"\n")
	write(t, root, "internal/other/h.go", "package other\nimport _ \"encoding/xml\"\n")
	write(t, root, authnDir+"/testdata/i.go", "package x\nimport _ \"encoding/xml\"\n")
	got, err := CheckImports(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{samlDir + "x/d.go:2", oidcDir + "/e.go:2", samlDir + "/f.go:2", authnDir + "/session/g.go:2"} {
		if !hasLine(got, want) {
			t.Errorf("no violation naming %s in %v", want, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("want exactly 4 violations, got %v", got)
	}
}

func TestFloors(t *testing.T) {
	cases := []struct {
		name, mod, want string
	}{
		{"at the floor", "require github.com/russellhaering/goxmldsig v1.6.0\nrequire github.com/russellhaering/gosaml2 v0.12.0\n", ""},
		{"above", "require github.com/russellhaering/goxmldsig v1.6.1\n", ""},
		{"absent", "", ""},
		{"goxmldsig 1.5.0", "require github.com/russellhaering/goxmldsig v1.5.0\n", "goxmldsig v1.5.0"},
		{"gosaml2 0.11.0", "require github.com/russellhaering/gosaml2 v0.11.0\n", "gosaml2 v0.11.0"},
		{"replace lower", "require github.com/russellhaering/goxmldsig v1.6.1\nreplace github.com/russellhaering/goxmldsig => github.com/russellhaering/goxmldsig v1.5.0\n", "replaces"},
		{"replace local", "require github.com/russellhaering/goxmldsig v1.6.1\nreplace github.com/russellhaering/goxmldsig => ../x\n", "cannot be checked"},
		{"replace fork", "require github.com/russellhaering/goxmldsig v1.6.1\nreplace github.com/russellhaering/goxmldsig => example.com/fork v9.0.0\n", "use the module itself"},
	}
	for _, c := range cases {
		root := t.TempDir()
		write(t, root, "go.mod", "module m\n\ngo 1.27.3\n"+c.mod)
		got, err := CheckModule(root)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if c.want == "" && len(got) != 0 || c.want != "" && !hasLine(got, c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, got)
		}
	}
}

const miniSpec = "## 4. OIDC\n| OIDC-1 | a |\n| OIDC-2 | b |\n## 5. SAML\n| SAML-1 | a |\n## 6. Shared\n| SSO-1 | c |\n"

func rec(id, class string, cites ...string) string {
	q := make([]string, len(cites))
	for i, c := range cites {
		q[i] = `"` + c + `"`
	}
	return `{"id":"` + id + `","class":"` + class + `","cites":[` + strings.Join(q, ",") + `],"build":"b","expect":"refuse","reason":"r"}`
}

func miniTree(t *testing.T) string {
	root := t.TempDir()
	write(t, root, specFile, miniSpec)
	for i, c := range []string{"forged", "wrapped", "replayed", "misaddressed", "malformed"} {
		id := "S-" + string(rune('A'+i))
		write(t, root, corpusDir+"/saml/"+id+".json", rec(id, c, "SAML-1", "SSO-1"))
	}
	for i, c := range []string{"forged", "replayed", "misaddressed", "malformed"} {
		id := "O-" + string(rune('A'+i))
		write(t, root, corpusDir+"/oidc/"+id+".json", rec(id, c, "OIDC-"+string(rune('1'+i%2))))
	}
	return root
}

func TestCorpusCoverage(t *testing.T) {
	root := miniTree(t)
	res, err := CheckCorpus(root)
	if err != nil || len(res.Violations) != 0 || len(res.Pending) != 0 {
		t.Fatalf("clean tree: %+v %v", res, err)
	}
	// each cited number is named when its last citing record goes
	if err := os.Remove(filepath.Join(root, corpusDir, "oidc", "O-B.json")); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(root, corpusDir, "oidc", "O-D.json"))
	res, _ = CheckCorpus(root)
	if !hasLine(res.Violations, "oidc: OIDC-2 is cited by no corpus record") || !hasLine(res.Violations, `no "replayed" record`) {
		t.Fatalf("got %v", res.Violations)
	}
}

func TestCorpusPendingOnlyWhileAbsent(t *testing.T) {
	root := miniTree(t)
	if err := os.RemoveAll(filepath.Join(root, corpusDir, "oidc")); err != nil {
		t.Fatal(err)
	}
	res, _ := CheckCorpus(root)
	if len(res.Violations) != 0 || len(res.Pending) != 1 || !strings.Contains(res.Pending[0], "T-0911") {
		t.Fatalf("absent OIDC corpus must be listed pending: %+v", res)
	}
	write(t, root, oidcDir+"/c_test.go", "package oidc\nfunc TestCorpus(t *testing.T) {}\n")
	if res, _ = CheckCorpus(root); !hasLine(res.Violations, "oidc: no corpus records") {
		t.Fatalf("TestCorpus without records must fail: %+v", res)
	}
	// SAML has no pending allowance
	root = miniTree(t)
	_ = os.RemoveAll(filepath.Join(root, corpusDir, "saml"))
	if res, _ = CheckCorpus(root); !hasLine(res.Violations, "saml: no corpus records") {
		t.Fatalf("absent SAML corpus must fail: %+v", res)
	}
}

func TestCorpusRecordShape(t *testing.T) {
	root := miniTree(t)
	write(t, root, corpusDir+"/saml/S-A.json", rec("S-X", "forged", "SAML-1"))
	write(t, root, corpusDir+"/saml/S-B.json", rec("S-B", "wrapped", "SAML-7"))
	write(t, root, corpusDir+"/saml/S-C.json", rec("S-C", "replayed", "OIDC-1"))
	write(t, root, corpusDir+"/saml/S-D.json", rec("S-D", "bogus", "SAML-1"))
	write(t, root, corpusDir+"/saml/S-E.json", `{"id":"S-E","class":"malformed","cites":[],"expect":"accept"}`)
	res, _ := CheckCorpus(root)
	for _, w := range []string{`id "S-X" must equal`, `cites "SAML-7"`, `cites "OIDC-1"`, `class "bogus"`, "cites no check number", `must expect "refuse"`} {
		if !hasLine(res.Violations, w) {
			t.Errorf("missing %q in %v", w, res.Violations)
		}
	}
}

func TestSubtestsJudgement(t *testing.T) {
	res := &Result{Records: map[string][]string{"saml": {"S-A", "S-B"}}}
	run := func(lines ...string) func(context.Context, string, []string, []string) ([]byte, error) {
		return func(context.Context, string, []string, []string) ([]byte, error) {
			return []byte(strings.Join(lines, "\n")), nil
		}
	}
	ev := func(action, test string) string {
		return `{"Action":"` + action + `","Package":"p","Test":"` + test + `"}`
	}
	ok := run(ev("pass", "TestCorpus/S-A"), ev("pass", "TestCorpus/S-B"), ev("pass", "TestCorpus"))
	if got, err := CheckSubtests(context.Background(), ".", res, ok); err != nil || len(got) != 0 {
		t.Fatalf("clean: %v %v", got, err)
	}
	missing := run(ev("pass", "TestCorpus/S-A"), ev("pass", "TestCorpus"))
	if got, _ := CheckSubtests(context.Background(), ".", res, missing); !hasLine(got, "S-B") || !hasLine(got, "subtest-missing") {
		t.Fatalf("missing subtest: %v", got)
	}
	none := run(ev("pass", "TestOther"))
	if got, _ := CheckSubtests(context.Background(), ".", res, none); !hasLine(got, "test-missing") {
		t.Fatalf("no TestCorpus: %v", got)
	}
}
