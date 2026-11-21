package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, marker bool, review string) string {
	t.Helper()
	root := t.TempDir()
	must := func(p, s string) {
		p = filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	body := "syntax = \"proto3\";\npackage skenzeriq.agent.v1;\n"
	if marker {
		body = "// contract: frozen\n" + body
	}
	must(protoDir+"/agent.proto", body)
	if review != "" {
		must(reviewFile, review)
	}
	return root
}

func TestU4(t *testing.T) {
	cases := []struct {
		name   string
		marker bool
		review string
		fail   bool
	}{
		{"frozen, review absent (negative fixture)", true, "", true},
		{"frozen, review draft (negative fixture)", true, "---\nstatus: draft\n---\n", true},
		{"frozen, review has no frontmatter", true, "status: accepted\n", true},
		{"frozen, review accepted", true, "---\ntitle: x\nstatus: accepted\n---\n", false},
		{"not frozen, review absent", false, "", false},
	}
	for _, c := range cases {
		vs, err := check(fixture(t, c.marker, c.review))
		if err != nil {
			t.Fatal(c.name, err)
		}
		if c.fail != (len(vs) > 0) {
			t.Errorf("%s: violations=%v, want fail=%v", c.name, vs, c.fail)
		}
		if c.fail && !strings.Contains(vs[0], "ADR-0002 U4") {
			t.Errorf("%s: violation does not name the clause: %s", c.name, vs[0])
		}
	}
}
