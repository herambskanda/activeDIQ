package main

import (
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

func fixture(t *testing.T) string {
	root := t.TempDir()
	write(t, root, "go.mod", "module github.com/skenzeriq/activediq\n\ngo 1.22\n")
	write(t, root, "internal/platform/authz/authz.go", `package authz

type ObjectID [16]byte

func FromOctets(b [16]byte) ObjectID { return ObjectID(b) }
`)
	write(t, root, "internal/platform/authz/authz_test.go", `package authz

func f(b [16]byte) ObjectID { return ObjectID(b) }
`)
	write(t, root, "internal/platform/authz/x_test.go", `package authz_test

import "github.com/skenzeriq/activediq/internal/platform/authz"

func f(b [16]byte) authz.ObjectID { return authz.ObjectID(b) }
`)
	// Negative fixture: no conversion; value/type use only.
	write(t, root, "internal/ok/ok.go", `package ok

import "github.com/skenzeriq/activediq/internal/platform/authz"

type GUID [16]byte

func Zero() authz.ObjectID { var id authz.ObjectID; return id }
func Other(g GUID) [16]byte { return [16]byte(g) }
`)
	return root
}

func run(t *testing.T, root string) []string {
	t.Helper()
	v, err := Check(root, "./...")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestNegativeFixturePasses(t *testing.T) {
	if v := run(t, fixture(t)); len(v) != 0 {
		t.Fatalf("expected no violations, got %v", v)
	}
}

func TestPositiveFixturesFail(t *testing.T) {
	cases := map[string]string{
		"plain": `package bad
import "github.com/skenzeriq/activediq/internal/platform/authz"
type GUID [16]byte
func F(g GUID) authz.ObjectID { return authz.ObjectID(g) }
`,
		"renamed": `package bad
import a "github.com/skenzeriq/activediq/internal/platform/authz"
func F(g [16]byte) a.ObjectID { return a.ObjectID(g) }
`,
		"dot": `package bad
import . "github.com/skenzeriq/activediq/internal/platform/authz"
func F(g [16]byte) ObjectID { return ObjectID(g) }
`,
		"alias": `package bad
import "github.com/skenzeriq/activediq/internal/platform/authz"
type A = authz.ObjectID
func F(g [16]byte) A { return A(g) }
`,
		"paren": `package bad
import "github.com/skenzeriq/activediq/internal/platform/authz"
func F(g [16]byte) authz.ObjectID { return (authz.ObjectID)(g) }
`,
		"in-test": `package bad
import ("testing"; "github.com/skenzeriq/activediq/internal/platform/authz")
func TestX(t *testing.T) { _ = authz.ObjectID([16]byte{1}) }
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			root := fixture(t)
			file := "internal/bad/bad.go"
			if name == "in-test" {
				file = "internal/bad/bad_test.go"
			}
			write(t, root, file, src)
			v := run(t, root)
			if len(v) != 1 || !strings.HasPrefix(v[0], "internal/bad/") || !strings.Contains(v[0], ".go:") {
				t.Fatalf("expected one file:line violation in internal/bad, got %v", v)
			}
		})
	}
}
