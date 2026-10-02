package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const good = `{"id":"PSQ-01","primitive":"pslit","call":"Quote","args":{"value":{"utf8":"O'Brien"}},"expect":{"render":"'O''Brien'"},"hostile":true,"source":"spec","verified":"doc"}
{"id":"PSQ-17","primitive":"pslit","call":"Quote","args":{"value":{"hex":"610062"}},"expect":{"error":"NulInString"},"hostile":true,"source":"spec","verified":"doc"}
{"id":"PSQ-14#1","primitive":"pslit","call":"Quote","args":{"value":"ʼ"},"expect":{"render":"'ʼ'"},"hostile":false,"verified":"doc"}
{"id":"PSQ-S1","primitive":"pslit","kind":"static","hostile":true,"verified":"doc"}
`

func write(t *testing.T, unit, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, unit+".jsonl"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadGood(t *testing.T) {
	f, err := Load(write(t, "pslit", good), "pslit")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Records) != 4 || f.Hostile() != 3 {
		t.Fatalf("records %d hostile %d", len(f.Records), f.Hostile())
	}
	if ids := f.RuntimeIDs(); len(ids) != 3 {
		t.Fatalf("runtime ids %v (the static record is not run)", ids)
	}
	in, err := f.Records[1].Arg("value")
	if err != nil || !in.IsHex || in.ValidUTF8() != true || in.Text() != "a\x00b" {
		t.Fatalf("hex input decoded wrong: %+v %v", in, err)
	}
	if in, _ := f.Records[2].Arg("value"); in.Text() != "ʼ" {
		t.Fatalf("bare string input: %q", in.Text())
	}
	if f.SHA256 != DigestHex([]byte(good)) {
		t.Fatal("digest is not the file's SHA-256")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]struct{ line, want string }{
		"implicit hostile": {`{"id":"A","primitive":"x","call":"c","expect":{"render":"r"},"verified":"doc"}`, "never inferred"},
		"unknown field":    {`{"id":"A","primitive":"x","call":"c","expect":{"render":"r"},"hostile":true,"verified":"doc","extra":1}`, "unknown field"},
		"two expectations": {`{"id":"A","primitive":"x","call":"c","expect":{"render":"r","error":"e"},"hostile":true,"verified":"doc"}`, "exactly one"},
		"no call":          {`{"id":"A","primitive":"x","expect":{"render":"r"},"hostile":true,"verified":"doc"}`, `needs a "call"`},
		"bad verified":     {`{"id":"A","primitive":"x","call":"c","expect":{"render":"r"},"hostile":true,"verified":"yes"}`, `"verified"`},
		"bad kind":         {`{"id":"A","primitive":"x","kind":"fuzz","hostile":true,"verified":"doc"}`, `"kind"`},
		"no id":            {`{"primitive":"x","hostile":true,"verified":"doc"}`, "no id"},
		"bad json":         {`{"id":`, "unexpected"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, "pslit", c.line+"\n"), "pslit")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
	dup := strings.Repeat(`{"id":"A","primitive":"x","kind":"static","hostile":true,"verified":"doc"}`+"\n", 2)
	if _, err := Load(write(t, "pslit", dup), "pslit"); err == nil || !strings.Contains(err.Error(), "duplicate record id A") {
		t.Fatalf("duplicate ids: %v", err)
	}
}

func TestLoadAllRejectsUnknownUnit(t *testing.T) {
	dir := write(t, "pslitt", good)
	_, problems, err := LoadAll(dir)
	if err != nil || len(problems) != 1 || !strings.Contains(problems[0], `"pslitt" is not an FF-SP4 unit`) {
		t.Fatalf("%v %v", problems, err)
	}
	if m, p, err := LoadAll(filepath.Join(dir, "missing")); err != nil || len(m) != 0 || len(p) != 0 {
		t.Fatalf("a missing corpus root is an empty corpus: %v %v %v", m, p, err)
	}
}

func TestWriteIsStable(t *testing.T) {
	dir := write(t, "pslit", good)
	f, _ := Load(dir, "pslit")
	f.Records[0].Verified = MergeVerified(f.Records[0].Verified, "samba")
	if err := Write(f.Path, f.Records); err != nil {
		t.Fatal(err)
	}
	g, err := Load(dir, "pslit")
	if err != nil || g.Records[0].Verified != "samba" || len(g.Records) != 4 {
		t.Fatalf("%v %+v", err, g.Records[0])
	}
	if !strings.Contains(string(mustRead(t, g.Path)), `"'O''Brien'"`) {
		t.Fatal("rewrite must not HTML-escape quotes")
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMergeVerified(t *testing.T) {
	for _, c := range [][3]string{
		{"doc", "samba", "samba"}, {"samba", "windows", "samba+windows"}, {"windows", "samba", "samba+windows"},
		{"samba+windows", "samba", "samba+windows"}, {"doc", "doc", "doc"}, {"libreoffice", "excel", "libreoffice+excel"},
	} {
		if got := MergeVerified(c[0], c[1]); got != c[2] {
			t.Errorf("MergeVerified(%q,%q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestFindRootOverride(t *testing.T) {
	t.Setenv("SAFEPRIM_CORPUS", "/somewhere")
	if r, err := FindRoot("."); err != nil || r != "/somewhere" {
		t.Fatalf("%q %v", r, err)
	}
}
