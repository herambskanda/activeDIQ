package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
)

const e2eImpl = `package pslit

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// Quote is a correct pslit: every one of the five single-quote characters is doubled.
func Quote(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", errors.New("InvalidUTF16")
	}
	if strings.ContainsRune(s, 0) {
		return "", errors.New("NulInString")
	}
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		b.WriteRune(r)
		if strings.ContainsRune("'‘’‚‛", r) {
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String(), nil
}

// Unquote is the inverse the fuzz target checks.
func Unquote(q string) string {
	body := q[1 : len(q)-1]
	var b strings.Builder
	rs := []rune(body)
	for i := 0; i < len(rs); i++ {
		b.WriteRune(rs[i])
		if strings.ContainsRune("'‘’‚‛", rs[i]) {
			i++
		}
	}
	return b.String()
}
`

const e2eTest = `package pslit

import (
	"testing"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/pslit", "pslit", func(r corpus.Record) (corpus.Result, error) {
		if r.ID == "PSQ-07" && SKIP {
			return corpus.Result{}, corpustest.Skip("not routed yet")
		}
		in, err := r.Arg("value")
		if err != nil {
			return corpus.Result{}, err
		}
		q, err := Quote(in.Text())
		if err != nil {
			return corpustest.Err(err.Error()), nil
		}
		return corpustest.Render(q), nil
	})
}

func FuzzRoundTrip(f *testing.F) {
	corpustest.Seed(f, "pslit")
	f.Fuzz(func(t *testing.T, in []byte) {
		if !utf8.Valid(in) {
			return
		}
		q, err := Quote(string(in))
		if err != nil {
			return
		}
		if Unquote(q) != string(in) {
			t.Fatalf("Unquote(Quote(%q)) = %q", in, Unquote(q))
		}
	})
}
`

func e2eTree(t *testing.T, skip bool) string {
	t.Helper()
	repo, _ := filepath.Abs("../../..")
	root := t.TempDir()
	write := func(p, body string) {
		must(t, os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755))
		must(t, os.WriteFile(filepath.Join(root, p), []byte(body), 0o644))
	}
	// The module path sits under the product module's path, so the fixture may import its internal
	// packages (the kit) while living in a throw-away directory.
	write("go.mod", "module github.com/skenzeriq/activediq/fixture\n\ngo 1.27.0\n\nrequire github.com/skenzeriq/activediq v0.0.0\n\nreplace github.com/skenzeriq/activediq => "+repo+"\n")
	sum, _ := os.ReadFile(filepath.Join(repo, "go.sum"))
	write("go.sum", string(sum))
	real, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(corpus.Dir), "pslit.jsonl"))
	must(t, err)
	write(corpus.Dir+"/pslit.jsonl", string(real))
	write(corpus.Dir+"/"+ManifestFile, oneImpl)
	write("internal/platform/pslit/pslit.go", e2eImpl)
	test := strings.Replace(e2eTest, "SKIP", map[bool]string{true: "true", false: "false"}[skip], 1)
	write("internal/platform/pslit/pslit_test.go", test)
	must(t, doUpdateLock(root))
	return root
}

// The whole path with a real Go implementation: the gate runs the declared test, which runs the
// real corpus through corpustest.Run, writes the report, and the gate reads it back.
func TestEndToEndGoImplementation(t *testing.T) {
	root := e2eTree(t, false)
	clean(t, gate(t, root, ExecRunner))

	// the fuzz target in the same package really fuzzes
	man, err := loadManifest(corpusDir(root))
	must(t, err)
	var log []string
	fs := RunFuzz(root, man, 2*time.Second, false, 1, ExecRunner, func(l string) { log = append(log, l) })
	clean(t, fs)
	if len(log) != 1 || !strings.Contains(log[0], "FuzzRoundTrip") || !strings.HasSuffix(log[0], "ok") {
		t.Fatalf("fuzz log: %q", log)
	}
}

func TestEndToEndImplementationThatSkipsARecord(t *testing.T) {
	fs := gate(t, e2eTree(t, true), ExecRunner)
	expect(t, fs, "skipped-record", "implementation go/pslit skips record PSQ-07 of unit pslit")
	expect(t, fs, "tests-failed", "PSQ-07: skipped (not routed yet)")
}
