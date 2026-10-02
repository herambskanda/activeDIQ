package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
)

// repoRoot is the repository root (two levels above tools/fitness/oracles' parent).
func repoRoot(t *testing.T) string {
	t.Helper()
	d, _ := os.Getwd()
	for ; d != "/"; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
	}
	t.Fatal("no go.mod above the test")
	return ""
}

// engine returns the PowerShell engine of this machine, failing the test (never skipping it) when none
// is available: an oracle that silently does not run is the false pass FF-SP6 exists to prevent.
func engine(t *testing.T) Engine {
	t.Helper()
	engineOnce.Do(func() {
		engineVal = Engine{Name: os.Getenv("SAFEPRIM_ORACLE_ENGINE")}
		if engineVal.Name == "" {
			engineVal = pickEngine("")
		}
		engineOK = engineVal.Version() != "unknown"
	})
	if !engineOK {
		t.Fatalf("no PowerShell oracle: install pwsh, or start Docker so the pinned image %s can run", PwshImage)
	}
	return engineVal
}

var (
	engineOnce sync.Once
	engineVal  Engine
	engineOK   bool
)

// asciiOnly is PatchIQ's escaper: it doubles only the ASCII apostrophe.
func asciiOnly(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// exact is the specified escaper: it doubles every one of the five single-quote characters.
func exact(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		b.WriteRune(r)
		if strings.ContainsRune("'‘’‚‛", r) {
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

func pslitCases(t *testing.T, quote func(string) string) []Case {
	t.Helper()
	cases, _, err := loadCases(repoRoot(t), "pslit", "golden", "")
	if err != nil {
		t.Fatal(err)
	}
	for i := range cases {
		cases[i].Output = quote(cases[i].Input.Text())
	}
	return cases
}

func TestPslitOracleAcceptsTheSpecifiedEscaperAndTheGolden(t *testing.T) {
	e := engine(t)
	golden, _, _ := loadCases(repoRoot(t), "pslit", "golden", "")
	both := append(pslitCases(t, exact), golden...) // the specified escaper, then the corpus's own expected values
	if n, fails, err := checkPslit(e, both); err != nil || len(fails) != 0 || n != 34 {
		t.Fatalf("checked %d, failures %v, err %v", n, fails, err)
	}
}

// The deliberate failing fixture of AC 2: an ASCII-only escaper fails PSQ-06.
func TestPslitOracleRejectsAnASCIIOnlyEscaper(t *testing.T) {
	_, fails, err := checkPslit(engine(t), pslitCases(t, asciiOnly))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(fails, "\n")
	for _, id := range []string{"PSQ-02", "PSQ-03", "PSQ-04", "PSQ-05", "PSQ-06", "PSQ-07", "PSQ-08", "PSQ-09"} {
		if !strings.Contains(got, id+":") {
			t.Errorf("an ASCII-only escaper must fail %s; failures:\n%s", id, got)
		}
	}
	for _, id := range []string{"PSQ-01", "PSQ-10", "PSQ-13"} {
		if strings.Contains(got, id+":") {
			t.Errorf("%s has no look-alike quote and must pass; failures:\n%s", id, got)
		}
	}
}

func TestPslitOracleRejectsShapes(t *testing.T) {
	e := engine(t)
	bad := []string{"'a'; calc", `"a"`, "'a' # x", `"a$(calc)"`, "'b'", "'a", "'a' 'a'"}
	var cases []Case
	for i, out := range bad {
		r := corpus.Record{ID: "X" + strconv.Itoa(i)}
		cases = append(cases, Case{Record: r, Input: corpus.Input{Raw: []byte("a")}, Output: out})
	}
	_, fails, err := checkPslit(e, cases)
	if err != nil || len(fails) != len(bad) {
		t.Fatalf("every malformed output must fail, got %d of %d: %v %v", len(fails), len(bad), fails, err)
	}
}

// The Windows scripts cannot run here, but PowerShell's own parser can at least prove they are valid
// PowerShell, so a typo does not wait for the Windows runner to be found.
func TestWindowsScriptsParse(t *testing.T) {
	e := engine(t)
	const parseOnly = `
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
$scripts = @([Console]::In.ReadToEnd() | ConvertFrom-Json)
$n = @(foreach ($s in $scripts) { $t = $null; $e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput([string]$s, [ref]$t, [ref]$e); $e.Count })
[Console]::Out.Write((ConvertTo-Json -InputObject $n -Compress))`
	var counts []int
	if err := e.Run(parseOnly, []string{winSidScript, winGuidScript, pslitScript}, &counts); err != nil {
		t.Fatal(err)
	}
	for i, c := range counts {
		if c != 0 {
			t.Errorf("script %d has %d parse errors", i, c)
		}
	}
}

func lfCase(id, call, attr, value, output string) Case {
	a, _ := json.Marshal(attr)
	v, _ := json.Marshal(map[string]string{"utf8": value})
	return Case{Record: corpus.Record{ID: id, Call: call, Args: map[string]json.RawMessage{"attr": a, "value": v}},
		Input: corpus.Input{Raw: []byte(value)}, Output: output}
}

func TestLDAPFilterOracle(t *testing.T) {
	good := []Case{
		lfCase("LF-01", "Eq", "cn", "*)(uid=*", `(cn=\2a\29\28uid=\2a)`),
		lfCase("LF-02", "Eq", "cn", "*", `(cn=\2a)`),
		lfCase("LF-04", "Eq", "cn", `\`, `(cn=\5c)`),
		lfCase("LF-09", "Eq", "cn", "Zoë 😀", `(cn=Zo\c3\ab \f0\9f\98\80)`),
		lfCase("LF-X", "And", "", "", `(&(objectClass=user)(cn=a))`),
	}
	if n, fails := checkLDAPFilter(good); n != 5 || len(fails) != 0 {
		t.Fatalf("checked %d, failures %v", n, fails)
	}
	bad := map[string]Case{
		"unescaped injection": lfCase("LF-01", "Eq", "cn", "*)(uid=*", `(cn=*)(uid=*)`),
		"star is presence":    lfCase("LF-02", "Eq", "cn", "*", `(cn=*)`),
		"wrong value":         lfCase("LF-03", "Eq", "cn", "a", `(cn=b)`),
		"wrong attribute":     lfCase("LF-03", "Eq", "cn", "a", `(sn=a)`),
		"wrong shape":         lfCase("LF-03", "Eq", "cn", "a", `(&(cn=a)(sn=b))`),
		"unbalanced":          lfCase("LF-03", "Eq", "cn", "a", `(cn=a`),
	}
	for name, c := range bad {
		if _, fails := checkLDAPFilter([]Case{c}); len(fails) != 1 {
			t.Errorf("%s: want a failure, got %v", name, fails)
		}
	}
}

func TestLoadCasesFromReports(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, filepath.FromSlash(corpus.Dir))
	_ = os.MkdirAll(dir, 0o755)
	src, _ := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(corpus.Dir), "pslit.jsonl"))
	_ = os.WriteFile(filepath.Join(dir, "pslit.jsonl"), src, 0o644)
	f, _ := corpus.Load(dir, "pslit")
	rep := corpus.Report{Impl: "go/pslit", Unit: "pslit", CorpusSHA: f.SHA256}
	for _, r := range f.Records {
		s := "'x'"
		rep.Ran = append(rep.Ran, corpus.Ran{ID: r.ID, OK: true, Actual: corpus.Result{Render: &s}})
	}
	rd := t.TempDir()
	if err := corpus.WriteReport(corpus.ReportPath(rd, "corpus", "go/pslit", "pslit"), rep); err != nil {
		t.Fatal(err)
	}
	cases, _, err := loadCases(root, "pslit", "report", rd)
	if err != nil || len(cases) != 19 || cases[0].Output != "'x'" || !strings.HasPrefix(cases[0].Source, "report go/pslit") {
		t.Fatalf("%d cases, err %v", len(cases), err)
	}
	rep.CorpusSHA = "stale"
	_ = corpus.WriteReport(corpus.ReportPath(rd, "corpus", "go/pslit", "pslit"), rep)
	if _, _, err := loadCases(root, "pslit", "report", rd); err == nil || !strings.Contains(err.Error(), "different corpus") {
		t.Fatalf("a stale report must be refused: %v", err)
	}
	if _, _, err := loadCases(root, "pslit", "report", t.TempDir()); err == nil {
		t.Fatal("a missing report must be an error, not a skip")
	}
}
