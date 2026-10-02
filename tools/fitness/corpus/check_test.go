package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

// jsonl returns a unit file with nHostile hostile and nBenign non-hostile render records.
func jsonl(unit string, nHostile, nBenign int) string {
	var b strings.Builder
	for i := 1; i <= nHostile+nBenign; i++ {
		fmt.Fprintf(&b, `{"id":"%s-%02d","primitive":"%s","call":"Quote","args":{"value":{"utf8":"v%d"}},"expect":{"render":"'v%d'"},"hostile":%v,"source":"fixture","verified":"doc"}`+"\n",
			strings.ToUpper(unit[:2]), i, unit, i, i, i <= nHostile)
	}
	return b.String()
}

type fixture struct {
	corpus   map[string]string // unit -> file body
	manifest string
	lock     string // "" means: generate from the corpus
	gofiles  map[string]string
}

func (f fixture) build(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, filepath.FromSlash(corpus.Dir))
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fix.test\n\ngo 1.27.0\n"), 0o644))
	for u, body := range f.corpus {
		must(t, os.WriteFile(filepath.Join(dir, u+".jsonl"), []byte(body), 0o644))
	}
	if f.manifest != "" {
		must(t, os.WriteFile(filepath.Join(dir, ManifestFile), []byte(f.manifest), 0o644))
	}
	for p, body := range f.gofiles {
		must(t, os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755))
		must(t, os.WriteFile(filepath.Join(root, p), []byte(body), 0o644))
	}
	if f.lock != "" {
		must(t, os.WriteFile(filepath.Join(dir, LockFile), []byte(f.lock), 0o644))
	} else if len(f.corpus) > 0 {
		must(t, doUpdateLock(root))
	}
	return root
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func all() map[string]bool { return map[string]bool{"FF-SP4": true, "FF-SP5": true, "FF-SP8": true} }

func gate(t *testing.T, root string, run Runner) []Finding {
	t.Helper()
	fs, err := Check(Options{Root: root, Checks: all(), Run: run})
	must(t, err)
	return fs
}

func expect(t *testing.T, fs []Finding, rule, contains string) {
	t.Helper()
	for _, f := range fs {
		if f.Rule == rule && strings.Contains(f.String(), contains) {
			return
		}
	}
	t.Fatalf("want a finding [%s] containing %q, got:\n%s", rule, contains, join(fs))
}

func clean(t *testing.T, fs []Finding) {
	t.Helper()
	if len(fs) != 0 {
		t.Fatalf("want no findings, got:\n%s", join(fs))
	}
}

func join(fs []Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, f.String())
	}
	return strings.Join(s, "\n")
}

const oneImpl = `{"implementations":[{"name":"go/pslit","language":"go","tier":"S","units":["pslit"],"package":"internal/platform/pslit"}],
 "fuzz":[{"implementation":"go/pslit","unit":"pslit","target":"FuzzRoundTrip","properties":["roundtrip","noUnescapedSpecial"]}]}`

const pslitGo = "package pslit\n\nfunc Quote(s string) string { return s }\n"
const fuzzTest = `package pslit

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

func FuzzRoundTrip(f *testing.F) {
	corpustest.Seed(f, "pslit")
	f.Fuzz(func(t *testing.T, in []byte) {})
}
`

func base(hostile int) fixture {
	return fixture{
		corpus:   map[string]string{"pslit": jsonl("pslit", hostile, 2)},
		manifest: oneImpl,
		gofiles:  map[string]string{"internal/platform/pslit/pslit.go": pslitGo, "internal/platform/pslit/pslit_test.go": fuzzTest},
	}
}

// sim is a fake implementation: its "test run" writes the report the real kit would.
type sim struct {
	skip, wrong map[string]bool
	dropAll     bool
	stale       bool
	fail        bool
}

func (s sim) runner(impl, unit string) Runner {
	return func(root string, env []string, argv []string) (string, error) {
		dir := strings.TrimPrefix(env[0], corpus.ReportDirEnv+"=")
		f, err := corpus.Load(corpusDir(root), unit)
		if err != nil {
			return "", err
		}
		rep := corpustest.Check(impl, f, func(r corpus.Record) (corpus.Result, error) {
			if s.skip[r.ID] {
				return corpus.Result{}, corpustest.Skip("not routed")
			}
			if s.wrong[r.ID] {
				return corpustest.Render("wrong"), nil
			}
			_, raw := r.ExpectKey()
			var want string
			_ = json.Unmarshal(raw, &want)
			return corpustest.Render(want), nil
		})
		if s.stale {
			rep.CorpusSHA = "0123456789abcdef"
		}
		if !s.dropAll {
			must2(corpus.WriteReport(corpus.ReportPath(dir, "corpus", impl, unit), rep))
		}
		if s.fail {
			return "FAIL TestCorpus\n", fmt.Errorf("exit status 1")
		}
		return "ok", nil
	}
}

func must2(err error) {
	if err != nil {
		panic(err)
	}
}

func TestCleanTree(t *testing.T) {
	clean(t, gate(t, base(10).build(t), sim{}.runner("go/pslit", "pslit")))
}

func TestNineHostileRecordsFailNamingTheUnit(t *testing.T) {
	fs := gate(t, base(9).build(t), sim{}.runner("go/pslit", "pslit"))
	expect(t, fs, "min-hostile", `unit pslit has 9 records with "hostile": true, needs 10`)
}

func TestCorpusFileWithoutImplementationStillNeedsTen(t *testing.T) {
	f := fixture{corpus: map[string]string{"dn": jsonl("dn", 9, 0)}}
	fs := gate(t, f.build(t), nil)
	expect(t, fs, "min-hostile", "unit dn has 9 records")
	expect(t, fs, "min-hostile", "no implementation yet")
}

func TestImplementationSkippingARecordFails(t *testing.T) {
	fs := gate(t, base(10).build(t), sim{skip: map[string]bool{"PS-03": true}}.runner("go/pslit", "pslit"))
	expect(t, fs, "skipped-record", "implementation go/pslit skips record PS-03 of unit pslit")
}

func TestSkipAndRunnerSuccess(t *testing.T) {
	// the sim exits 0 even when it skips, as an old kit or a non-Go implementation might: the gate must still fail
	fs := gate(t, base(10).build(t), sim{skip: map[string]bool{"PS-03": true}}.runner("go/pslit", "pslit"))
	expect(t, fs, "skipped-record", "PS-03")
}

func TestRecordMissingFromReportFails(t *testing.T) {
	root := base(10).build(t)
	run := func(r string, env []string, argv []string) (string, error) {
		out, err := sim{}.runner("go/pslit", "pslit")(r, env, argv)
		dir := strings.TrimPrefix(env[0], corpus.ReportDirEnv+"=")
		p := corpus.ReportPath(dir, "corpus", "go/pslit", "pslit")
		var rep corpus.Report
		b, _ := os.ReadFile(p)
		must2(json.Unmarshal(b, &rep))
		rep.Ran = rep.Ran[:len(rep.Ran)-1]
		must2(corpus.WriteReport(p, rep))
		return out, err
	}
	expect(t, gate(t, root, run), "skipped-record", "did not run record PS-12")
}

func TestFailedRecordStaleCorpusNoReportAndFailingCommand(t *testing.T) {
	root := base(10).build(t)
	expect(t, gate(t, root, sim{wrong: map[string]bool{"PS-01": true}}.runner("go/pslit", "pslit")), "record-failed", "PS-01")
	expect(t, gate(t, root, sim{stale: true}.runner("go/pslit", "pslit")), "stale-corpus", "different corpus file")
	expect(t, gate(t, root, sim{dropAll: true}.runner("go/pslit", "pslit")), "no-report", "wrote no corpus report for unit pslit")
	expect(t, gate(t, root, sim{fail: true}.runner("go/pslit", "pslit")), "tests-failed", "FAIL TestCorpus")
}

func TestRecordRemovedWithoutSuccessor(t *testing.T) {
	fx := base(12)
	root := fx.build(t) // lock holds PS-01…PS-14
	body := jsonl("pslit", 12, 2)
	lines := strings.Split(strings.TrimSpace(body), "\n")
	must(t, os.WriteFile(filepath.Join(corpusDir(root), "pslit.jsonl"), []byte(strings.Join(lines[1:], "\n")+"\n"), 0o644)) // drop PS-01
	fs := gate(t, root, nil)
	expect(t, fs, "record-removed", "record PS-01 disappeared without a superseding record")

	// retired with a hostile successor that exists: accepted
	lk, _ := loadLock(corpusDir(root))
	lk.Retired = []Retired{{Unit: "pslit", ID: "PS-01", SupersededBy: "PS-02", Reason: "merged into PS-02"}}
	b, _ := json.Marshal(lk)
	must(t, os.WriteFile(filepath.Join(corpusDir(root), LockFile), b, 0o644))
	clean(t, gate(t, root, nil))

	// the successor must exist...
	lk.Retired[0].SupersededBy = "PS-99"
	b, _ = json.Marshal(lk)
	must(t, os.WriteFile(filepath.Join(corpusDir(root), LockFile), b, 0o644))
	expect(t, gate(t, root, nil), "record-removed", "superseding record PS-99 is not in the corpus")

	// ...and be hostile when the retired record was (PS-13 is benign here, PS-14 too)
	lk.Retired[0].SupersededBy = "PS-14"
	b, _ = json.Marshal(lk)
	must(t, os.WriteFile(filepath.Join(corpusDir(root), LockFile), b, 0o644))
	expect(t, gate(t, root, nil), "record-removed", "which is not hostile")
}

func TestReclassifiedHostileRecord(t *testing.T) {
	root := base(10).build(t)
	body := strings.Replace(jsonl("pslit", 10, 2), `"hostile":true`, `"hostile":false`, 1)
	must(t, os.WriteFile(filepath.Join(corpusDir(root), "pslit.jsonl"), []byte(body), 0o644))
	fs := gate(t, root, nil)
	expect(t, fs, "reclassified", "hostile record PS-01 was reclassified")
	expect(t, fs, "min-hostile", "has 9 records")
	if err := doUpdateLock(root); err == nil || !strings.Contains(err.Error(), "reclassified") {
		t.Fatalf("-update-lock must refuse to downgrade: %v", err)
	}
}

func TestNewRecordNeedsLockUpdate(t *testing.T) {
	root := base(10).build(t)
	body := jsonl("pslit", 11, 2)
	must(t, os.WriteFile(filepath.Join(corpusDir(root), "pslit.jsonl"), []byte(body), 0o644))
	expect(t, gate(t, root, nil), "lock-stale", "not in "+LockFile)
	must(t, doUpdateLock(root))
	clean(t, gate(t, root, nil))
}

func TestUndeclaredImplementationInAHome(t *testing.T) {
	fx := fixture{
		corpus:  map[string]string{"proc": jsonl("proc", 10, 0)},
		gofiles: map[string]string{"internal/platform/proc/proc.go": "package proc\n"},
	}
	fs := gate(t, fx.build(t), nil)
	expect(t, fs, "undeclared-implementation", "no implementation in testdata/safe-primitives/implementations.json declares proc")

	// a subpackage of a home counts, a generated or exempt subpackage does not
	fx = fixture{gofiles: map[string]string{"internal/platform/store/exempt/e.go": "package exempt\n", "internal/platform/store/sqlcdb/q.go": "package sqlcdb\n"}}
	clean(t, gate(t, fx.build(t), nil))
	fx = fixture{gofiles: map[string]string{"internal/platform/store/pool.go": "package store\n"}}
	expect(t, gate(t, fx.build(t), nil), "undeclared-implementation", "unit sql")
	fx = fixture{gofiles: map[string]string{"internal/export/csv/w.go": "package csv\n"}}
	expect(t, gate(t, fx.build(t), nil), "undeclared-implementation", "unit csv")
}

func TestManifestProblems(t *testing.T) {
	fx := base(10)
	fx.manifest = `{"implementations":[{"name":"go/x","language":"go","units":["nope"],"package":"internal/missing"},{"name":"go/x","language":"rust","units":["psx"]}]}`
	fs := gate(t, fx.build(t), nil)
	expect(t, fs, "manifest", `unit "nope" is not an FF-SP4 unit`)
	expect(t, fs, "manifest", "package internal/missing does not exist")
	expect(t, fs, "manifest", "declared twice")
	expect(t, fs, "manifest", "gives the command")
	expect(t, fs, "constant-argv", "names its constant-argv test")
}

func TestUnknownUnitFile(t *testing.T) {
	fx := fixture{corpus: map[string]string{"pslitt": jsonl("pslit", 10, 0)}, lock: "{}"}
	root := fx.build(t)
	fs, err := Check(Options{Root: root, Checks: all()})
	must(t, err)
	expect(t, fs, "schema", `"pslitt" is not an FF-SP4 unit`)
}

func TestFuzzDeclarations(t *testing.T) {
	// no target and no exemption
	fx := base(10)
	fx.manifest = strings.Split(oneImpl, `,
 "fuzz"`)[0] + "}"
	expect(t, gate(t, fx.build(t), sim{}.runner("go/pslit", "pslit")), "no-fuzz-target", "unit pslit of implementation go/pslit has no corpus-seeded fuzz target")

	// a stated reason is accepted
	fx.manifest = strings.Split(oneImpl, `,
 "fuzz"`)[0] + `,"fuzzExempt":[{"implementation":"go/pslit","unit":"pslit","reason":"no parser"}]}`
	clean(t, gate(t, fx.build(t), sim{}.runner("go/pslit", "pslit")))
	fx.manifest = strings.Split(oneImpl, `,
 "fuzz"`)[0] + `,"fuzzExempt":[{"implementation":"go/pslit","unit":"pslit","reason":" "}]}`
	expect(t, gate(t, fx.build(t), sim{}.runner("go/pslit", "pslit")), "fuzz-exempt", "needs a reason")

	// the target must exist, be seeded from this unit's corpus, and claim the properties
	fx = base(10)
	fx.gofiles["internal/platform/pslit/pslit_test.go"] = "package pslit\n"
	expect(t, gate(t, fx.build(t), sim{}.runner("go/pslit", "pslit")), "fuzz-target", "no func FuzzRoundTrip exists")
	fx = base(10)
	fx.gofiles["internal/platform/pslit/pslit_test.go"] = strings.Replace(fuzzTest, `corpustest.Seed(f, "pslit")`, ``, 1)
	expect(t, gate(t, fx.build(t), sim{}.runner("go/pslit", "pslit")), "fuzz-not-seeded", `corpustest.Seed(f, "pslit")`)
	fx = base(10)
	fx.gofiles["internal/platform/pslit/pslit_test.go"] = strings.Replace(fuzzTest, `Seed(f, "pslit")`, `Seed(f, "dn")`, 1)
	expect(t, gate(t, fx.build(t), sim{}.runner("go/pslit", "pslit")), "fuzz-not-seeded", "")
	fx = base(10)
	fx.manifest = strings.Replace(oneImpl, `"roundtrip","noUnescapedSpecial"`, `"roundtrip"`, 1)
	expect(t, gate(t, fx.build(t), sim{}.runner("go/pslit", "pslit")), "fuzz-properties", `must check "noUnescapedSpecial"`)
}

func TestConstantArgvGate(t *testing.T) {
	const man = `{"implementations":[{"name":"go/proc","language":"go","tier":"S","units":["proc"],"package":"internal/platform/proc","argvTest":"TestConstantArgv"}],
 "fuzzExempt":[{"implementation":"go/proc","unit":"proc","reason":"constant argv, no parser"}]}`
	fx := fixture{corpus: map[string]string{"proc": jsonl("proc", 10, 0)}, manifest: man,
		gofiles: map[string]string{"internal/platform/proc/proc.go": "package proc\n"}}
	root := fx.build(t)
	argv := func(rep *corpus.ArgvReport) Runner {
		return func(r string, env []string, a []string) (string, error) {
			dir := strings.TrimPrefix(env[0], corpus.ReportDirEnv+"=")
			if strings.Contains(strings.Join(a, " "), "TestConstantArgv") {
				if rep != nil {
					must2(corpus.WriteReport(corpus.ReportPath(dir, "argv", "go/proc", "argv"), *rep))
				}
				return "", nil
			}
			f, _ := corpus.Load(corpusDir(r), "proc")
			must2(corpus.WriteReport(corpus.ReportPath(dir, "corpus", "go/proc", "proc"), corpustest.Check("go/proc", f, func(rc corpus.Record) (corpus.Result, error) {
				_, raw := rc.ExpectKey()
				var want string
				_ = json.Unmarshal(raw, &want)
				return corpustest.Render(want), nil
			})))
			return "", nil
		}
	}
	clean(t, gate(t, root, argv(&corpus.ArgvReport{Impl: "go/proc", Requests: 500})))
	expect(t, gate(t, root, argv(nil)), "no-report", "constant-argv report")
	expect(t, gate(t, root, argv(&corpus.ArgvReport{Impl: "go/proc", Requests: 20})), "too-few-requests", "20 random requests")
	fs := gate(t, root, argv(&corpus.ArgvReport{Impl: "go/proc", Requests: 500, Mismatches: []string{"request 7 (seed 1): argv has 3 elements, the manifest has 2"}}))
	expect(t, fs, "argv-differs", "argv differs from the manifest's constant argv for 1 of 500 random requests")
}

func TestRunFuzzRefusesShortNightlyAndDetectsNotRun(t *testing.T) {
	m := &Manifest{
		Implementations: []Implementation{{Name: "go/pslit", Language: "go", Units: []string{"pslit"}, Package: "internal/platform/pslit"}},
		Fuzz:            []FuzzTarget{{Implementation: "go/pslit", Unit: "pslit", Target: "FuzzRoundTrip", Properties: []string{"roundtrip"}}},
	}
	fs := RunFuzz("", m, time.Minute, true, 1, nil, nil)
	expect(t, fs, "fuzz-time", "at least 10m0s per target")

	var log []string
	ok := func(string, []string, []string) (string, error) {
		time.Sleep(20 * time.Millisecond)
		return "fuzz: elapsed: 0s, execs: 1", nil
	}
	fs = RunFuzz("", m, 10*time.Millisecond, false, 1, ok, func(l string) { log = append(log, l) })
	clean(t, fs)
	if len(log) != 1 || !strings.Contains(log[0], "go/pslit") || !strings.Contains(log[0], "FuzzRoundTrip") || !strings.HasSuffix(log[0], "ok") {
		t.Fatalf("log must list the target: %q", log)
	}
	idle := func(string, []string, []string) (string, error) {
		return "testing: warning: no fuzz tests to fuzz\nPASS", nil
	}
	expect(t, RunFuzz("", m, time.Second, false, 1, idle, nil), "fuzz-not-run", "ended without fuzzing")
	crash := func(string, []string, []string) (string, error) {
		return "--- FAIL: FuzzRoundTrip\n    Failing input written to testdata/fuzz/FuzzRoundTrip/abc", fmt.Errorf("exit status 1")
	}
	expect(t, RunFuzz("", m, time.Second, false, 1, crash, nil), "fuzz-failed", "commit it as a regression seed")
	early := func(string, []string, []string) (string, error) { return "fuzz: elapsed: 0s", nil }
	expect(t, RunFuzz("", m, time.Hour, false, 1, early, nil), "fuzz-time", "ended after")
}

func TestSetVerified(t *testing.T) {
	root := base(10).build(t)
	res := filepath.Join(t.TempDir(), "r.json")
	must(t, os.WriteFile(res, []byte(`{"pslit":{"PS-01":"samba","PS-02":"windows"}}`), 0o644))
	must(t, doSetVerified(root, res))
	must(t, doSetVerified(root, res)) // idempotent
	f, err := corpus.Load(corpusDir(root), "pslit")
	must(t, err)
	if f.Records[0].Verified != "samba" || f.Records[1].Verified != "windows" || f.Records[2].Verified != "doc" {
		t.Fatalf("verified: %q %q %q", f.Records[0].Verified, f.Records[1].Verified, f.Records[2].Verified)
	}
	must(t, os.WriteFile(res, []byte(`{"pslit":{"PS-01":"windows"}}`), 0o644))
	must(t, doSetVerified(root, res))
	f, _ = corpus.Load(corpusDir(root), "pslit")
	if f.Records[0].Verified != "samba+windows" {
		t.Fatalf("verified = %q", f.Records[0].Verified)
	}
}

func TestEmptyRepositoryIsClean(t *testing.T) {
	clean(t, gate(t, t.TempDir(), ExecRunner))
}
