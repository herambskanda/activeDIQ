// Package latency_test is the universal-search latency benchmark (T-1102, ADR-0011 rule 14 and fitness
// function SE6): p95 under 200 ms per query class over 50,000 inventory objects on PostgreSQL 16 and 18, for an
// unscoped and a scoped caller, through the HTTP handler in process.
//
// Two tests drive one harness:
//
//   - TestSearchHarnessSmoke runs in `make ci` on a 1,200-object seed with a proportionally small ceiling. It
//     checks every answer against the brute-force oracle, so the harness and the oracle cannot rot, but it
//     enforces no time budget (a small seed proves nothing about latency).
//   - TestSearchLatency50k is the benchmark. It is opt-in (ACTIVEDIQ_SEARCH_LARGE_OBJECTS=50000, the
//     ACTIVEDIQ_*_LARGE convention of the reports scale tests, modules/reports.md), runs in the nightly job
//     (`make search-latency`, part of `make fitness-nightly`) and fails naming the class, caller, PostgreSQL
//     version and percentile that missed.
//
// Output format: the table of rows per class and version that T-0972 (report scale calibration) prints is
// the same shape (class, n, p50, p95, p99, max); the helpers summarize, ms and report in this package are what
// T-0972 should lift into a shared test-support package when it starts. Its 100,000-user report lab is not
// duplicated here.
package latency_test

import (
	"encoding/json"
	"os/exec"

	"context"
	"fmt"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/testlab/harnessdocker"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

// seedDigest50k pins the 50,000-object seed. A change here means the benchmark changed: say so in the commit.
const seedDigest50k = "8e30166cb3805ee0dddca8141a6b23b2c6a9566d26a12560ac452f21b329676f"

func TestSeedIsDeterministic(t *testing.T) {
	a, b := NewSeed(50000), NewSeed(50000)
	if a.Digest() != b.Digest() {
		t.Fatal("two generations of the same seed differ")
	}
	if got := a.Digest(); got != seedDigest50k {
		t.Fatalf("seed digest = %s, pinned %s: the seed changed", got, seedDigest50k)
	}
	if len(a.Objs) != 50000 {
		t.Fatalf("%d objects, want exactly 50,000", len(a.Objs))
	}
	for k, want := range map[string]int{"user": 30000, "group": 8000, "computer": 10000, "contact": 2000} {
		if got := a.Counts[kindOf(k)]; got != want {
			t.Errorf("%s: %d, want %d", k, got, want)
		}
	}
	if len(a.OUs) != 2*376 {
		t.Errorf("%d OUs, want 752 (376 per connection, six levels)", len(a.OUs))
	}
	var scopedVisible, hiddenByExclusion int
	for i := range a.Objs {
		if a.Visible("scoped", i) {
			scopedVisible++
		}
		if a.Objs[i].Conn == 0 && a.Under(a.Objs[i].OU, a.ScopedExclude()) {
			hiddenByExclusion++
		}
	}
	// The scoped caller must see a real slice and the excluded sub-OU must be large, or the scoped runs
	// prove nothing about trimming.
	if scopedVisible < 3000 || hiddenByExclusion < 5000 {
		t.Errorf("scoped caller sees %d objects, the exclusion hides %d: both must be substantial", scopedVisible, hiddenByExclusion)
	}
	t.Logf("scoped caller sees %d of 50000; the excluded sub-OU holds %d", scopedVisible, hiddenByExclusion)
}

func TestSearchHarnessSmoke(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		runBench(t, s, benchCfg{n: 1200, ceil: 240, per: 30, warm: 20, verify: 15})
	})
}

func TestSearchLatency50k(t *testing.T) {
	v := os.Getenv("ACTIVEDIQ_SEARCH_LARGE_OBJECTS")
	if v == "" {
		t.Skip("needs ACTIVEDIQ_SEARCH_LARGE_OBJECTS=50000 to measure (nightly: make search-latency)")
	}
	if n, _ := strconv.Atoi(v); n != 50000 {
		t.Fatalf("ACTIVEDIQ_SEARCH_LARGE_OBJECTS=%q: the benchmark is defined at exactly 50000 objects", v)
	}
	// 4 vCPU for the server side; the database container is limited below.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		limitContainer(t, s)
		runBench(t, s, benchCfg{n: 50000, ceil: 10000, per: 1000, warm: 200, verify: 25, enforce: true, plans: true, sweep: []int{5000, 10000, 20000, 40000}})
	})
}

// limitContainer gives the database the benchmark's machine profile: 4 CPUs and 8 GB (ticket acceptance 2).
func limitContainer(t *testing.T, s *storetest.Server) {
	t.Helper()
	out, err := execOut("docker", "ps", "-q", "--filter", "ancestor="+s.Image, "--filter", "label="+harnessdocker.OwnerLabel+"="+strconv.Itoa(os.Getpid()))
	ids := strings.Fields(out)
	if err != nil || len(ids) == 0 {
		t.Fatalf("no running container of %s to limit: %v %s", s.Image, err, out)
	}
	for _, id := range ids {
		if o, err := execOut("docker", "update", "--cpus=4", "--memory=8g", "--memory-swap=8g", id); err != nil {
			t.Fatalf("docker update %s: %v %s", id, err, o)
		}
	}
}

type benchCfg struct {
	n, ceil   int
	per, warm int  // timed queries per class and caller; warm-up queries
	verify    int  // queries per class checked against the oracle
	enforce   bool // a p95 over budget fails the test
	plans     bool // EXPLAIN ANALYZE probes (bounded work; fuzzy recheck)
	sweep     []int
}

type outcome struct {
	pg, caller, class string
	st                stats
}

// runBench is the whole benchmark against one PostgreSQL server.
func runBench(t *testing.T, s *storetest.Server, cfg benchCfg) {
	var out strings.Builder
	say := func(f string, a ...any) { fmt.Fprintf(&out, f+"\n", a...) }
	defer func() {
		t.Log("\n" + out.String())
		if dir := os.Getenv("ACTIVEDIQ_SEARCH_LARGE_OUT"); dir != "" && cfg.enforce {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(filepath.Join(dir, "search-latency-pg"+s.Version+".txt"), []byte(out.String()), 0o644); err != nil {
				t.Error(err)
			}
		}
	}()

	seed := NewSeed(cfg.n)
	w := newWorld(t, s, seed)
	say("search latency · PostgreSQL %s · %d objects · ceiling W=%d · GOMAXPROCS=%d · host CPUs=%d", s.Version, cfg.n, cfg.ceil, runtime.GOMAXPROCS(0), runtime.NumCPU())
	say("seed digest %s", seed.Digest())
	wrote := w.write(1000)
	say("seed written through inventory.Populator in %s; row counts asserted before measuring:\n%s", wrote.Round(time.Millisecond), w.assertSeed())
	if t.Failed() {
		t.FailNow()
	}
	w.analyze()
	var shared, ver string
	if err := w.db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
		if err := tx.QueryRow(ctx, `SHOW shared_buffers`).Scan(&shared); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SHOW server_version`).Scan(&ver)
	}); err != nil {
		t.Fatal(err)
	}
	say("server_version %s · shared_buffers %s · %d search-key rows · scoped caller sees %d objects", ver, shared, w.nKey, countVisible(seed, "scoped"))

	srv := w.newServer(cfg.ceil)
	classes := w.workload(max(cfg.per, cfg.verify), cfg.ceil)
	var ceilingRows []int
	if _, rows := w.calibrate(cfg.ceil*6/10, cfg.ceil); len(rows) > 0 {
		ceilingRows = rows[:min(len(rows), 8)]
	}
	for _, c := range classes {
		if len(c.texts) == 0 {
			if c.name == "ceiling" && !cfg.enforce {
				say("(no prefix of one or two letters holds %d–%d key rows on this small seed: ceiling class skipped)", cfg.ceil*6/10, cfg.ceil)
				continue
			}
			t.Fatalf("class %s has no queries: no one- or two-letter prefix holds %d–%d key rows, so the ceiling-sized class cannot be built; adjust the seed", c.name, cfg.ceil*6/10, cfg.ceil)
		}
	}
	say("ceiling-sized class: prefix texts holding %v matched key rows (W=%d)", ceilingRows, cfg.ceil)

	// Warm-up: round-robin over every class and both callers.
	for i := 0; i < cfg.warm; i++ {
		c := classes[i%len(classes)]
		if len(c.texts) == 0 {
			continue
		}
		caller := []string{"admin", "scoped"}[i/len(classes)%2]
		if code, _, _ := srv.post(caller, c.texts[i%len(c.texts)], 0); code != 200 {
			t.Fatalf("warm-up %s %q: status %d", caller, c.texts[i%len(c.texts)], code)
		}
	}

	// Timed runs.
	var results []outcome
	say("\n%-7s %-10s %6s %8s %8s %8s %8s   (ms; %d queries per row)", "caller", "class", "n", "p50", "p95", "p99", "max", cfg.per)
	for _, caller := range []string{"admin", "scoped"} {
		for _, c := range classes {
			if len(c.texts) == 0 {
				continue
			}
			ds := make([]time.Duration, 0, cfg.per)
			for i := 0; i < cfg.per; i++ {
				text := c.texts[i%len(c.texts)]
				code, body, d := srv.post(caller, text, 0)
				if code != 200 {
					t.Fatalf("%s %s %q: status %d: %s", caller, c.name, text, code, body)
				}
				ds = append(ds, d)
				// Hidden objects are never returned: checked on every timed answer, outside the clock.
				w.noHidden(t, caller, c.name, text, body)
			}
			st := summarize(ds)
			results = append(results, outcome{"pg" + s.Version, caller, c.name, st})
			say("%-7s %-10s %6d %8s %8s %8s %8s", caller, c.name, st.n, ms(st.p50), ms(st.p95), ms(st.p99), ms(st.max))
		}
	}

	// Oracle comparison on a sample of each class, with full pages so the sets can be compared.
	say("\nresult equality against the brute-force oracle (%d queries per class and caller, groupLimit 50):", cfg.verify)
	cache := map[string]*matched{}
	var disagreements []string
	for _, c := range classes {
		checked := 0
		for _, caller := range []string{"admin", "scoped"} {
			for i := 0; i < cfg.verify && i < len(c.texts); i++ {
				text := c.texts[i]
				m := cache[text]
				if m == nil {
					mm := w.match(text)
					w.fuzzyOracle(&mm)
					m = &mm
					cache[text] = m
				}
				code, body, _ := srv.post(caller, text, 50)
				if code != 200 {
					t.Fatalf("verify %s %q: status %d: %s", caller, text, code, body)
				}
				disagreements = append(disagreements, w.check(caller, text, body, m, cfg.ceil, 50)...)
				checked++
			}
		}
		say("  %-10s %4d answers compared", c.name, checked)
	}
	if len(disagreements) == 0 {
		say("  no disagreement with the oracle; no hidden object returned")
	}
	for _, d := range disagreements[:min(len(disagreements), 20)] {
		t.Errorf("oracle: %s", d)
	}
	if len(disagreements) > 20 {
		t.Errorf("oracle: ... and %d more disagreements", len(disagreements)-20)
	}

	if cfg.plans {
		w.planReport(t, say, cfg.ceil, classes)
	}
	for _, W := range cfg.sweep {
		w.sweepCeiling(t, say, W, cfg)
	}

	// The budget.
	say("")
	for _, r := range results {
		verdict := "ok"
		if r.st.p95 >= budget {
			verdict = "OVER BUDGET"
			msg := fmt.Sprintf("search latency budget missed: %s caller=%s class=%s p95=%sms (budget %dms)", r.pg, r.caller, r.class, ms(r.st.p95), budget.Milliseconds())
			if cfg.enforce {
				t.Error(msg)
			} else {
				say("(not enforced on the smoke seed) %s", msg)
			}
		}
		if cfg.enforce {
			say("%s %-7s %-10s p95 %7sms  %s", r.pg, r.caller, r.class, ms(r.st.p95), verdict)
		}
	}
}

func countVisible(s *Seed, caller string) (n int) {
	for i := range s.Objs {
		if s.Visible(caller, i) {
			n++
		}
	}
	return n
}

// noHidden fails the test if the answer names an object the caller may not see.
func (w *world) noHidden(t *testing.T, caller, class, text string, body []byte) {
	t.Helper()
	var resp response
	if err := jsonUnmarshal(body, &resp); err != nil {
		t.Fatalf("%s %s %q: %v", caller, class, text, err)
	}
	for _, g := range resp.Groups {
		for _, it := range g.Items {
			if i, ok := w.byID[it.ObjectID]; !ok || !w.seed.Visible(caller, i) {
				t.Errorf("%s %s %q: returned %s, which the caller must not see", caller, class, text, it.ObjectID)
			}
		}
	}
}

// planReport proves the bounded-work claims on the full seed and records the fuzzy class's index recheck.
func (w *world) planReport(t *testing.T, say func(string, ...any), ceil int, classes []class) {
	t.Helper()
	sc := w.scopes()
	say("\nplan probes (EXPLAIN ANALYZE of the statement the handler runs):")
	// One letter: the work is the ceiling, whatever the scope hides.
	var oneRows [2]float64
	for i, caller := range []string{"admin", "scoped"} {
		f := w.explain(sc[caller], "a", ceil)
		oneRows[i] = f.rows["m_prefix"]
		say("  one letter %-7s m_prefix key rows read %6.0f (W+1 = %d) · seq scans %v · objects joined %0.f", caller, f.rows["m_prefix"], ceil+1, f.seqScans, f.objLoops)
		if f.rows["m_prefix"] > float64(ceil+1) {
			t.Errorf("one-letter %s: read %.0f prefix key rows, want at most W+1 = %d", caller, f.rows["m_prefix"], ceil+1)
		}
		if len(f.seqScans) > 0 {
			t.Errorf("one-letter %s: sequential scans %v", caller, f.seqScans)
		}
		if f.objLoops > float64(3*(ceil+1)) {
			t.Errorf("one-letter %s: %.0f loops on directory_objects, want at most 3(W+1)", caller, f.objLoops)
		}
	}
	if oneRows[0] != oneRows[1] {
		t.Errorf("a scoped one-letter query read %.0f key rows, the unscoped read %.0f: the work depends on the scope", oneRows[1], oneRows[0])
	}
	// Fuzzy: record what the index recheck removes.
	for _, c := range classes {
		if c.name != "fuzzy1" {
			continue
		}
		for _, caller := range []string{"admin", "scoped"} {
			var rows, rech, filt, exec float64
			var scan string
			const k = 8
			for i := 0; i < k; i++ {
				f := w.explain(sc[caller], c.texts[i], ceil)
				rows += f.rows["m_fuzzy"]
				rech += f.recheck
				filt += f.filtered
				exec += f.execTimeMS
				scan = f.fuzzyScan
				if len(f.seqScans) > 0 {
					t.Errorf("fuzzy %s %q: sequential scans %v", caller, c.texts[i], f.seqScans)
				}
			}
			say("  fuzzy one-typo %-7s mean over %d queries: key rows read %.0f · Rows Removed by Index Recheck %.0f · removed by filter %.0f · statement %.1f ms · %s", caller, k, rows/k, rech/k, filt/k, exec/k, scan)
		}
	}
}

// sweepCeiling measures a ceiling-sized prefix class at W, for the choice of W (ADR-0011 rule 13: the largest
// value at which a ceiling-sized class still meets the budget). Informational: the enforced run is at the
// configured W.
func (w *world) sweepCeiling(t *testing.T, say func(string, ...any), W int, cfg benchCfg) {
	t.Helper()
	texts, rows := w.calibrate(W*6/10, W)
	if len(texts) == 0 {
		say("\nsweep W=%d: no one- or two-letter prefix holds %d–%d key rows on this seed", W, W*6/10, W)
		return
	}
	texts, rows = texts[:min(len(texts), 4)], rows[:min(len(rows), 4)]
	srv := w.newServer(W)
	say("\nsweep W=%d, ceiling-sized prefix texts %v holding %v key rows (ms):", W, texts, rows)
	for _, caller := range []string{"admin", "scoped"} {
		var ds []time.Duration
		for i := 0; i < 150; i++ {
			code, _, d := srv.post(caller, texts[i%len(texts)], 0)
			if code != 200 {
				t.Fatalf("sweep %s: status %d", caller, code)
			}
			ds = append(ds, d)
		}
		st := summarize(ds)
		say("  %-7s n %4d  p50 %7s  p95 %7s  p99 %7s  max %7s  %s", caller, st.n, ms(st.p50), ms(st.p95), ms(st.p99), ms(st.max), map[bool]string{true: "within budget", false: "OVER BUDGET"}[st.p95 < budget])
	}
}

func kindOf(s string) inventory.Kind { return inventory.Kind(s) }

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func execOut(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
