package inventory_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// probeName is a pseudo-random two-word name of 5-9 letters a word from a 16-letter alphabet in English
// frequency order, deterministic in g: posting lists are as skewed as a real directory's, not as flat as a
// syllable table's.
const probeName = `(translate(substr(md5(g::text), 1, 5 + g % 5), '0123456789abcdef', 'etaoinsrhldcumfp') || ' ' || translate(substr(md5((g * 31)::text), 1, 5 + (g / 5) % 5), '0123456789abcdef', 'etaoinsrhldcumfp'))`

// probeStatement runs the compiled handler statement of text at ceiling w under EXPLAIN (ANALYZE, BUFFERS),
// as the runtime role (the tenant transaction carries the 30 s statement timeout), and returns the Execution Time and the plan.
func (e *env) probeStatement(t *testing.T, text string, w int) (float64, *planNode) {
	t.Helper()
	p, err := searchkey.Classify(text)
	if err != nil {
		t.Fatal(err)
	}
	cq, err := reportsql.CompileSearch(e.seSource(t), reportsql.SearchQuery{Exact: p.Exact, Prefix: p.Prefix, Fuzzy: p.Fuzzy, GroupLimit: 50, Ceiling: w, Threshold: 0.3},
		reportsql.SearchScopes{"directory.read": e.scopeNC(e.adA)})
	if err != nil {
		t.Fatal(err)
	}
	sql, args := cq.Statement()
	var ms float64
	var plan *planNode
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		restore, err := store.SetTrigramThreshold(ctx, tx, 0.3)
		if err != nil {
			return err
		}
		defer restore()
		var doc []byte
		if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+sql, args...).Scan(&doc); err != nil {
			return err
		}
		var top []struct {
			Plan    planNode `json:"Plan"`
			Elapsed float64  `json:"Execution Time"`
		}
		if err := json.Unmarshal(doc, &top); err != nil || len(top) != 1 {
			return fmt.Errorf("plan: %v", err)
		}
		ms, plan = top[0].Elapsed, &top[0].Plan
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ms, plan
}

// Test_search_probe_50k is the T-1335 AC6 probe (opt-in: ACTIVEDIQ_SEARCH_PROBE=1; it seeds 50,000 objects, a
// few minutes per PostgreSQL version). The T-1102 probe file was never committed, so this is its re-creation
// over the same shape: 50,000 user objects with a name and a sam key each, one tenant, FORCE RLS, the runtime
// role, the handler's statement. ACTIVEDIQ_SEARCH_PROBE_OUT names the directory that receives the transcript.
func Test_search_probe_50k(t *testing.T) {
	if os.Getenv("ACTIVEDIQ_SEARCH_PROBE") != "1" {
		t.Skip("opt-in: ACTIVEDIQ_SEARCH_PROBE=1")
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		var out strings.Builder
		say := func(f string, a ...any) {
			line := fmt.Sprintf(f, a...)
			t.Log(line)
			out.WriteString(line + "\n")
		}
		defer func() {
			if dir := os.Getenv("ACTIVEDIQ_SEARCH_PROBE_OUT"); dir != "" {
				_ = os.MkdirAll(dir, 0o755)
				_ = os.WriteFile(filepath.Join(dir, "probe-pg"+s.Version+".txt"), []byte(out.String()), 0o644)
			}
		}()
		e := setup(t, s)
		e.hStructure(t, e.adA)
		if _, err := e.populate(t, e.adA, hBase, sSrchUser(1, "praman", "Priya Raman")); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		for from := 1; from <= 50000; from += 10000 {
			e.fillObjects(t, e.a, fmt.Sprintf(`SELECT g, %s AS name FROM generate_series(%d, %d) g`, probeName, from, from+9999))
		}
		e.vacuumSearch(t)
		say("T-1335 AC6 probe · PostgreSQL %s · %d objects seeded and vacuumed in %s · runtime role, FORCE RLS, one tenant", s.Version, 50001, time.Since(start).Round(time.Second))

		nth := func(g int) string {
			return e.ownerRun(t, e.a, `SELECT key FROM public.inventory_search_keys WHERE key_kind = 1 ORDER BY key LIMIT 1 OFFSET $1`, g)[0]
		}
		name := nth(25000)
		r := []rune(name)
		typo := string(append(append([]rune{}, r[:3]...), r[4:]...)) // one letter deleted
		say("keys %s · postings %s · tenant postings %s · keys table total %s · postings table total %s",
			e.ownerRun(t, e.a, `SELECT count(*)::text FROM public.inventory_search_keys`)[0],
			e.ownerRun(t, e.a, `SELECT count(*)::text FROM public.inventory_search_trigrams`)[0],
			e.ownerRun(t, e.a, `SELECT count(DISTINCT trgm)::text||' distinct trigrams'`+` FROM public.inventory_search_trigrams`)[0],
			e.ownerRun(t, e.a, `SELECT pg_size_pretty(pg_total_relation_size('public.inventory_search_keys'))`)[0],
			e.ownerRun(t, e.a, `SELECT pg_size_pretty(pg_total_relation_size('public.inventory_search_trigrams'))||' (heap '||pg_size_pretty(pg_relation_size('public.inventory_search_trigrams'))||', pkey '||pg_size_pretty(pg_relation_size('public.inventory_search_trigrams_pkey'))||')'`)[0])
		say("top trigrams: %v", e.ownerRun(t, e.a, `SELECT trgm||'='||c FROM (SELECT trgm, count(*) c FROM public.inventory_search_trigrams GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 8) x`))

		// Worst case: 32 runes made of the tenant's most frequent whole trigrams (4 words of 3 + 4 spaces ... up to 32).
		top := e.ownerRun(t, e.a, `SELECT trgm FROM public.inventory_search_trigrams WHERE trgm !~ ' ' GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT 8`)
		worst := strings.Join(top, " ")
		if len([]rune(worst)) > 32 {
			worst = string([]rune(worst)[:32])
		}
		for _, c := range []struct{ class, q string }{{"exact", name}, {"prefix", string(r[:7])}, {"fuzzy1", typo}, {"nomatch", "zx0946z"}, {"worst32", worst}} {
			if p, err := searchkey.Classify(c.q); err != nil || len(p.Fuzzy) == 0 {
				t.Fatalf("%s %q is not a fuzzy query: %v", c.class, c.q, err)
			}
			for _, w := range []int{inventory.DefaultSearchCeiling, 100} {
				for i := 0; i < 2; i++ {
					e.probeStatement(t, c.q, w) // warm-up
				}
				var times []float64
				var plan *planNode
				for i := 0; i < 9; i++ {
					var ms float64
					ms, plan = e.probeStatement(t, c.q, w)
					times = append(times, ms)
				}
				sort.Float64s(times)
				m := measure(plan)
				verdict := ""
				if w == inventory.DefaultSearchCeiling && c.class != "worst32" && times[len(times)-1] > 130 {
					verdict = "  OVER 130 ms"
				}
				say("%-8s W=%-5d %-34q median %7.1f ms  max %7.1f ms · posting rows read %v · keys rows %v · objects rows %v%s",
					c.class, w, c.q, times[len(times)/2], times[len(times)-1], m.rows["inventory_search_trigrams"], m.rows["inventory_search_keys"], m.rows["directory_objects"], verdict)
				if c.class == "worst32" || verdict != "" {
					say("  plan shape:%s", describe(plan))
				}
			}
		}
	})
}
