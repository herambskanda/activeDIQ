package inventory_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// SE5 (ADR-0011 rule 13): the work of a search is bounded by the ceiling, not by how much the scope hides.
// A scoped technician has five visible matches; an excluded OU holds H more matching key rows, for H in
// {0, W-10, W+10, 20,000}. W is injected small (100) to keep the test cheap; the bound is the same in W.
//
// H counts matching key rows. The hidden rows are attached to 20 hidden objects written through the
// writer; the rows past those objects' own keys are bulk-inserted kind-1 keys, because it is the key
// table the statement reads, and 20,000 writer calls prove nothing more than 20,000 rows do.

// planNode is the part of one EXPLAIN (ANALYZE, FORMAT JSON) node SE5 reads.
type planNode struct {
	Type     string     `json:"Node Type"`
	Relation string     `json:"Relation Name"`
	Index    string     `json:"Index Name"`
	Rows     float64    `json:"Actual Rows"`
	Loops    float64    `json:"Actual Loops"`
	Removed  float64    `json:"Rows Removed by Filter"`
	Recheck  float64    `json:"Rows Removed by Index Recheck"`
	Subplan  string     `json:"Subplan Name"`
	Children []planNode `json:"Plans"`

	IndexCond  string  `json:"Index Cond"`
	JoinType   string  `json:"Join Type"`
	Heap       float64 `json:"Heap Fetches"`
	SharedHit  float64 `json:"Shared Hit Blocks"`
	SharedRead float64 `json:"Shared Read Blocks"`
}

// walk calls fn on every node with the name of the CTE it belongs to.
func (n *planNode) walk(cte string, fn func(n *planNode, cte string)) {
	if strings.HasPrefix(n.Subplan, "CTE ") {
		cte = strings.TrimPrefix(n.Subplan, "CTE ")
	}
	fn(n, cte)
	for i := range n.Children {
		n.Children[i].walk(cte, fn)
	}
}

// explainAnalyze runs the compiled statement under EXPLAIN (ANALYZE, FORMAT JSON) in tx.
func explainAnalyze(ctx context.Context, tx store.Tx, sql string, args []any) (*planNode, error) {
	var doc []byte
	if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+sql, args...).Scan(&doc); err != nil {
		return nil, err
	}
	var top []struct {
		Plan planNode `json:"Plan"`
	}
	if err := json.Unmarshal(doc, &top); err != nil || len(top) != 1 {
		return nil, fmt.Errorf("plan: %v (%d entries)", err, len(top))
	}
	return &top[0].Plan, nil
}

func (e *env) seSource(t *testing.T) reportsql.SearchSource {
	t.Helper()
	src, err := reportsql.NewSearchSource(e.catalog(t), "inventory_search_keys", "inventory_search_trigrams", report.Anchor{ID: "t", Table: "directory_objects", Mode: report.RowAnchor,
		Project: []report.Ident{"object_guid"}, Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid",
		Ancestry: "ancestry", Complete: "ancestry_complete"}, "kind", "state", "enabled", "display_name")
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// analyze plans and runs the statement of text for the scope with the given classes, as the app role.
// withFuzzy false drops the fuzzy class, so the plan holds only the B-tree classes.
func (e *env) analyze(t *testing.T, scope authz.ReadScope, text string, w int, withFuzzy bool) *planNode {
	t.Helper()
	p, err := searchkey.Classify(text)
	if err != nil {
		t.Fatal(err)
	}
	q := reportsql.SearchQuery{Exact: p.Exact, Prefix: p.Prefix, GroupLimit: 5, Ceiling: w, Threshold: 0.3}
	if withFuzzy {
		q.Fuzzy = p.Fuzzy
	}
	cq, err := reportsql.CompileSearch(e.seSource(t), q, reportsql.SearchScopes{"directory.read": scope})
	if err != nil {
		t.Fatal(err)
	}
	sql, args := cq.Statement()
	var plan *planNode
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		if withFuzzy {
			restore, err := store.SetTrigramThreshold(ctx, tx, 0.3)
			if err != nil {
				return err
			}
			defer restore()
		}
		var err error
		plan, err = explainAnalyze(ctx, tx, sql, args)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return plan
}

func Test_search_work_is_bounded(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		const w = 100
		e := setup(t, s)
		e.hStructure(t, e.adA)
		sr := e.searcherW(t, inventory.WithCeiling(w))
		var obs []inventory.Observation
		for i := 1; i <= 5; i++ {
			obs = append(obs, sInv(1, i, fmt.Sprintf("s%d", i), fmt.Sprintf("Sezo Person %d", i), false))
		}
		for i := 1; i <= 20; i++ {
			obs = append(obs, sInv(2, i, fmt.Sprintf("h%d", i), fmt.Sprintf("Other Hidden %d", i), true))
		}
		if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		// A directory_objects table of realistic size, so that the join is planned as a join: filler users
		// that match nothing.
		if err := e.exec(e.a, `INSERT INTO public.directory_objects (tenant_id, connection_id, object_guid, nc_guid, kind, object_class, parent_guid, ancestry, ancestry_complete, display_name, observed_at, state)
			SELECT o.tenant_id, o.connection_id, gen_random_uuid(), o.nc_guid, 'user', 'user', o.parent_guid, o.ancestry, true, 'Filler ' || g, o.observed_at, 'live'
			FROM (SELECT * FROM public.directory_objects WHERE kind = 'user' LIMIT 1) o CROSS JOIN generate_series(1, 20000) g`); err != nil {
			t.Fatal(err)
		}
		// ... and keys for them, so the key table is not so small that a scan is the natural plan.
		if err := e.exec(e.a, `INSERT INTO public.inventory_search_keys (tenant_id, connection_id, object_guid, key_kind, key, norm_version)
			SELECT tenant_id, connection_id, object_guid, 1, lower(display_name), 1 FROM public.directory_objects WHERE starts_with(display_name, 'Filler ')
			UNION ALL SELECT tenant_id, connection_id, object_guid, 3, 'f' || substr(display_name, 8), 1 FROM public.directory_objects WHERE starts_with(display_name, 'Filler ')`); err != nil {
			t.Fatal(err)
		}
		visRows := func() int {
			return e.count(t, `SELECT count(*) FROM public.inventory_search_keys WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND key >= 'sezo' AND key < 'sezp'`)
		}
		if n := visRows(); n != 10 {
			t.Fatalf("the five visible matches hold 10 prefix key rows (a name and a word each), got %d: the H values below assume it", n)
		}
		addHidden := func(total int) { // top the hidden matching rows up to total
			have := e.count(t, `SELECT count(*) FROM public.inventory_search_keys WHERE starts_with(key, 'sezo hidden ')`)
			if total <= have {
				return
			}
			if err := e.exec(e.a, `INSERT INTO public.inventory_search_keys (tenant_id, connection_id, object_guid, key_kind, key, norm_version)
				SELECT o.tenant_id, o.connection_id, o.object_guid, 1, 'sezo hidden ' || g::text, 1
				FROM (SELECT *, row_number() OVER (ORDER BY object_guid) AS rn FROM public.directory_objects WHERE starts_with(display_name, 'Other Hidden ')) o
				JOIN generate_series($1::int, $2::int) g ON o.rn = 1 + mod(g, 20)`, have+1, total); err != nil {
				t.Fatal(err)
			}
		}
		analyzeAll := func() {
			for _, tbl := range []string{"inventory_search_keys", "inventory_search_trigrams", "directory_objects"} {
				if err := e.d.ExecOwner(context.Background(), `ANALYZE public.`+tbl); err != nil {
					t.Fatal(err)
				}
			}
		}
		scoped, unscoped := e.scopeOU(e.adA), e.scopeNC(e.adA)
		var baseline map[string]inventory.SearchResult
		texts := []string{"sezo", "s3"} // every hidden row matches "sezo" in the prefix and fuzzy classes alike, 10+H <= W below the ceiling
		answers := func(sc authz.ReadScope) map[string]inventory.SearchResult {
			out := map[string]inventory.SearchResult{}
			for _, text := range texts {
				r, err := e.search(t, sr, sc, inventory.SearchRequest{Text: text, GroupLimit: 50})
				if err != nil {
					t.Fatal(err)
				}
				out[text] = r
			}
			return out
		}
		for _, h := range []int{0, w - 10, w + 10, 20000} {
			t.Run(fmt.Sprintf("H=%d", h), func(t *testing.T) {
				addHidden(h)
				analyzeAll()
				got := answers(scoped)
				switch {
				case h == 0:
					baseline = got
					if got["sezo"].Refine || len(got["sezo"].Hits) != 5 {
						t.Fatalf("baseline: %+v", got["sezo"])
					}
				case h <= w-10:
					// 10 visible + W-10 hidden rows = W: not over the ceiling. Nothing the technician
					// receives depends on the hidden rows.
					if !reflect.DeepEqual(got, baseline) {
						t.Errorf("H=W-10: the response differs from H=0\n%+v\n%+v", got, baseline)
					}
				default:
					// Over the ceiling the prefix class is withheld for everyone. An admin gets the same state.
					all := answers(unscoped)
					r, a := got["sezo"], all["sezo"]
					if !r.Refine || len(r.Hits) != 0 || r.Count != nil || r.More != nil {
						t.Errorf("scoped: want the refine state: %+v", r)
					}
					if r.Refine != a.Refine || !reflect.DeepEqual(r.Hits, a.Hits) || !reflect.DeepEqual(r.Count, a.Count) || !reflect.DeepEqual(r.More, a.More) {
						t.Errorf("an unscoped admin's refine state equals the technician's:\n%+v\n%+v", r, a)
					}
					// The exact class ranks above it and is still answered, from the same bounded read.
					if ex := got["s3"]; len(ex.Hits) == 0 || ex.Hits[0].Object != hGUID(1, 3) || ex.Hits[0].Class != reportsql.ClassExact {
						t.Errorf("exact survives the prefix ceiling: %+v", ex.Hits)
					}
				}
				// Plan: the B-tree classes of the statement, run for real.
				for _, text := range []string{"sezo", "s3"} {
					plan := e.analyze(t, scoped, text, w, false)
					var rows = map[string]float64{}
					plan.walk("", func(n *planNode, cte string) {
						switch n.Relation {
						case "inventory_search_keys":
							if strings.Contains(n.Type, "Seq Scan") {
								t.Errorf("%s: %s on inventory_search_keys (%s)", text, n.Type, cte)
							}
							if cte == "m_prefix" && (!strings.HasPrefix(n.Type, "Index") || n.Index != "inventory_search_keys_by_key") {
								// A bitmap scan builds the whole range before the first row: not bounded by the limit.
								t.Errorf("%s: m_prefix is a %s via %q, want an ordered Index Scan of inventory_search_keys_by_key", text, n.Type, n.Index)
							}
							if n.Removed != 0 {
								t.Errorf("%s: %s removed %v rows by filter: the bound is the index range, not a filter", text, cte, n.Removed)
							}
							rows[cte] += n.Rows * n.Loops
						case "directory_objects":
							if strings.Contains(n.Type, "Seq Scan") {
								t.Errorf("%s: %s on directory_objects", text, n.Type)
							}
							if n.Loops > 3*(w+1) {
								t.Errorf("%s: %d loops on directory_objects, want at most 3(W+1) = %d", text, int(n.Loops), 3*(w+1))
							}
						}
					})
					for _, cte := range []string{"m_exact", "m_prefix"} {
						if rows[cte] > w+1 {
							t.Errorf("%s: %s examined %v key rows, want at most W+1 = %d (H=%d)", text, cte, rows[cte], w+1, h)
						}
					}
					if text == "sezo" && h >= w+10 && rows["m_prefix"] != w+1 {
						t.Errorf("a ceiling-sized read stops at W+1 key rows, got %v", rows["m_prefix"])
					}
				}
			})
		}
		// SE5, fuzzy class (ADR-0011 rule 5a): the posting index and the per-candidate recheck, run for real
		// over the table the H loop left behind (20,000 hidden name keys sharing the query's trigrams). The plan
		// depends on the postings' statistics and visibility map, so they are vacuumed first, as the runner does
		// after a bulk load: left to autovacuum, the plan would depend on timing.
		e.vacuumSearch(t)
		t.Run("fuzzy_plan", func(t *testing.T) {
			for _, text := range []string{"sezo", "sezo hidden 7"} {
				assertFuzzyPlan(t, e.analyze(t, scoped, text, w, true))
			}
		})
		// The longest fuzzy query (32 runes, the most trigrams) must finish and keep the plan shape. Its words are
		// rare in this world, as a real query's trigrams are: a query whose every trigram sits in all 20,000
		// hidden keys would rightly be a Seq Scan of the postings (reading them all is cheaper), and says nothing
		// about the shape. The frequent-trigram worst case is measured at 50,000 objects by the AC6 probe.
		t.Run("fuzzy_longest", func(t *testing.T) {
			const longest = "quixotic zephyr jumbled waxy fox"
			if n := utf8.RuneCountInString(longest); n != searchkey.MaxFuzzyRunes {
				t.Fatalf("the longest query is %d runes, want %d", n, searchkey.MaxFuzzyRunes)
			}
			start := time.Now()
			plan := e.analyze(t, scoped, longest, w, true)
			assertFuzzyPlan(t, plan)
			var read float64
			plan.walk("", func(n *planNode, cte string) {
				if n.Index == "inventory_search_trigrams_pkey" {
					read += n.Rows * n.Loops
				}
			})
			t.Logf("longest fuzzy query: %v wall, %v posting rows read", time.Since(start).Round(time.Millisecond), read)
		})
	})
}
