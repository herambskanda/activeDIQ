package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func (e *env) catalog(t *testing.T) reportsql.Schema {
	t.Helper()
	var sc reportsql.Schema
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) { sc, err = reportsql.CatalogSchema(ctx, tx); return }); err != nil {
		t.Fatal(err)
	}
	return sc
}

// migration 0069's partial trigram index carries the literal kind list; the statement's fuzzy branch
// draws the same list from the same table, so the planner can prove the index (ADR-0011 rule 5).
func Test_search_fuzzy_kind_list_matches_the_migration_index(t *testing.T) {
	if got := reportsql.FuzzyKindPredicate(); got != "1, 2, 3, 4, 5" {
		t.Fatalf("FuzzyKindPredicate = %q, migration 0069 says 1, 2, 3, 4, 5", got)
	}
	var fuzzy []int
	for _, k := range searchkey.AllKinds {
		if k.FuzzyEligible() {
			fuzzy = append(fuzzy, int(k))
		}
	}
	if len(fuzzy) != 5 {
		t.Fatalf("fuzzy-eligible kinds %v", fuzzy)
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		def := e.strings(t, `SELECT pg_get_indexdef(indexrelid) FROM pg_index WHERE indexrelid = 'public.inventory_search_keys_fuzzy'::regclass`)
		t.Logf("fuzzy index: %v", def)
		if len(def) != 1 || !strings.Contains(def[0], "gin_trgm_ops") || !strings.Contains(def[0], "key_kind") {
			t.Errorf("fuzzy index definition: %v", def)
		}
	})
}

// The ADR left pg_trgm's treatment of non-ASCII letters under the bundled image's C.UTF-8 ctype
// [UNVERIFIED]. Each script gets a misspelling of a seeded name; the result is recorded in the test log
// and asserted, so a change of image shows here.
func Test_search_fuzzy_per_script(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		sr := e.searcher(t)
		names := []struct{ script, name, typo string }{
			{"latin", "Priya Raman", "Pryia Ramn"},
			{"latin_diacritics", "Zoë Müller-Ångström", "Zoe Muler Angstrom"},
			{"cyrillic", "Александр Петров", "Алексндр Петров"},
			{"greek", "Αλέξανδρος Παπαδόπουλος", "Αλεξανδρος Παπαδοπολος"},
			{"cjk", "田中太郎", "田中太朗"},
		}
		var obs []inventory.Observation
		for i, n := range names {
			obs = append(obs, sSrchUser(100+i, fmt.Sprintf("script%d", i), n.name))
		}
		if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		for i, n := range names {
			res, err := e.search(t, sr, e.scopeNC(e.adA), inventory.SearchRequest{Text: n.typo})
			if err != nil {
				t.Fatalf("%s: %v", n.script, err)
			}
			found := len(res.Hits) > 0 && res.Hits[0].Object == hGUID(1, 100+i)
			var sim float32
			var cls reportsql.SearchClass
			if len(res.Hits) > 0 {
				sim, cls = res.Hits[0].Similarity, res.Hits[0].Class
			}
			t.Logf("script %-16s %q -> found=%v class=%v sim=%.3f hits=%d", n.script, n.typo, found, cls, sim, len(res.Hits))
			switch n.script {
			case "latin", "latin_diacritics":
				if !found {
					t.Errorf("%s: %q must find %q", n.script, n.typo, n.name)
				}
			}
			// whatever the trigram classification, the exact spelling is always found by the B-tree
			ex, _ := e.search(t, sr, e.scopeNC(e.adA), inventory.SearchRequest{Text: n.name})
			if len(ex.Hits) == 0 || ex.Hits[0].Object != hGUID(1, 100+i) || ex.Hits[0].Class == reportsql.ClassFuzzy {
				t.Errorf("%s: the exact name is found by exact/prefix, not by trigrams: %+v", n.script, ex.Hits)
			}
		}
	})
}

// explain runs EXPLAIN over the compiled search statement in tx and returns the plan text.
func explain(ctx context.Context, tx store.Tx, sql string, args []any) (string, error) {
	rs, err := tx.Query(ctx, "EXPLAIN (COSTS OFF) "+sql, args...)
	if err != nil {
		return "", err
	}
	defer rs.Close()
	var plan []string
	for rs.Next() {
		var l string
		if err := rs.Scan(&l); err != nil {
			return "", err
		}
		plan = append(plan, l)
	}
	return strings.Join(plan, "\n"), rs.Err()
}

// The exact and prefix probes read the B-tree. The fuzzy probe's partial GIN index is provable from the
// statement's kind list (shown with row security off, as the owner), but under row security the planner
// cannot use it: pg_trgm's operators are not leakproof, and a non-leakproof clause is not promoted into
// an index condition on a table with policy quals. The second half pins that known limit (follow-up
// ticket); when a fix lands, it flips to requiring the index.
func Test_search_plan_uses_the_indexes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		var obs []inventory.Observation
		for i := 1; i <= 30; i++ {
			obs = append(obs, sSrchUser(i, fmt.Sprintf("p%02d", i), fmt.Sprintf("Plan Person %d", i)))
		}
		if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		syl := `(array['ka','ri','mo','sha','pri','ya','ram','an','ji','lo','ve','na','du','te','ba','ho','la','sen','ko','mi','ar','el','os','un','ti','ger','man','dov','ska','wen','fi','zu','qui','bra','lin','cha','dre','sol','pet','nik'])[1 + floor(random() * 40)::int]`
		if err := e.exec(e.a, `INSERT INTO public.inventory_search_keys (tenant_id, connection_id, object_guid, key_kind, key, norm_version)
			SELECT o.tenant_id, o.connection_id, o.object_guid, 1 + (g % 2),
			(SELECT string_agg(`+syl+`, '') FROM generate_series(1, 2 + (g % 3))) || ' ' || (SELECT string_agg(`+syl+`, '') FROM generate_series(1, 2 + (g % 2))) || g::text, 1
			FROM (SELECT * FROM public.directory_objects WHERE kind = 'user') o CROSS JOIN generate_series(1, 3000) g`); err != nil {
			t.Fatal(err)
		}
		if err := e.d.ExecOwner(context.Background(), `ANALYZE public.inventory_search_keys`); err != nil {
			t.Fatal(err)
		}
		src, err := reportsql.NewSearchSource(e.catalog(t), "inventory_search_keys", "inventory_search_trigrams", report.Anchor{ID: "t", Table: "directory_objects", Mode: report.RowAnchor,
			Project: []report.Ident{"object_guid"}, Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid",
			Ancestry: "ancestry", Complete: "ancestry_complete"}, "kind", "state", "enabled", "display_name")
		if err != nil {
			t.Fatal(err)
		}
		p, err := searchkey.Classify("plan person")
		if err != nil {
			t.Fatal(err)
		}
		cq, err := reportsql.CompileSearch(src, reportsql.SearchQuery{Exact: p.Exact, Prefix: p.Prefix, Fuzzy: p.Fuzzy, GroupLimit: 5, Ceiling: 10000, Threshold: 0.3},
			reportsql.SearchScopes{"directory.read": e.scopeNC(e.adA)})
		if err != nil {
			t.Fatal(err)
		}
		sql, args := cq.Statement()
		var plan string
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) { plan, err = explain(ctx, tx, sql, args); return }); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(plan, "Index Scan using inventory_search_keys_by_key") {
			t.Errorf("the prefix probe reads the B-tree:\n%s", plan)
		}
		if strings.Contains(plan, "inventory_search_keys_fuzzy") {
			t.Errorf("under row security the planner now uses the trigram index: make this test require it (follow-up closed?):\n%s", plan)
		}
		// Row security off and every other index dropped, as the owner, inside a transaction that is rolled
		// back: the statement proves the partial index's kind list and reads the GIN. (Which index the
		// planner prefers on its own depends on the LIMIT and its flat estimate; eligibility is the point.)
		ctx := context.Background()
		c, err := e.d.Owner(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		for _, ddl := range []string{`BEGIN`, `DROP INDEX public.inventory_search_keys_by_version, public.inventory_search_keys_by_key`,
			`ALTER TABLE public.inventory_search_keys DROP CONSTRAINT inventory_search_keys_pkey`,
			`ALTER TABLE public.inventory_search_keys DISABLE ROW LEVEL SECURITY`} {
			if _, err := c.Exec(ctx, ddl); err != nil {
				t.Fatalf("%s: %v", ddl, err)
			}
		}
		// The tenant setting stays unset: EXPLAIN plans the statement and runs nothing.
		rs, err := c.Query(ctx, "EXPLAIN (COSTS OFF) "+sql, args...)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for rs.Next() {
			var l string
			if err := rs.Scan(&l); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, l)
		}
		rs.Close()
		if _, err := c.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		if all := strings.Join(lines, "\n"); !strings.Contains(all, "inventory_search_keys_fuzzy") {
			t.Errorf("without row security the fuzzy probe uses the partial GIN index:\n%s", all)
		}
	})
}
