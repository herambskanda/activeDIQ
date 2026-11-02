package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
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

// Migration 0070's trigger function builds postings for the kinds in its literal list; the statement's fuzzy
// branch draws its kind list from searchkey.Kind.FuzzyEligible. The kind enum, the template and the trigger
// must agree on {name, sam} (ADR-0011 rule 9).
func Test_search_fuzzy_kind_list_matches_the_trigger(t *testing.T) {
	if got := reportsql.FuzzyKindPredicate(); got != "1, 3" {
		t.Fatalf("FuzzyKindPredicate = %q, migration 0070 says 1, 3", got)
	}
	var fuzzy []searchkey.Kind
	for _, k := range searchkey.AllKinds {
		if k.FuzzyEligible() {
			fuzzy = append(fuzzy, k)
		}
	}
	if len(fuzzy) != 2 || fuzzy[0] != searchkey.KindName || fuzzy[1] != searchkey.KindSAM {
		t.Fatalf("fuzzy-eligible kinds %v, want name and sam", fuzzy)
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		def := e.strings(t, `SELECT prosrc FROM pg_proc WHERE oid = 'public.inventory_search_trigrams_sync()'::regprocedure`)
		if len(def) != 1 {
			t.Fatalf("trigger function: %v", def)
		}
		if n := strings.Count(def[0], "key_kind IN ("); n != strings.Count(def[0], "key_kind IN ("+reportsql.FuzzyKindPredicate()+")") || n == 0 {
			t.Errorf("the trigger function's kind lists are not all (%s):\n%s", reportsql.FuzzyKindPredicate(), def[0])
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

// The exact and prefix probes read the B-tree of the key table; the fuzzy probe reads the tenant-led posting
// B-tree and rechecks each candidate through a correlated lookup (ADR-0011 rule 5a, T-1335). Under FORCE row
// security, as the runtime role, with no Seq Scan on the key, posting or object table.
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
		e.fillKeys(t, e.a, 21000)
		e.vacuumSearch(t)
		p, err := searchkey.Classify("plan person")
		if err != nil {
			t.Fatal(err)
		}
		cq, err := reportsql.CompileSearch(e.seSource(t), reportsql.SearchQuery{Exact: p.Exact, Prefix: p.Prefix, Fuzzy: p.Fuzzy, GroupLimit: 5, Ceiling: 10000, Threshold: 0.3},
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
		fp := e.analyze(t, e.scopeNC(e.adA), "plan persn", 10000, true)
		assertFuzzyPlan(t, fp)
	})
}
