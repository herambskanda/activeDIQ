package inventory_test

import (
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// seedTenantB gives tenant B a naming context and one user, the row that fillObjects copies.
func (e *env) seedTenantB(t *testing.T) {
	t.Helper()
	if err := e.tx(t, e.b, func(ctx context.Context, tx store.Tx) error {
		_, err := pop.Populate(ctx, tx, e.adB, hBase, []inventory.Observation{
			{Object: inventory.GUID(hGUID(9, 1)), NC: inventory.GUID(hGUID(9, 1)), Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive},
			func() inventory.Observation {
				o := sSrchUser(5, "bsmith", "Bea Smith")
				o.Parent, o.Ancestry, o.NC = inventory.GUID(hGUID(9, 1)), []inventory.GUID{inventory.GUID(hGUID(9, 1))}, inventory.GUID(hGUID(9, 1))
				return o
			}()})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// fillProbe loads the names of probeName for g in [from, to]: two random-looking words per name, so that the
// proof queries of a 50,000-object world still match a handful of keys (the syllable names of fillRange repeat
// every few hundred objects, which is right for the small worlds and wrong for this one).
func (e *env) fillProbe(t *testing.T, tid tenant.ID, from, to int) {
	t.Helper()
	e.fillObjects(t, tid, fmt.Sprintf(`SELECT g, %s AS name FROM generate_series(%d, %d) g`, probeName, from, to))
}

// btreeLevel is the level of a B-tree index root (0 = a single leaf), read with pageinspect as the cluster admin.
func (e *env) btreeLevel(t *testing.T, index string) int {
	t.Helper()
	ctx := context.Background()
	c, err := e.d.Admin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pageinspect`); err != nil {
		t.Fatal(err)
	}
	var level int
	if err := c.QueryRow(ctx, `SELECT level FROM bt_metap($1)`, "public."+index).Scan(&level); err != nil {
		t.Fatal(err)
	}
	return level
}

// work is what one statement examined, per relation (ADR-0011 rule 16 as restated in T-1335 AC5).
type work struct {
	rows   map[string]float64 // Actual Rows x Loops + Rows Removed by Filter x Loops + Rows Removed by Index Recheck x Loops + Heap Fetches
	blocks map[string]float64 // shared hit + read blocks of the scan nodes
	loops  map[string]float64 // loops of the index-scan nodes, which scale the block tolerance
	forms  map[string]string  // the index-scan node types that read each relation, sorted
}

// relationOf names the table a plan node reads: a Bitmap Index Scan has an index and no relation.
func relationOf(n *planNode) string {
	switch {
	case n.Relation != "":
		return n.Relation
	case strings.HasPrefix(n.Index, "inventory_search_trigrams"):
		return "inventory_search_trigrams"
	case strings.HasPrefix(n.Index, "inventory_search_keys"):
		return "inventory_search_keys"
	case strings.HasPrefix(n.Index, "directory_objects"):
		return "directory_objects"
	}
	return ""
}

// describe lists the scan nodes of a plan for a failure message.
func describe(plan *planNode) string {
	var b strings.Builder
	plan.walk("", func(n *planNode, cte string) {
		if strings.HasSuffix(n.Type, "Scan") && relationOf(n) != "" {
			fmt.Fprintf(&b, "\n  %-10s %-18s %-28s %-26s rows %v x %v, removed %v, recheck %v, heap %v, blocks %v+%v", cte, n.Type, relationOf(n), n.Index, n.Rows, n.Loops, n.Removed, n.Recheck, n.Heap, n.SharedHit, n.SharedRead)
		}
	})
	return b.String()
}

// heapFetches is the number of heap fetches of the Index Only Scans of a plan.
func heapFetches(plan *planNode) float64 {
	var n float64
	plan.walk("", func(p *planNode, _ string) { n += p.Heap })
	return n
}

func measure(plan *planNode) work {
	w := work{map[string]float64{}, map[string]float64{}, map[string]float64{}, map[string]string{}}
	types := map[string]map[string]bool{}
	plan.walk("", func(n *planNode, _ string) {
		rel := relationOf(n)
		if rel == "" || n.Loops == 0 {
			return
		}
		if !strings.HasSuffix(n.Type, "Scan") {
			return
		}
		// A Bitmap Index Scan only yields the TIDs that its Bitmap Heap Scan then reads: the rows are counted once,
		// at the heap scan, so that the bitmap and the plain form of the same read weigh the same.
		// JSON gives Actual Rows and the removed counts per loop; Heap Fetches is a total.
		if n.Type != "Bitmap Index Scan" {
			w.rows[rel] += (n.Rows+n.Removed+n.Recheck)*n.Loops + n.Heap
		}
		// Blocks are the shared hit + read of the INDEX-scan nodes only (Index Scan, Index Only Scan, Bitmap Index
		// Scan): the planner flips the posting read between a Bitmap Heap Scan and an Index Only Scan as the
		// other tenants' size changes the table statistics, and the heap half of the bitmap form is rows, which
		// are already compared exactly. The tolerance is 2 per loop of each index-scan node.
		switch n.Type {
		case "Index Scan", "Index Only Scan", "Bitmap Index Scan":
			w.blocks[rel] += n.SharedHit + n.SharedRead
			w.loops[rel] += n.Loops
			if types[rel] == nil {
				types[rel] = map[string]bool{}
			}
			types[rel][n.Type] = true
		}
	})
	for rel, set := range types {
		var names []string
		for ty := range set {
			names = append(names, ty)
		}
		sort.Strings(names)
		w.forms[rel] = strings.Join(names, "+")
	}
	return w
}

// AC5: tenant B's data changes nothing that tenant A's fuzzy query reads. A holds the key set; B is loaded
// empty, equal to A and ten times A, with VACUUM (ANALYZE) after each load. Rows examined per relation are
// exactly equal; shared blocks are equal within 2 per scan-node loop; every plan has AC4's shape.
//
// The queries have at most W matches, so every candidate is rechecked and the order in which candidates reach
// the LIMIT cannot differ between loads. W is 100, as in SE5 (T-1344 records what the planner does to the
// hits join at the default W). The scale is ACTIVEDIQ_SEARCH_LARGE_OBJECTS objects for A (default 2,000);
// the AC names 50,000, which is the large switch.
func Test_search_fuzzy_reads_only_the_tenants_own_postings(t *testing.T) {
	n := 2000
	if v, err := strconv.Atoi(os.Getenv("ACTIVEDIQ_SEARCH_LARGE_OBJECTS")); err == nil && v > 0 {
		n = v
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		const w = 100
		e := setup(t, s)
		e.hStructure(t, e.adA)
		if _, err := e.populate(t, e.adA, hBase, sSrchUser(1, "praman", "Priya Raman")); err != nil {
			t.Fatal(err)
		}
		e.seedTenantB(t)
		e.fillProbe(t, e.a, 1, n)
		// A directory_objects table of realistic size, as in SE5: on a table of 2,000 rows a Seq Scan is the natural
		// plan for the hits join, and AC4 forbids it only where the planner has a reason to choose the index.
		if err := e.exec(e.a, `INSERT INTO public.directory_objects (tenant_id, connection_id, object_guid, nc_guid, kind, object_class, parent_guid, ancestry, ancestry_complete, display_name, observed_at, state)
			SELECT o.tenant_id, o.connection_id, gen_random_uuid(), o.nc_guid, 'user', 'user', o.parent_guid, o.ancestry, true, 'Filler ' || g, o.observed_at, 'live'
			FROM (SELECT * FROM public.directory_objects WHERE kind = 'user' LIMIT 1) o CROSS JOIN generate_series(1, 20000) g`); err != nil {
			t.Fatal(err)
		}
		e.vacuumSearch(t)

		// Proof queries: a name of A with its third letter dropped, kept when it matches between 2 and w/2 keys of A
		// by the index-free oracle, so that no candidate can be cut by the LIMIT.
		var queries []string
		for _, g := range []int{17, n / 7, n / 3, n / 2, 2 * n / 3, n - 5, 31, 53, 101} {
			if len(queries) == 4 || g < 1 || g > n {
				continue
			}
			nm := e.ownerRun(t, e.a, `SELECT key FROM public.inventory_search_keys WHERE key_kind = 1 ORDER BY key LIMIT 1 OFFSET $1`, g)
			if len(nm) != 1 || len([]rune(nm[0])) < 6 {
				continue
			}
			r := []rune(nm[0])
			q := string(append(append([]rune{}, r[:2]...), r[3:]...))
			cnt, _ := strconv.Atoi(e.ownerRun(t, e.a, `SELECT count(*)::text FROM public.inventory_search_keys WHERE key_kind IN (1, 3) AND word_similarity($1, key) >= 0.3`, q)[0])
			if cnt >= 2 && cnt <= w/2 {
				queries = append(queries, q)
			}
		}
		if len(queries) < 3 {
			t.Fatalf("only %d usable proof queries: %v", len(queries), queries)
		}
		t.Logf("A holds %d objects; proof queries %q", n, queries)

		var shapes []string
		measureAll := func() []work {
			var out []work
			shapes = nil
			for _, q := range queries {
				// The first run of a statement in a session reads about 3 blocks more than every later run (the index's
				// metapage and the catalog entries it needs are not cached yet): the run that is measured is the second.
				e.analyze(t, e.scopeNC(e.adA), q, w, true)
				plan := e.analyze(t, e.scopeNC(e.adA), q, w, true)
				// Heap Fetches count as rows examined. They are 0 once VACUUM has marked the postings all-visible, which
				// it cannot do while another session (an autovacuum worker, say) holds the xmin horizon back: vacuum
				// again until the visibility map is current rather than leave the term out.
				for try := 0; heapFetches(plan) > 0 && try < 10; try++ {
					time.Sleep(500 * time.Millisecond)
					e.vacuumSearch(t)
					plan = e.analyze(t, e.scopeNC(e.adA), q, w, true)
				}
				assertFuzzyPlan(t, plan)
				shapes = append(shapes, q+describe(plan))
				m := measure(plan)
				// (Before PostgreSQL 18 the JSON Actual Rows of a looped node is a rounded average per loop, so the key
				// rows of a plan that rechecks few candidates may read 0: the loops are the proof that it ran.)
				if m.rows["inventory_search_trigrams"] == 0 || m.loops["inventory_search_keys"] < 2 {
					t.Fatalf("%q: the plan examined no postings or keys: %+v", q, m)
				}
				out = append(out, m)
			}
			return out
		}
		base := measureAll() // B is empty
		baseLevel := e.btreeLevel(t, "inventory_search_trigrams_pkey")
		baseShapes := shapes
		loads := []struct {
			name     string
			from, to int
		}{{"equal to A", 1, n}, {"ten times A", n + 1, 10 * n}}
		for _, l := range loads {
			e.fillProbe(t, e.b, l.from, l.to)
			e.vacuumSearch(t)
			// ... B's postings are real: its own count matches its keys
			if missing, extra, want := e.trgDiff(t, e.b); missing != 0 || extra != 0 || want == 0 {
				t.Fatalf("B %s: %d missing, %d extra of %d postings", l.name, missing, extra, want)
			}
			got := measureAll()
			// The posting index grows a level as B grows, and every probe of the query's trigrams descends through it:
			// one more block per trigram per added level. That is the size of the tree, not a read of B's entries
			// (the rows, which are exact, prove that), so it is added to the tolerance, separately from the AC's 2 per loop.
			levels := e.btreeLevel(t, "inventory_search_trigrams_pkey") - baseLevel
			t.Logf("B %s: the posting index has %d more level(s) than with B empty", l.name, levels)
			for i, q := range queries {
				for rel, rows := range base[i].rows {
					if got[i].rows[rel] != rows {
						t.Errorf("%q with B %s: %s examined %v rows, %v with B empty: another tenant's data is read", q, l.name, rel, got[i].rows[rel], rows)
					}
				}
				for rel, blocks := range base[i].blocks {
					tol := 2 * math.Max(base[i].loops[rel], got[i].loops[rel])
					// A Bitmap Index Scan reads about 3 blocks more than an Index Only Scan of the same posting list:
					// the planner may flip between the two as B's size changes the statistics.
					if base[i].forms[rel] != got[i].forms[rel] {
						tol += 3
					}
					if rel == "inventory_search_trigrams" && levels > 0 {
						ntrg, _ := strconv.Atoi(e.ownerRun(t, e.a, `SELECT cardinality(public.show_trgm($1))::text`, q)[0])
						tol += float64(levels * ntrg)
					}
					if d := math.Abs(got[i].blocks[rel] - blocks); d > tol {
						t.Errorf("%q with B %s: %s read %v shared blocks, %v with B empty (tolerance %v)", q, l.name, rel, got[i].blocks[rel], blocks, tol)
					}
				}
			}
			if t.Failed() {
				t.Logf("B empty:\n%s\nB %s:\n%s", strings.Join(baseShapes, "\n"), l.name, strings.Join(shapes, "\n"))
			}
			t.Logf("B %s: A's rows examined unchanged; %s", l.name, fmt.Sprint(got[0].rows))
		}
	})
}
