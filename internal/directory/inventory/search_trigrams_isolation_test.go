package inventory_test

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
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

// work is what one statement examined, per relation (ADR-0011 rule 16 as restated in T-1335 AC5).
type work struct {
	rows   map[string]float64 // Actual Rows x Loops + Rows Removed by Filter x Loops + Rows Removed by Index Recheck x Loops + Heap Fetches
	blocks map[string]float64 // shared hit + read blocks of the scan nodes
	loops  map[string]float64 // loops of the scan nodes, which scale the block tolerance
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

func measure(plan *planNode) work {
	w := work{map[string]float64{}, map[string]float64{}, map[string]float64{}}
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
		// Blocks are summed over every scan node of the relation, so that the bitmap form (index + heap blocks)
		// and an Index Only Scan can be compared; the tolerance is 2 per loop of each of those nodes.
		w.blocks[rel] += n.SharedHit + n.SharedRead
		w.loops[rel] += n.Loops
	})
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
		e.fillRange(t, e.a, 1, n)
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
				plan := e.analyze(t, e.scopeNC(e.adA), q, w, true)
				assertFuzzyPlan(t, plan)
				shapes = append(shapes, q+describe(plan))
				m := measure(plan)
				if m.rows["inventory_search_trigrams"] == 0 || m.rows["inventory_search_keys"] == 0 {
					t.Fatalf("%q: the plan examined no postings or keys: %+v", q, m)
				}
				out = append(out, m)
			}
			return out
		}
		base := measureAll() // B is empty
		baseShapes := shapes
		loads := []struct {
			name     string
			from, to int
		}{{"equal to A", 1, n}, {"ten times A", n + 1, 10 * n}}
		for _, l := range loads {
			e.fillRange(t, e.b, l.from, l.to)
			e.vacuumSearch(t)
			// ... B's postings are real: its own count matches its keys
			if missing, extra, want := e.trgDiff(t, e.b); missing != 0 || extra != 0 || want == 0 {
				t.Fatalf("B %s: %d missing, %d extra of %d postings", l.name, missing, extra, want)
			}
			got := measureAll()
			for i, q := range queries {
				for rel, rows := range base[i].rows {
					if got[i].rows[rel] != rows {
						t.Errorf("%q with B %s: %s examined %v rows, %v with B empty: another tenant's data is read", q, l.name, rel, got[i].rows[rel], rows)
					}
				}
				for rel, blocks := range base[i].blocks {
					tol := 2 * math.Max(base[i].loops[rel], got[i].loops[rel])
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
