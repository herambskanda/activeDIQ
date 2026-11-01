package inventory_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// SE3 (ADR-0011): the scope a search is trimmed by equals the read oracle, and nothing hidden shows in any
// response below the ceiling. The worlds are RP6's (rp6_scope_test.go): trees written through the inventory
// writer, OU moves, rows that lost their ancestry guarantee, two connections, flawed scope terms and token
// layers. Every user in a world carries the same display name, so one query is a match for all of them in
// a known class and the oracle's admitted set is the expected hit set.
//
// Gated kinds: at 2a every key kind is read under directory.read (searchkey.Kind.Permission), so there is
// no gated kind to build a world for. The "gated_kinds" subtest fails when one is added, so whoever adds
// it extends SE3 with the world the ADR describes.

const se3Seeds = 40 // random worlds per PostgreSQL version

// se3User is the observation of user node i of connection conn in a world: a name shared by every user and
// a fixed-width sam, so a sam prefix of the seed matches exactly the world's users.
func (w *rpWorld) se3Obs(seed, conn int) []inventory.Observation {
	var out []inventory.Observation
	for i, n := range w.nodes {
		if n.conn != conn {
			continue
		}
		o := w.obs(i)
		if o.Kind == inventory.KindUser {
			o.DisplayName = "Zelda Quinn"
			o.SAMAccountName = fmt.Sprintf("zq%02d%d%04x", seed, conn, i)
		}
		out = append(out, o)
	}
	return out
}

func (w *rpWorld) se3Users() (idx []int) {
	for i, n := range w.nodes {
		if !n.ou && n.parent >= 0 {
			idx = append(idx, i)
		}
	}
	return idx
}

func hitSet(res inventory.SearchResult, class reportsql.SearchClass) []string {
	var out []string
	for _, h := range res.Hits {
		if class == 0 || h.Class == class {
			out = append(out, h.Object)
		}
	}
	sort.Strings(out)
	return out
}

func Test_search_scope_matches_read_oracle(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		t.Run("oracle", func(t *testing.T) { se3Oracle(t, s) })
		t.Run("invariance_M4", func(t *testing.T) { se3Invariance(t, s) })
		t.Run("above_ceiling", func(t *testing.T) { se3AboveCeiling(t, s) })
		t.Run("gated_kinds", se3Gated)
		t.Run("empty_scope", func(t *testing.T) { se3Empty(t, s) })
	})
}

func se3Oracle(t *testing.T, s *storetest.Server) {
	e := setup(t, s)
	conns := [2]inventory.ConnectionID{
		e.conn(t, e.a, connection.KindADForest, connection.TransportLDAPS),
		e.conn(t, e.a, connection.KindADForest, connection.TransportLDAPS),
	}
	sr := e.searcher(t)
	clock := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	var compared, moves, flipped, queries int
	for seed := 0; seed < se3Seeds; seed++ {
		r := rand.New(rand.NewPCG(uint64(seed), 0x3c6ef372))
		w := rpBuild(r, seed)
		for c := range conns {
			w.ids[c] = rpID(string(conns[c]))
			clock = clock.Add(time.Minute)
			if _, err := e.populate(t, conns[c], clock, w.se3Obs(seed, c)...); err != nil {
				t.Fatalf("seed %d: populate: %v", seed, err)
			}
		}
		for k := r.IntN(6); k > 0; k-- {
			x, ok := w.rpMove(r)
			if !ok {
				continue
			}
			moves++
			clock = clock.Add(time.Minute)
			if _, err := e.populate(t, conns[w.nodes[x].conn], clock, w.obs(x)); err != nil {
				t.Fatalf("seed %d: move: %v", seed, err)
			}
		}
		w.stored = map[string]row{}
		for c := range conns {
			for g, rw := range e.rows(t, e.a, conns[c]) {
				w.stored[g] = rw
			}
		}
		if r.IntN(100) < 15 {
			for k := 1 + r.IntN(3); k > 0; k-- {
				i := r.IntN(len(w.nodes))
				if _, err := e.execTag(t, `UPDATE public.directory_objects SET ancestry_complete = false WHERE object_guid = $1::uuid`, w.nodes[i].guid); err != nil {
					t.Fatalf("seed %d: marking incomplete: %v", seed, err)
				}
				rw := w.stored[w.nodes[i].guid]
				rw.Complete = false
				w.stored[w.nodes[i].guid] = rw
				flipped++
			}
		}
		users := w.se3Users()
		pick := users[r.IntN(len(users))]
		sam := fmt.Sprintf("zq%02d%d%04x", seed, w.nodes[pick].conn, pick)
		nodeOf := map[string]int{}
		for i, n := range w.nodes {
			nodeOf[n.guid] = i
		}
		type query struct {
			name, text string
			class      reportsql.SearchClass
			// everyone: every user of the world is a match in class; otherwise only user pick, in class exact
			everyone bool
		}
		qs := []query{
			{"whole_name", "Zelda Quinn", reportsql.ClassPrefix, true}, // names are prefix keys; only identifiers are exact
			{"prefix_name", "zelda q", reportsql.ClassPrefix, true},
			{"fuzzy_name", "Zelda Qiunn", reportsql.ClassFuzzy, true},
			{"prefix_sam", fmt.Sprintf("zq%02d", seed), reportsql.ClassPrefix, true},
			{"exact_sam", sam, reportsql.ClassExact, false},
		}
		for k := 0; k < rp6Scope; k++ {
			sc := w.genScope(r)
			scope := w.readScope(sc)
			var admitted []string
			for _, i := range users {
				if w.admits(sc, now, i) {
					admitted = append(admitted, w.nodes[i].guid)
				}
			}
			sort.Strings(admitted)
			for _, q := range qs {
				res, err := e.search(t, sr, scope, inventory.SearchRequest{Text: q.text, GroupLimit: 50})
				if err != nil {
					t.Fatalf("seed %d scope %d %s: %v", seed, k, q.name, err)
				}
				queries++
				if res.Refine {
					t.Fatalf("seed %d %s: refine in a world far below the ceiling", seed, q.name)
				}
				// Nothing outside the oracle's admitted set, in any class.
				for _, h := range res.Hits {
					i, ok := nodeOf[h.Object]
					if !ok || !w.admits(sc, now, i) {
						t.Fatalf("seed %d scope %d %s: hit %s (class %s) is not admitted by the oracle\n scope: %s", seed, k, q.name, h.Object, h.Class, sc)
					}
				}
				var want []string
				if q.everyone {
					want = admitted
				} else if slices.Contains(admitted, w.nodes[pick].guid) {
					want = []string{w.nodes[pick].guid}
				}
				got := hitSet(res, q.class)
				if !slices.Equal(got, want) {
					t.Fatalf("seed %d scope %d %s %q:\n search-only %v\n oracle-only %v\n scope: %s", seed, k, q.name, q.text, diff(got, want), diff(want, got), sc)
				}
				if q.everyone && len(res.Hits) != len(want) {
					t.Fatalf("seed %d %s: %d hits, %d admitted matches", seed, q.name, len(res.Hits), len(want))
				}
				if n := res.Count[reportsql.TypeUser]; q.everyone && n != len(want) {
					t.Fatalf("seed %d scope %d %s: count %d, oracle %d\n scope: %s", seed, k, q.name, n, len(want), sc)
				}
				if res.More[reportsql.TypeUser] {
					t.Fatalf("seed %d %s: more set below the group limit", seed, q.name)
				}
				compared += len(want)
			}
		}
	}
	t.Logf("%d worlds, %d moves, %d rows marked incomplete, %d searches, %d admitted hits compared", se3Seeds, moves, flipped, queries, compared)
	if compared == 0 || moves == 0 {
		t.Fatalf("the generator is degenerate: compared=%d moves=%d", compared, moves)
	}
}

// execTag runs fixture SQL in the tenant's transaction and returns the rows affected, which must be 1.
func (e *env) execTag(t *testing.T, sql string, args ...any) (int64, error) {
	t.Helper()
	var n int64
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		if n != 1 {
			return fmt.Errorf("%d rows updated", n)
		}
		return nil
	})
	return n, err
}

// sInv is a user named name: visible (under the OU) or hidden (under the container, outside it).
func sInv(class byte, i int, sam, name string, hidden bool) inventory.Observation {
	o := hUser{guid: hGUID(class, i), sam: sam, rid: uint32(5000 + 1000*int(class) + i)}.obs()
	o.DisplayName = name
	if hidden {
		o.Parent, o.Ancestry = inventory.GUID(hSys), []inventory.GUID{inventory.GUID(hSys), inventory.GUID(hDom)}
	}
	return o
}

// M4: hidden matching objects, added and removed without crossing the ceiling, change nothing a scoped
// caller receives: not the hits, the order, the counts, the more flags nor the similarity.
func se3Invariance(t *testing.T, s *storetest.Server) {
	e := setup(t, s)
	e.hStructure(t, e.adA)
	sr := e.searcher(t)
	var vis []inventory.Observation
	for i := 1; i <= 5; i++ {
		vis = append(vis, sInv(1, i, fmt.Sprintf("invp%d", i), fmt.Sprintf("Inv Person %d", i), false))
	}
	if _, err := e.populate(t, e.adA, hBase, vis...); err != nil {
		t.Fatal(err)
	}
	texts := []string{"Inv Person 3", "inv per", "Inv Prson 3", "inv", "in", "invp3", "Person"}
	run := func() map[string]inventory.SearchResult {
		out := map[string]inventory.SearchResult{}
		for _, text := range texts {
			res, err := e.search(t, sr, e.scopeOU(e.adA), inventory.SearchRequest{Text: text, GroupLimit: 50, Ceiling: 1000})
			if err != nil {
				t.Fatalf("%q: %v", text, err)
			}
			if res.Refine {
				t.Fatalf("%q: refine below the ceiling", text)
			}
			for _, h := range res.Hits {
				if h.Object[:2] == fmt.Sprintf("%02x", 2) {
					t.Fatalf("%q: hidden object %s returned to the scoped caller", text, h.Object)
				}
			}
			out[text] = res
		}
		return out
	}
	base := run()
	if len(base["Inv Person 3"].Hits) == 0 || len(base["inv per"].Hits) != 5 || len(base["Inv Prson 3"].Hits) == 0 {
		t.Fatalf("the baseline finds its visible objects: %+v", base)
	}
	check := func(label string) {
		t.Helper()
		got := run()
		for _, text := range texts {
			if !reflect.DeepEqual(got[text], base[text]) {
				t.Errorf("%s: the response to %q changed\n before %+v\n after  %+v", label, text, base[text], got[text])
			}
		}
	}
	add := func(from, to int, at time.Time, state inventory.ObjectState) {
		var hid []inventory.Observation
		for i := from; i <= to; i++ {
			o := sInv(2, i, fmt.Sprintf("invh%d", i), fmt.Sprintf("Inv Person %d", 1+i%5), true)
			o.State = state
			hid = append(hid, o)
		}
		if _, err := e.populate(t, e.adA, at, hid...); err != nil {
			t.Fatal(err)
		}
	}
	add(1, 7, hBase.Add(time.Hour), inventory.ObjLive)
	check("7 hidden matches added")
	add(8, 40, hBase.Add(2*time.Hour), inventory.ObjLive)
	check("40 hidden matches")
	add(1, 40, hBase.Add(3*time.Hour), inventory.ObjPurged)
	check("hidden matches removed")
	// the hidden objects were really there for an unscoped caller
	add(1, 40, hBase.Add(4*time.Hour), inventory.ObjLive)
	all, err := e.search(t, sr, e.scopeNC(e.adA), inventory.SearchRequest{Text: "inv per", GroupLimit: 50, Ceiling: 1000})
	if err != nil || len(all.Hits) != 45 {
		t.Fatalf("an unscoped caller sees the hidden objects: %d hits, %v", len(all.Hits), err)
	}
	check("hidden matches back")
}

// Above the ceiling a class is withheld whole: the same refine state for every caller of the world, no
// counts, no more flags, and the classes ranked above the ceiling class still answered.
func se3AboveCeiling(t *testing.T, s *storetest.Server) {
	e := setup(t, s)
	e.hStructure(t, e.adA)
	sr := e.searcher(t)
	var obs []inventory.Observation
	for i := 1; i <= 5; i++ {
		obs = append(obs, sInv(1, i, fmt.Sprintf("invp%d", i), fmt.Sprintf("Inv Person %d", i), false))
	}
	for i := 1; i <= 60; i++ { // sam keys that continue "invp3": prefix matches of it, all hidden from the technician
		obs = append(obs, sInv(2, i, fmt.Sprintf("invp3x%d", i), fmt.Sprintf("Hidden Person %d", i), true))
	}
	if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
		t.Fatal(err)
	}
	const w = 40
	res := map[string]inventory.SearchResult{}
	for name, sc := range map[string]authz.ReadScope{"scoped": e.scopeOU(e.adA), "unscoped": e.scopeNC(e.adA)} {
		r, err := e.search(t, sr, sc, inventory.SearchRequest{Text: "invp3", Ceiling: w, GroupLimit: 50})
		if err != nil {
			t.Fatal(err)
		}
		res[name] = r
		if !r.Refine || r.Count != nil || r.More != nil {
			t.Errorf("%s: want the refine state, got refine=%v count=%v more=%v", name, r.Refine, r.Count, r.More)
		}
		if len(r.Hits) != 1 || r.Hits[0].Object != hGUID(1, 3) || r.Hits[0].Class != reportsql.ClassExact {
			t.Errorf("%s: the exact class ranked above the ceiling class is still answered: %+v", name, r.Hits)
		}
	}
	if !reflect.DeepEqual(res["scoped"].Hits, res["unscoped"].Hits) || res["scoped"].Refine != res["unscoped"].Refine {
		t.Errorf("refine and the exact hits are the same for a scoped and an unscoped caller:\n%+v\n%+v", res["scoped"], res["unscoped"])
	}
	// The prefix class alone, withheld for both callers: no hit leaks through a lower class either.
	for name, sc := range map[string]authz.ReadScope{"scoped": e.scopeOU(e.adA), "unscoped": e.scopeNC(e.adA)} {
		r, _ := e.search(t, sr, sc, inventory.SearchRequest{Text: "invp", Ceiling: w, GroupLimit: 50})
		if !r.Refine || len(r.Hits) != 0 || r.Count != nil {
			t.Errorf("%s: %q is over the ceiling in the prefix class: %+v", name, "invp", r)
		}
	}
	// With the ceiling lifted the scoped caller gets the whole answer and nothing hidden.
	r, _ := e.search(t, sr, e.scopeOU(e.adA), inventory.SearchRequest{Text: "invp3", Ceiling: 1000, GroupLimit: 50})
	if r.Refine || len(r.Hits) == 0 || r.Hits[0].Object != hGUID(1, 3) || r.Hits[0].Class != reportsql.ClassExact || r.Count[reportsql.TypeUser] != len(r.Hits) {
		t.Errorf("below the ceiling: %+v", r)
	}
	for _, h := range r.Hits {
		if h.Object[:2] == "02" {
			t.Errorf("a hidden object reached the scoped caller: %s", h.Object)
		}

	}
}

func se3Gated(t *testing.T) {
	for _, k := range searchkey.AllKinds {
		if k.Permission() != searchkey.DirectoryRead {
			t.Fatalf("key kind %d is read under %q: extend SE3 with a world holding such keys and a caller without that permission, whose response must equal the same world without them", k, k.Permission())
		}
	}
}

func se3Empty(t *testing.T, s *storetest.Server) {
	e := setup(t, s)
	e.hStructure(t, e.adA)
	sr := e.searcher(t)
	if _, err := e.populate(t, e.adA, hBase, sSrchUser(1, "visible1", "Visible Match")); err != nil {
		t.Fatal(err)
	}
	for name, scopes := range map[string]reportsql.SearchScopes{
		"empty scope":      {"directory.read": authz.ReadScope{}},
		"no permission":    {},
		"another perm":     {"reports.run": e.scopeNC(e.adA)},
		"nil scope entry":  nil,
		"read, but others": {"directory.read": authz.ReadScope{}, "reports.run": e.scopeNC(e.adA)},
	} {
		var res inventory.SearchResult
		err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
			res, err = sr.Search(ctx, tx, e.a, scopes, inventory.SearchRequest{Text: "Visible Match"})
			return
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(res.Hits) != 0 || res.Refine {
			t.Errorf("%s: zero hits, no refine: %+v", name, res)
		}
	}
	// The empty scope names its reason.
	var res inventory.SearchResult
	_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
		res, err = sr.Search(ctx, tx, e.a, reportsql.SearchScopes{"directory.read": authz.ReadScope{}}, inventory.SearchRequest{Text: "Visible Match"})
		return
	})
	if !slices.Contains(res.ScopeReasons, "scope_empty") {
		t.Errorf("an empty scope gives its reason: %v", res.ScopeReasons)
	}
}
