package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func (e *env) searcher(t *testing.T) *inventory.Searcher {
	t.Helper()
	var s *inventory.Searcher
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		sc, err := reportsql.CatalogSchema(ctx, tx)
		if err != nil {
			return err
		}
		s, err = inventory.NewSearcher(sc)
		return err
	}); err != nil {
		t.Fatalf("searcher: %v", err)
	}
	return s
}

func (e *env) search(t *testing.T, s *inventory.Searcher, scope authz.ReadScope, req inventory.SearchRequest) (inventory.SearchResult, error) {
	t.Helper()
	var res inventory.SearchResult
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
		res, err = s.Search(ctx, tx, e.a, reportsql.SearchScopes{"directory.read": scope}, req)
		return
	})
	return res, err
}

// sUser is a user named name with the given sam, under the OU of the structure.
func sSrchUser(i int, sam, name string) inventory.Observation {
	o := hUser{guid: hGUID(1, i), sam: sam, rid: uint32(2000 + i)}.obs()
	o.DisplayName = name
	o.UPN = sam + "@example.test"
	return o
}

func searchGUIDs(res inventory.SearchResult) []string {
	var out []string
	for _, h := range res.Hits {
		out = append(out, h.Object)
	}
	return out
}

func (e *env) keys(t *testing.T, guid string) []string {
	t.Helper()
	return e.strings(t, `SELECT key_kind::text || ':' || key FROM public.inventory_search_keys WHERE object_guid = $1::uuid ORDER BY 1`, guid)
}

func Test_search_keys_follow_the_object_in_its_transaction(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		u := sSrchUser(1, "praman", "Priya Raman")
		if _, err := e.populate(t, e.adA, hBase, u); err != nil {
			t.Fatal(err)
		}
		got := strings.Join(e.keys(t, string(u.Object)), "|")
		for _, want := range []string{"1:priya raman", "1:praman", "2:priya", "2:raman", "3:praman", "4:praman@example.test", "8:" + hGUID(1, 1), "10:cn=praman,ou=people,dc=example,dc=test"} {
			if !strings.Contains(got, want) {
				t.Errorf("keys %q lack %q", got, want)
			}
		}
		// Renamed: the old name key is gone and the new one is there, in the same call.
		u2 := u
		u2.DisplayName = "Priya Raman-Iyer"
		if _, err := e.populate(t, e.adA, hBase.Add(time.Hour), u2); err != nil {
			t.Fatal(err)
		}
		got = strings.Join(e.keys(t, string(u.Object)), "|")
		if strings.Contains(got, "1:priya raman|") || !strings.Contains(got, "1:priya raman iyer") || !strings.Contains(got, "2:iyer") {
			t.Errorf("rename: %q", got)
		}
		// Fault injection: a cycle that fails after the object write rolls the keys back with it.
		before := e.keys(t, string(u.Object))
		u3 := u
		u3.DisplayName = "Never Committed"
		err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			if _, err := pop.Populate(ctx, tx, e.adA, hBase.Add(2*time.Hour), []inventory.Observation{u3}); err != nil {
				return err
			}
			inside := e.countIn(ctx, tx, `SELECT count(*) FROM public.inventory_search_keys WHERE key = 'never committed'`)
			if inside != 1 {
				t.Errorf("the key is current inside the writer's transaction: %d", inside)
			}
			return errors.New("injected failure after the write")
		})
		if err == nil {
			t.Fatal("expected the injected failure")
		}
		if after := e.keys(t, string(u.Object)); strings.Join(after, "|") != strings.Join(before, "|") {
			t.Errorf("rollback changed the keys:\n%v\n%v", before, after)
		}
		// Deleted: still indexed (ranked after live); purged: no keys.
		u4 := u2
		u4.State = inventory.ObjDeleted
		if _, err := e.populate(t, e.adA, hBase.Add(3*time.Hour), u4); err != nil {
			t.Fatal(err)
		}
		if len(e.keys(t, string(u.Object))) == 0 {
			t.Error("a deleted object stays findable")
		}
		u5 := u2
		u5.State = inventory.ObjPurged
		if _, err := e.populate(t, e.adA, hBase.Add(4*time.Hour), u5); err != nil {
			t.Fatal(err)
		}
		if k := e.keys(t, string(u.Object)); len(k) != 0 {
			t.Errorf("a purged object has no keys: %v", k)
		}
	})
}

func (e *env) countIn(ctx context.Context, tx store.Tx, sql string) (n int) {
	_ = tx.QueryRow(ctx, sql).Scan(&n)
	return
}

func Test_search_exact_prefix_fuzzy_classes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		sr := e.searcher(t)
		if _, err := e.populate(t, e.adA, hBase, sSrchUser(1, "praman", "Priya Raman"), sSrchUser(2, "pramanujan", "Pramod Anujan"), sSrchUser(3, "jdoe", "John Doe"),
			sSrchUser(4, "lodz", "Łódź Office")); err != nil {
			t.Fatal(err)
		}
		scope := e.scopeNC(e.adA)
		for _, c := range []struct {
			name, text string
			want       string // object that must be first
			class      reportsql.SearchClass
		}{
			{"exact_sam", "praman", hGUID(1, 1), reportsql.ClassExact},
			{"exact_upn", "JDoe@Example.test", hGUID(1, 3), reportsql.ClassExact},
			{"exact_guid", "{" + strings.ToUpper(hGUID(1, 3)) + "}", hGUID(1, 3), reportsql.ClassExact},
			{"prefix_name", "Priya R", hGUID(1, 1), reportsql.ClassPrefix},
			{"prefix_word", "raman", hGUID(1, 1), reportsql.ClassPrefix},
			{"prefix_comma_swap", "Raman, Priya", hGUID(1, 1), reportsql.ClassPrefix},
			{"prefix_folded", "LODZ off", hGUID(1, 4), reportsql.ClassPrefix},
			{"fuzzy_misspelling", "Pryia Ramn", hGUID(1, 1), reportsql.ClassFuzzy},
		} {
			t.Run(c.name, func(t *testing.T) {
				res, err := e.search(t, sr, scope, inventory.SearchRequest{Text: c.text})
				if err != nil {
					t.Fatal(err)
				}
				if len(res.Hits) == 0 || res.Hits[0].Object != c.want || res.Hits[0].Class != c.class {
					t.Fatalf("hits %+v, want %s first with class %s", res.Hits, c.want, c.class)
				}
				if c.class == reportsql.ClassFuzzy && res.Hits[0].Similarity <= 0 {
					t.Errorf("a fuzzy hit carries its similarity: %v", res.Hits[0].Similarity)
				}
				if res.Refine {
					t.Error("refine on a tiny tenant")
				}
			})
		}
		// the same object appears once, in its best class
		res, _ := e.search(t, sr, scope, inventory.SearchRequest{Text: "praman"})
		seen := map[string]bool{}
		for _, h := range res.Hits {
			if seen[h.Object] {
				t.Errorf("object %s twice", h.Object)
			}
			seen[h.Object] = true
		}
		// counts: from three characters, exact below the ceiling
		if res.Count[reportsql.TypeUser] != 2 {
			t.Errorf("praman matches praman (exact) and pramanujan (prefix): count %v", res.Count)
		}
		short, _ := e.search(t, sr, scope, inventory.SearchRequest{Text: "pr"})
		if short.Count != nil || len(short.Hits) == 0 {
			t.Errorf("no count under three characters: %v hits %d", short.Count, len(short.Hits))
		}
	})
}

func Test_search_is_trimmed_by_the_scope(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		sr := e.searcher(t)
		out := sSrchUser(2, "hidden1", "Hidden Match")
		out.Parent, out.Ancestry = inventory.GUID(hSys), []inventory.GUID{inventory.GUID(hSys), inventory.GUID(hDom)}
		if _, err := e.populate(t, e.adA, hBase, sSrchUser(1, "visible1", "Visible Match"), out); err != nil {
			t.Fatal(err)
		}
		res, err := e.search(t, sr, e.scopeOU(e.adA), inventory.SearchRequest{Text: "match"})
		if err != nil {
			t.Fatal(err)
		}
		if g := searchGUIDs(res); len(g) != 1 || g[0] != hGUID(1, 1) {
			t.Fatalf("an OU-scoped caller sees only the OU: %v", g)
		}
		if res.Count[reportsql.TypeUser] != 1 {
			t.Errorf("counts come after trimming: %v", res.Count)
		}
		all, _ := e.search(t, sr, e.scopeNC(e.adA), inventory.SearchRequest{Text: "match"})
		if len(all.Hits) != 2 {
			t.Errorf("the NC-wide caller sees both: %v", searchGUIDs(all))
		}
		// An empty scope answers nothing, with its reason.
		none, err := e.search(t, sr, authz.ReadScope{}, inventory.SearchRequest{Text: "match"})
		if err != nil || len(none.Hits) != 0 {
			t.Errorf("empty scope: %v %v", none.Hits, err)
		}
	})
}

func Test_search_ceiling_withholds_a_class_whole(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		sr := e.searcher(t)
		var obs []inventory.Observation
		for i := 1; i <= 6; i++ {
			obs = append(obs, sSrchUser(i, fmt.Sprintf("zed%d", i), fmt.Sprintf("Zed Person %d", i)))
		}
		hidden := sSrchUser(7, "zed7", "Zed Hidden")
		hidden.Parent, hidden.Ancestry = inventory.GUID(hSys), []inventory.GUID{inventory.GUID(hSys), inventory.GUID(hDom)}
		obs = append(obs, hidden)
		if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		// W=100: nothing hits the ceiling and the scoped caller sees exactly its six.
		w10, _ := e.search(t, sr, e.scopeOU(e.adA), inventory.SearchRequest{Text: "zed", Ceiling: 100, GroupLimit: 50})
		if w10.Refine || len(w10.Hits) != 6 || w10.Count[reportsql.TypeUser] != 6 {
			t.Fatalf("below the ceiling: refine=%v hits=%d count=%v", w10.Refine, len(w10.Hits), w10.Count)
		}
		// W=3: the prefix class holds more than three key rows for every caller, scoped or not.
		for name, sc := range map[string]authz.ReadScope{"scoped": e.scopeOU(e.adA), "unscoped": e.scopeNC(e.adA)} {
			r, err := e.search(t, sr, sc, inventory.SearchRequest{Text: "zed", Ceiling: 3})
			if err != nil {
				t.Fatal(err)
			}
			if !r.Refine || len(r.Hits) != 0 || r.Count != nil || r.More != nil {
				t.Errorf("%s: want the refine state, got refine=%v hits=%d count=%v more=%v", name, r.Refine, len(r.Hits), r.Count, r.More)
			}
		}
		// The exact class ranked above the ceiling is still answered.
		r, _ := e.search(t, sr, e.scopeOU(e.adA), inventory.SearchRequest{Text: "zed1", Ceiling: 3})
		if len(r.Hits) == 0 || r.Hits[0].Object != hGUID(1, 1) || r.Hits[0].Class != reportsql.ClassExact {
			t.Errorf("exact survives: %+v", r.Hits)
		}
		// More: the group limit.
		lim, _ := e.search(t, sr, e.scopeOU(e.adA), inventory.SearchRequest{Text: "zed", Ceiling: 100, GroupLimit: 2})
		if len(lim.Hits) != 2 || !lim.More[reportsql.TypeUser] || lim.Count[reportsql.TypeUser] != 6 {
			t.Errorf("limit: hits=%d more=%v count=%v", len(lim.Hits), lim.More, lim.Count)
		}
		// Keyset: the second page starts after the first.
		last := lim.Hits[len(lim.Hits)-1].Rank
		next, _ := e.search(t, sr, e.scopeOU(e.adA), inventory.SearchRequest{Text: "zed", Ceiling: 100, GroupLimit: 2, After: &last})
		if len(next.Hits) != 2 || next.Hits[0].Object == lim.Hits[0].Object || next.Hits[0].Object == lim.Hits[1].Object {
			t.Errorf("page 2: %v after %v", searchGUIDs(next), searchGUIDs(lim))
		}
	})
}

func Test_search_text_is_a_bound_parameter(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		sr := e.searcher(t)
		if _, err := e.populate(t, e.adA, hBase, sSrchUser(1, "pct", "100% real"), sSrchUser(2, "under", "a_b under"), sSrchUser(3, "plain", "axb plain"),
			sSrchUser(4, "quote", `O'Brien`), sSrchUser(5, "back", `back\slash`)); err != nil {
			t.Fatal(err)
		}
		scope := e.scopeNC(e.adA)
		for _, c := range []struct{ text, want string }{
			{"100%", hGUID(1, 1)}, {"%", ""}, {"_", ""}, {"a_b", hGUID(1, 2)}, {`back\slash`, hGUID(1, 5)}, {"O'Brien", hGUID(1, 4)},
			{"'; DROP TABLE directory_objects; --", ""}, {"$1", ""}, {"%%%%", ""}, {`\`, ""},
		} {
			res, err := e.search(t, sr, scope, inventory.SearchRequest{Text: c.text})
			if err != nil {
				t.Errorf("%q: %v", c.text, err)
				continue
			}
			g := searchGUIDs(res)
			if c.want == "" && len(g) != 0 || c.want != "" && (len(g) == 0 || g[0] != c.want) {
				t.Errorf("%q matched %v, want %q", c.text, g, c.want)
			}
		}
		// "a_b" must not match "axb" (an underscore is not a pattern)
		res, _ := e.search(t, sr, scope, inventory.SearchRequest{Text: "a b"})
		for _, h := range res.Hits {
			if h.Object == hGUID(1, 3) && h.Class != reportsql.ClassFuzzy {
				t.Errorf("axb matched a_b literally: %+v", h)
			}
		}
		for name, text := range map[string]string{"nul": "ab\x00cd", "utf8": "ab\xffcd", "long": strings.Repeat("a", 5000), "257": strings.Repeat("a", 257),
			"recovery": strings.Repeat("1234567", 7)} {
			if _, err := e.search(t, sr, scope, inventory.SearchRequest{Text: text}); !errors.Is(err, inventory.ErrSearchRefused) {
				t.Errorf("%s: err = %v", name, err)
			}
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects`); n < 5 {
			t.Fatalf("the table survived the injection attempts: %d", n)
		}
	})
}

func Test_search_stores_no_secret_attribute(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		const secret = "S3cr3t-Value-Zq9"
		for i, name := range []string{"ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
			"msDS-ManagedPassword", "msFVE-RecoveryPassword"} {
			c := hUser{guid: hGUID(3, 10+i), sam: fmt.Sprintf("cmp%d", i), rid: uint32(3000 + i), kind: inventory.KindComputer, class: "computer"}.obs()
			c.Attributes = map[string]any{name: secret, "dNSHostName": fmt.Sprintf("cmp%d.example.test", i)}
			if _, err := e.populate(t, e.adA, hBase, c); err == nil {
				t.Errorf("%s: an observation carrying a secret attribute is refused", name)
			}
		}
		// A custom attribute marked confidential (searchFlags 0x80) is dropped by the producer; and even
		// if it reaches the bag, no key is built from it: keys read an allow-list, never the bag.
		c := hUser{guid: hGUID(3, 1), sam: "pc1", rid: 3100, kind: inventory.KindComputer, class: "computer"}.obs()
		c.Attributes = map[string]any{"customConfidential": secret, "dNSHostName": "pc1.example.test", "description": secret, "mail": secret}
		if _, err := e.populate(t, e.adA, hBase, c); err != nil {
			t.Fatal(err)
		}
		if n := e.count(t, `SELECT count(*) FROM public.inventory_search_keys WHERE position('s3cr3t' in lower(key)) > 0`); n != 0 {
			t.Errorf("a secret value is in the index: %d keys", n)
		}
		if got := strings.Join(e.keys(t, hGUID(3, 1)), "|"); !strings.Contains(got, "6:pc1.example.test") {
			t.Errorf("the allow-listed dNSHostName is indexed: %s", got)
		}
	})
}

func Test_search_backfill_indexes_each_object_once(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		var obs []inventory.Observation
		for i := 1; i <= 30; i++ {
			obs = append(obs, sSrchUser(i, fmt.Sprintf("u%02d", i), fmt.Sprintf("User Number %d", i)))
		}
		if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		want := e.count(t, `SELECT count(*) FROM public.inventory_search_keys`)
		if want == 0 {
			t.Fatal("no keys")
		}
		// An existing inventory that predates the index: no keys at all.
		if err := e.exec(e.a, `DELETE FROM public.inventory_search_keys`); err != nil {
			t.Fatal(err)
		}
		if n := e.count(t, `SELECT count(*) FROM public.inventory_search_keys`); n != 0 {
			t.Fatalf("the fixture delete left %d keys", n)
		}
		var ticks int
		got, err := e.r.Backfill(context.Background(), e.a, func(inventory.BackfillProgress) { ticks++ })
		if err != nil {
			t.Fatal(err)
		}
		// 30 users + the structure rows (NC head, OU, container are not searchable)
		if got.Objects != 33 || got.Indexed != 30 || got.Inserted != want || got.Updated != 0 || got.Deleted != 0 || ticks == 0 {
			t.Fatalf("backfill: %+v ticks %d, want %d inserted", got, ticks, want)
		}
		if n := e.count(t, `SELECT count(*) FROM public.inventory_search_keys`); n != want {
			t.Fatalf("keys %d want %d", n, want)
		}
		again, err := e.r.Backfill(context.Background(), e.a, nil)
		if err != nil || again.Inserted != 0 || again.Updated != 0 || again.Deleted != 0 || again.Objects != 33 {
			t.Fatalf("a second run changes nothing: %+v %v", again, err)
		}
		// A key built by another normaliser version, and a key of nothing, are corrected.
		if err := e.exec(e.a, `UPDATE public.inventory_search_keys SET norm_version = 2 WHERE key_kind = 1`); err != nil {
			t.Fatal(err)
		}
		if err := e.exec(e.a, `INSERT INTO public.inventory_search_keys (tenant_id, connection_id, object_guid, key_kind, key, norm_version)
			SELECT tenant_id, connection_id, object_guid, 1, 'stale key', 1 FROM public.directory_objects LIMIT 1`); err != nil {
			t.Fatal(err)
		}
		fix, err := e.r.Backfill(context.Background(), e.a, nil)
		if err != nil || fix.Updated == 0 || fix.Deleted != 1 {
			t.Fatalf("stale rows: %+v %v", fix, err)
		}
		// Search works on the backfilled index.
		sr := e.searcher(t)
		res, err := e.search(t, sr, e.scopeNC(e.adA), inventory.SearchRequest{Text: "User Number 7"})
		if err != nil || len(res.Hits) == 0 || res.Hits[0].Object != hGUID(1, 7) {
			t.Fatalf("search after backfill: %v %v", searchGUIDs(res), err)
		}
	})
}
