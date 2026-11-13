package inventory_test

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// T-1335 (ADR-0011 rev 3, rule 5a): the trigram posting table, its triggers and the probe built on them.

// ownerTenant runs fixture SQL as the migration owner with the tenant set: FORCE row security binds the owner
// to the one tenant, and there is no statement timeout, so a bulk load that the 30 s tenant transaction would
// cancel can run. The statement is test fixture text.
func (e *env) ownerTenant(t *testing.T, tid tenant.ID, query func(ctx context.Context, q func(sql string, args ...any) []string) error) {
	t.Helper()
	ctx := context.Background()
	// The tenant is a start-up parameter of the owner connection, so that no SET text appears in a test.
	c, err := e.d.OwnerForTenant(ctx, tid.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	q := func(sql string, args ...any) []string {
		rs, err := c.Query(ctx, sql, args...)
		if err != nil {
			t.Fatalf("%v\n%s", err, sql)
		}
		defer rs.Close()
		var out []string
		for rs.Next() {
			var s *string
			if err := rs.Scan(&s); err != nil {
				// a command with no column
				return out
			}
			if s != nil {
				out = append(out, *s)
			}
		}
		if err := rs.Err(); err != nil {
			t.Fatalf("%v\n%s", err, sql)
		}
		return out
	}
	if err := query(ctx, q); err != nil {
		t.Fatal(err)
	}
}

func (e *env) ownerRun(t *testing.T, tid tenant.ID, sql string, args ...any) []string {
	t.Helper()
	var out []string
	e.ownerTenant(t, tid, func(_ context.Context, q func(string, ...any) []string) error { out = q(sql, args...); return nil })
	return out
}

// synName builds a deterministic name from g out of 40 syllables, so that tenant B can hold the same names as A.
const synName = `(SELECT (array['ka','ri','mo','sha','pri','ya','ram','an','ji','lo','ve','na','du','te','ba','ho','la','sen','ko','mi','ar','el','os','un','ti','ger','man','dov','ska','wen','fi','zu','qui','bra','lin','cha','dre','sol','pet','nik'])[1 + (g %% 40)]
	|| (array['ka','ri','mo','sha','pri','ya','ram','an','ji','lo','ve','na','du','te','ba','ho','la','sen','ko','mi','ar','el','os','un','ti','ger','man','dov','ska','wen','fi','zu','qui','bra','lin','cha','dre','sol','pet','nik'])[1 + ((g / 40) %% 40)]
	|| ' ' || (array['ka','ri','mo','sha','pri','ya','ram','an','ji','lo','ve','na','du','te','ba','ho','la','sen','ko','mi','ar','el','os','un','ti','ger','man','dov','ska','wen','fi','zu','qui','bra','lin','cha','dre','sol','pet','nik'])[1 + ((g * 7) %% 40)]
	|| (array['ka','ri','mo','sha','pri','ya','ram','an','ji','lo','ve','na','du','te','ba','ho','la','sen','ko','mi','ar','el','os','un','ti','ger','man','dov','ska','wen','fi','zu','qui','bra','lin','cha','dre','sol','pet','nik'])[1 + ((g / 3) %% 40)])`

// fillObjects inserts one 'user' object per name (display name) into the tenant, copying the tenant's first
// user row, with a name key (kind 1) and a sam key (kind 3) each: the keys of an object that the sync writer
// writes, in bulk. names is a SQL set of (g, name) rows.
func (e *env) fillObjects(t *testing.T, tid tenant.ID, names string) {
	t.Helper()
	e.ownerRun(t, tid, `WITH o AS (
			INSERT INTO public.directory_objects (tenant_id, connection_id, object_guid, nc_guid, kind, object_class, parent_guid, ancestry, ancestry_complete, display_name, observed_at, state)
			SELECT t.tenant_id, t.connection_id, gen_random_uuid(), t.nc_guid, 'user', 'user', t.parent_guid, t.ancestry, true, n.name, t.observed_at, 'live'
			FROM (SELECT * FROM public.directory_objects WHERE kind = 'user' LIMIT 1) t CROSS JOIN (`+names+`) n
			RETURNING tenant_id, connection_id, object_guid, display_name)
		INSERT INTO public.inventory_search_keys (tenant_id, connection_id, object_guid, key_kind, key, norm_version)
		SELECT tenant_id, connection_id, object_guid, 1, lower(display_name), 1 FROM o
		UNION ALL SELECT tenant_id, connection_id, object_guid, 3, replace(lower(display_name), ' ', '.'), 1 FROM o`)
}

// fillKeys adds n synthetic users (names 1..n) to the tenant.
func (e *env) fillKeys(t *testing.T, tid tenant.ID, n int) { e.fillRange(t, tid, 1, n) }

func (e *env) fillRange(t *testing.T, tid tenant.ID, from, to int) {
	t.Helper()
	e.fillObjects(t, tid, fmt.Sprintf(`SELECT g, %s AS name FROM generate_series(%d, %d) g`, strings.ReplaceAll(synName, "%%", "%"), from, to))
}

// vacuumSearch brings the visibility maps and statistics of the search tables up to date, as the runner does
// after migration 0074 and an operator does after a bulk load.
func (e *env) vacuumSearch(t *testing.T) {
	t.Helper()
	// Twice: the first pass cannot mark a page all-visible past a row whose inserting transaction is still
	// inside the oldest snapshot, so an Index Only Scan would fetch heap pages for those rows.
	for pass := 0; pass < 2; pass++ {
		for _, tbl := range []string{"inventory_search_trigrams", "inventory_search_keys", "directory_objects"} {
			if err := e.d.ExecOwner(context.Background(), `VACUUM (ANALYZE) public.`+tbl); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// trgDiff compares the postings of the tenant with the set (tenant_id, t, key_id) for t in show_trgm(key) over
// its name and sam keys: rows missing, rows extra, and the number expected.
func (e *env) trgDiff(t *testing.T, tid tenant.ID) (missing, extra, want int) {
	t.Helper()
	const exp = `SELECT k.tenant_id, g.trgm, k.key_id FROM public.inventory_search_keys k CROSS JOIN LATERAL unnest(public.show_trgm(k.key)) AS g(trgm) WHERE k.key_kind IN (1, 3)`
	const act = `SELECT tenant_id, trgm, key_id FROM public.inventory_search_trigrams`
	var out []string
	e.ownerTenant(t, tid, func(_ context.Context, q func(string, ...any) []string) error {
		out = append(out, q(`SELECT count(*)::text FROM (`+exp+` EXCEPT `+act+`) d`)...)
		out = append(out, q(`SELECT count(*)::text FROM (`+act+` EXCEPT `+exp+`) d`)...)
		out = append(out, q(`SELECT count(*)::text FROM (`+exp+`) d`)...)
		return nil
	})
	fmt.Sscan(out[0], &missing)
	fmt.Sscan(out[1], &extra)
	fmt.Sscan(out[2], &want)
	return
}

func (e *env) wantPostings(t *testing.T, when string) int {
	t.Helper()
	missing, extra, want := e.trgDiff(t, e.a)
	if missing != 0 || extra != 0 {
		t.Fatalf("%s: postings differ from show_trgm over the name and sam keys: %d missing, %d orphan or extra (of %d expected)", when, missing, extra, want)
	}
	return want
}

// assertFuzzyPlan is AC4/SE5: the fuzzy probe reads the posting B-tree and rechecks per candidate.
func assertFuzzyPlan(t *testing.T, plan *planNode) {
	t.Helper()
	var posting, recheck, loop int
	plan.walk("", func(n *planNode, cte string) {
		switch n.Relation {
		case "inventory_search_keys", "inventory_search_trigrams", "directory_objects":
			if strings.Contains(n.Type, "Seq Scan") {
				t.Errorf("%s on %s (%s)", n.Type, n.Relation, cte)
			}
		}
		if cte != "m_fuzzy" {
			return
		}
		if n.Type == "Hash Join" || n.Type == "Merge Join" {
			t.Errorf("m_fuzzy has a %s: the recheck must be a correlated loop", n.Type)
		}
		if n.Type == "Nested Loop" {
			loop++
		}
		if n.Index == "inventory_search_trigrams_pkey" {
			posting++
			if n.Type != "Index Only Scan" && n.Type != "Index Scan" && n.Type != "Bitmap Index Scan" {
				t.Errorf("posting scan is a %s", n.Type)
			}
			if !strings.Contains(n.IndexCond, "tenant_id") || !strings.Contains(n.IndexCond, "trgm") {
				t.Errorf("posting Index Cond %q must hold tenant_id and trgm", n.IndexCond)
			}
		}
		if n.Relation == "inventory_search_keys" {
			recheck++
			if (n.Type != "Index Scan" && n.Type != "Index Only Scan") || n.Index != "inventory_search_keys_tenant_key_id_key" {
				t.Errorf("recheck is a %s via %q, want an Index Scan of inventory_search_keys_tenant_key_id_key", n.Type, n.Index)
			}
			if !strings.Contains(n.IndexCond, "key_id") || !strings.Contains(n.IndexCond, "tenant_id") {
				t.Errorf("recheck Index Cond %q must hold tenant_id and key_id", n.IndexCond)
			}
		}
	})
	if posting != 1 || recheck != 1 || loop == 0 {
		t.Errorf("m_fuzzy shape: %d posting index scans, %d key rechecks, %d nested loops, want 1, 1, >= 1", posting, recheck, loop)
	}
}

// AC2: the postings are exactly show_trgm over the name and sam keys, whichever writer touches the keys.
func Test_search_trigrams_follow_every_writer(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		u1, u2 := sSrchUser(1, "praman", "Priya Raman"), sSrchUser(2, "jdoe", "Jóhn Döe, Jr.")
		if _, err := e.populate(t, e.adA, hBase, u1, u2); err != nil {
			t.Fatal(err)
		}
		if n := e.wantPostings(t, "sync writer insert"); n == 0 {
			t.Fatal("no postings were built for the name and sam keys")
		}
		var other int
		fmt.Sscan(e.ownerRun(t, e.a, `SELECT count(*)::text FROM public.inventory_search_keys WHERE key_kind NOT IN (1, 3)`)[0], &other)
		if other == 0 {
			t.Fatal("the fixture has no other-kind keys")
		}
		// The sync writer again with a changed name and sam: delete and insert.
		u1.DisplayName, u1.SAMAccountName = "Priya Raman-Iyer", "pramaniyer"
		if _, err := e.populate(t, e.adA, hBase, u1, u2); err != nil {
			t.Fatal(err)
		}
		e.wantPostings(t, "sync writer rename")
		// The dn rewrite of an OU move: a re-observation under another parent rewrites the dn key.
		u2.DN = "CN=Doe,OU=Elsewhere,DC=example,DC=test"
		if _, err := e.populate(t, e.adA, hBase, u2); err != nil {
			t.Fatal(err)
		}
		e.wantPostings(t, "dn rewrite")
		// The norm_version backfill (an UPDATE that changes no key), and a backfill that has to insert.
		if err := e.exec(e.a, `UPDATE public.inventory_search_keys SET norm_version = 2`); err != nil {
			t.Fatal(err)
		}
		if _, err := e.r.Backfill(context.Background(), e.a, nil); err != nil {
			t.Fatal(err)
		}
		e.wantPostings(t, "norm_version backfill")
		// A key_kind change in both directions: name to upn and back, upn to sam and back.
		for _, step := range []struct{ sql, when string }{
			{`UPDATE public.inventory_search_keys SET key_kind = 4 WHERE key_kind = 1 AND object_guid = '` + string(u1.Object) + `'`, "name to upn"},
			{`UPDATE public.inventory_search_keys SET key_kind = 1 WHERE key_kind = 4 AND object_guid = '` + string(u1.Object) + `' AND position('@' in key) = 0`, "upn back to name"},
			{`UPDATE public.inventory_search_keys SET key_kind = 3 WHERE key_kind = 4 AND object_guid = '` + string(u2.Object) + `'`, "upn to sam"},
			{`UPDATE public.inventory_search_keys SET key_kind = 5 WHERE key_kind = 3 AND object_guid = '` + string(u2.Object) + `' AND position('@' in key) > 0`, "sam back to mail"},
		} {
			if err := e.exec(e.a, step.sql); err != nil {
				t.Fatalf("%s: %v", step.when, err)
			}
			e.wantPostings(t, step.when)
		}
		// Object deletion.
		if err := e.exec(e.a, `DELETE FROM public.inventory_search_keys WHERE object_guid = $1::uuid`, string(u2.Object)); err != nil {
			t.Fatal(err)
		}
		// (the runtime role holds no DELETE on directory_objects: the owner, bound to the tenant, purges it)
		e.ownerRun(t, e.a, `DELETE FROM public.directory_objects WHERE object_guid = $1::uuid`, string(u2.Object))
		e.wantPostings(t, "object deletion")
		// An FK-cascade deletion: on PostgreSQL 18 the AFTER trigger of the cascaded delete runs as the role that
		// queued it (the table owner). The foreign key is made ON DELETE CASCADE for this test only.
		fk := e.ownerRun(t, e.a, `SELECT conname FROM pg_constraint WHERE conrelid = 'public.inventory_search_keys'::regclass AND contype = 'f' AND confrelid = 'public.directory_objects'::regclass`)
		if len(fk) != 1 {
			t.Fatalf("foreign keys to directory_objects: %v", fk)
		}
		if err := e.d.ExecOwner(context.Background(), `ALTER TABLE public.inventory_search_keys DROP CONSTRAINT `+fk[0]+`;
			ALTER TABLE public.inventory_search_keys ADD CONSTRAINT `+fk[0]+` FOREIGN KEY (tenant_id, connection_id, object_guid)
			REFERENCES public.directory_objects (tenant_id, connection_id, object_guid) ON DELETE CASCADE`); err != nil {
			t.Fatal(err)
		}
		before := e.wantPostings(t, "before the cascade")
		e.ownerRun(t, e.a, `DELETE FROM public.directory_objects WHERE object_guid = $1::uuid`, string(u1.Object))
		if after := e.wantPostings(t, "FK cascade deletion"); after >= before {
			t.Errorf("the cascade removed no postings: %d -> %d", before, after)
		}
		// Row security still binds the writer: another tenant's keys are not touched.
		if m, x, _ := e.trgDiff(t, e.b); m != 0 || x != 0 {
			t.Errorf("tenant B: %d missing, %d extra", m, x)
		}
	})
}

// AC3: the candidate bound loses nothing. For random queries of 3 to 32 runes and thresholds 0.3-0.7, the
// objects the fuzzy class can match equal the index-free oracle of $q <% key over every name and sam key. The
// float4-sensitive cases (0.56 with n = 25, 0.7 with n = 10, 0.3 with n = 10) are built in.
func Test_search_fuzzy_candidates_lose_nothing(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		if _, err := e.populate(t, e.adA, hBase, sSrchUser(1, "seed", "Seed Person")); err != nil {
			t.Fatal(err)
		}
		e.fillKeys(t, e.a, 1500)
		rng := rand.New(rand.NewSource(1335))
		// Sensitive worlds: a query word of 24 letters (n = 25) and two of 9 (n = 10), and keys that share
		// exactly c of its trigrams. The first L letters of the word share L trigrams with it (the two
		// leading padded trigrams and the L-2 interior ones), so every c from 3 to the whole word is built,
		// which covers the float4 boundary and one either side of it. At 0.56 with n = 25 the float4 rule
		// admits c = 14 where ceil(t*n) in double needs 15: the key of 14 letters is the one a tightened
		// bound drops.
		type probe struct {
			text string
			th   float32
			must string // the boundary key, where ceil(t*n) in double is tighter than the float4 rule: the statement has to return it
		}
		sens := []struct {
			word string
			n    int
			th   float32
		}{{"qwvxjzkhgfdsapoiuytrewqm", 25, 0.56}, {"zxcvbnmkj", 10, 0.7}, {"mnbvcxzlk", 10, 0.3}}
		var queries []probe
		for _, c := range sens {
			if got := e.ownerRun(t, e.a, `SELECT cardinality(public.show_trgm($1))::text`, c.word); len(got) != 1 || got[0] != fmt.Sprint(c.n) {
				t.Fatalf("the sensitive query %q has n = %v, want %d", c.word, got, c.n)
			}
			// The smallest c the float4 rule admits, and the one ceil(t*n) in double would need.
			bnd := 1
			for float32(bnd)/float32(c.n) < c.th {
				bnd++
			}
			dbl := int(math.Ceil(float64(c.th) * float64(c.n)))
			if bnd >= dbl && c.n == 25 {
				t.Fatalf("the world is degenerate: float4 boundary %d, double boundary %d (the double form must be tighter at n = 25, t = %v)", bnd, dbl, c.th)
			}
			var names []string
			for l := 3; l <= len(c.word); l++ {
				names = append(names, c.word[:l])
			}
			e.fillObjects(t, e.a, "SELECT 0 AS g, n AS name FROM unnest(ARRAY['"+strings.Join(names, "','")+"']) n")
			// The keys really share the intended number of trigrams with the query.
			for _, l := range []int{bnd - 1, bnd, bnd + 1} {
				got := e.ownerRun(t, e.a, `SELECT cardinality(ARRAY(SELECT unnest(public.show_trgm($1)) INTERSECT SELECT unnest(public.show_trgm($2))))::text`, c.word, c.word[:l])
				if len(got) != 1 || got[0] != fmt.Sprint(l) {
					t.Fatalf("%q: the key %q shares %v trigrams with the query, want %d", c.word, c.word[:l], got, l)
				}
			}
			pr := probe{text: c.word, th: c.th}
			if dbl > bnd {
				// pg_trgm's operator decides the other boundaries (at 0.7 with n = 10 it refuses the key whose
				// word_similarity prints as 0.7): there the oracle comparison alone applies. Where the double form
				// is tighter, the boundary key is required, so the test fails if that form comes back.
				pr.must = c.word[:bnd]
			}
			queries = append(queries, pr)
		}
		// Random queries: a mutated name, or two names run together, 3-32 runes, any threshold.
		stored := e.ownerRun(t, e.a, `SELECT key FROM public.inventory_search_keys WHERE key_kind = 1 ORDER BY key LIMIT 400`)
		ths := []float32{0.3, 0.4, 0.5, 0.56, 0.6, 0.7}
		for i := 0; i < 120; i++ {
			q := []rune(stored[rng.Intn(len(stored))])
			if rng.Intn(3) == 0 {
				q = append(q, append([]rune{' '}, []rune(stored[rng.Intn(len(stored))])...)...)
			}
			for m := rng.Intn(4); m > 0 && len(q) > 0; m-- {
				switch rng.Intn(3) {
				case 0:
					j := rng.Intn(len(q))
					q = append(q[:j], q[j+1:]...)
				case 1:
					q[rng.Intn(len(q))] = rune('a' + rng.Intn(26))
				case 2:
					j := rng.Intn(len(q))
					q = append(q[:j], append([]rune{rune('a' + rng.Intn(26))}, q[j:]...)...)
				}
			}
			if len(q) > searchkey.MaxFuzzyRunes {
				q = q[:searchkey.MaxFuzzyRunes]
			}
			queries = append(queries, probe{text: string(q), th: ths[rng.Intn(len(ths))]})
		}
		var compared, withMatches, sensitive int
		for _, qq := range queries {
			p, err := searchkey.Classify(qq.text)
			if err != nil || p.Fuzzy == "" {
				continue
			}
			cq, err := reportsql.CompileSearch(e.seSource(t), reportsql.SearchQuery{Exact: p.Exact, Prefix: p.Prefix, Fuzzy: p.Fuzzy, GroupLimit: 50, Ceiling: 100000, Threshold: qq.th},
				reportsql.SearchScopes{"directory.read": e.scopeNC(e.adA)})
			if err != nil {
				t.Fatal(err)
			}
			var res reportsql.SearchResult
			var oracle []string
			if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
				var err error
				if res, err = reportsql.ExecSearch(ctx, tx, cq); err != nil {
					return err
				}
				restore, err := store.SetTrigramThreshold(ctx, tx, float64(qq.th))
				if err != nil {
					return err
				}
				defer restore()
				rs, err := tx.Query(ctx, `SELECT DISTINCT object_guid::text FROM public.inventory_search_keys WHERE key_kind IN (1, 3) AND $1::text <% key`, p.Fuzzy)
				if err != nil {
					return err
				}
				defer rs.Close()
				for rs.Next() {
					var g string
					if err := rs.Scan(&g); err != nil {
						return err
					}
					oracle = append(oracle, g)
				}
				return rs.Err()
			}); err != nil {
				t.Fatalf("%q at %v: %v", qq.text, qq.th, err)
			}
			if res.Refine || len(oracle) > 40 {
				continue // withheld above the ceiling, or more than a group page shows
			}
			all, fz := map[string]bool{}, map[string]bool{}
			for _, h := range res.Hits {
				all[h.Object] = true
				if h.Class == reportsql.ClassFuzzy {
					fz[h.Object] = true
				}
			}
			or := map[string]bool{}
			for _, g := range oracle {
				or[g] = true
				if !all[g] {
					sort.Strings(oracle)
					t.Errorf("%q at threshold %v: the oracle matches %s and the statement does not return it", qq.text, qq.th, g)
				}
			}
			for g := range fz {
				if !or[g] {
					t.Errorf("%q at threshold %v: %s is a fuzzy hit and does not satisfy <%%", qq.text, qq.th, g)
				}
			}
			if qq.must != "" {
				// The boundary key: the oracle matches it (the float4 rule) and the statement returns it.
				g := e.ownerRun(t, e.a, `SELECT object_guid::text FROM public.inventory_search_keys WHERE key_kind = 1 AND key = $1`, qq.must)
				if len(g) != 1 || !or[g[0]] {
					t.Fatalf("%q at %v: the oracle does not match the boundary key %q (%v): the world is wrong", qq.text, qq.th, qq.must, g)
				}
				if !all[g[0]] || !fz[g[0]] {
					t.Errorf("%q at %v: the boundary key %q (the float4 rule admits it) is not a fuzzy hit: the candidate bound is tighter than pg_trgm's", qq.text, qq.th, qq.must)
				}
				sensitive++
			}
			compared++
			if len(oracle) > 0 {
				withMatches++
			}
		}
		if sensitive == 0 {
			t.Fatal("no float4-sensitive query was compared with its boundary key")
		}
		t.Logf("%d queries compared with the index-free oracle, %d of them with matches", compared, withMatches)
		if compared < 60 || withMatches < 20 {
			t.Fatalf("the generator is degenerate: %d compared, %d with matches", compared, withMatches)
		}
		// 33 runes get no fuzzy class; the bound n of a 32-rune query is real.
		p33, _ := searchkey.Classify(strings.Repeat("ab", 16) + "c")
		if p33.Runes != 33 || p33.Fuzzy != "" {
			t.Errorf("33 runes: fuzzy %q", p33.Fuzzy)
		}
		maxN := 0
		for _, q := range []string{strings.Repeat("a b ", 8), "ab cd ef gh ij kl mn op qr st uv w", strings.Repeat("x", 32), "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", "ä ö ü ß é è ê ë ï î ô ù û ç à â ", "ab,cd,ef,gh,ij,kl,mn,op,qr,st,uv,w"} {
			p, err := searchkey.Classify(q)
			if err != nil || p.Fuzzy == "" {
				continue
			}
			var n int
			fmt.Sscan(e.ownerRun(t, e.a, `SELECT cardinality(public.show_trgm($1))::text`, p.Fuzzy)[0], &n)
			maxN = max(maxN, n)
		}
		t.Logf("largest n of the 32-rune shapes tried: %d (the ADR bound is 48)", maxN)
		if maxN > 48 {
			t.Errorf("n = %d exceeds the ADR bound 48", maxN)
		}
	})
}

var _ = inventory.KindUser
