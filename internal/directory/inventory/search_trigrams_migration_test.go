package inventory_test

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/migrations"
)

func migrationsFS(t *testing.T, keep func(name string) bool) fs.FS {
	t.Helper()
	m := fstest.MapFS{}
	ents, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range ents {
		if !strings.HasSuffix(en.Name(), ".sql") || !keep(en.Name()) {
			continue
		}
		b, err := migrations.FS.ReadFile(en.Name())
		if err != nil {
			t.Fatal(err)
		}
		m[en.Name()] = &fstest.MapFile{Data: b}
	}
	return m
}

// AC1: migration 0070 over a populated database. Two tenants with name, sam and other-kind keys exist before
// the migration; afterwards the postings equal what show_trgm gives over the name and sam keys (non-zero),
// the structure is as the ADR says, and the privileges are the runtime role's.
func Test_migration_0070_builds_the_postings_over_a_populated_database(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		const mig = "0070_inventory_search_trigrams.sql"
		e := setupFS(t, s, migrationsFS(t, func(n string) bool { return n < mig }))
		e.hStructure(t, e.adA)
		if _, err := e.populate(t, e.adA, hBase, sSrchUser(1, "praman", "Priya Raman"), sSrchUser(2, "jdoe", "Jóhn Döe")); err != nil {
			t.Fatal(err)
		}
		// Tenant B has its own keys.
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
		if n := e.count(t, `SELECT count(*) FROM public.inventory_search_keys WHERE key_kind NOT IN (1, 3)`); n == 0 {
			t.Fatal("no other-kind keys before the migration")
		}
		// 0070 as the migration owner (no superuser, no CREATEROLE), with its "-- after:" statement.
		if err := e.d.Apply(context.Background(), migrationsFS(t, func(n string) bool { return n == mig })); err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, tn := range []struct {
			name string
			run  func(sql string) []string
		}{
			{"A", func(sql string) []string { return e.ownerRun(t, e.a, sql) }},
			{"B", func(sql string) []string { return e.ownerRun(t, e.b, sql) }},
		} {
			want := tn.run(`SELECT count(*)::text FROM (SELECT g.trgm FROM public.inventory_search_keys k CROSS JOIN LATERAL unnest(public.show_trgm(k.key)) g(trgm) WHERE k.key_kind IN (1, 3)) d`)
			got := tn.run(`SELECT count(*)::text FROM public.inventory_search_trigrams`)
			if want[0] == "0" || want[0] != got[0] {
				t.Errorf("tenant %s: %s postings, %s expected from show_trgm over the name and sam keys (must be non-zero and equal)", tn.name, got[0], want[0])
			}
			var n int
			fmt.Sscan(got[0], &n)
			total += n
		}
		if m, x, _ := e.trgDiff(t, e.a); m != 0 || x != 0 {
			t.Errorf("tenant A: %d missing, %d extra", m, x)
		}
		if m, x, _ := e.trgDiff(t, e.b); m != 0 || x != 0 {
			t.Errorf("tenant B: %d missing, %d extra", m, x)
		}
		one := func(sql string) string {
			r := e.strings(t, sql)
			if len(r) != 1 {
				t.Fatalf("%s -> %v", sql, r)
			}
			return r[0]
		}
		if v := one(`SELECT attidentity::text FROM pg_attribute WHERE attrelid = 'public.inventory_search_keys'::regclass AND attname = 'key_id'`); v != "a" {
			t.Errorf("key_id identity %q, want a (GENERATED ALWAYS)", v)
		}
		if v := one(`SELECT string_agg(pg_get_constraintdef(oid), ' | ' ORDER BY conname) FROM pg_constraint WHERE conrelid = 'public.inventory_search_keys'::regclass AND contype = 'u'`); v != "UNIQUE (tenant_id, key_id)" {
			t.Errorf("keys unique constraint: %q", v)
		}
		if v := one(`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'public.inventory_search_trigrams'::regclass AND contype = 'p'`); v != "PRIMARY KEY (tenant_id, trgm, key_id)" {
			t.Errorf("postings primary key: %q", v)
		}
		if v := one(`SELECT relrowsecurity::text || relforcerowsecurity::text FROM pg_class WHERE oid = 'public.inventory_search_trigrams'::regclass`); v != "truetrue" {
			t.Errorf("postings RLS enable/force: %q", v)
		}
		if v := one(`SELECT string_agg(pg_get_expr(polqual, polrelid) || ' / ' || pg_get_expr(polwithcheck, polrelid), '|') FROM pg_policy WHERE polrelid = 'public.inventory_search_trigrams'::regclass`); !strings.Contains(v, "app.tenant_id") || !strings.Contains(v, "/") {
			t.Errorf("postings policy: %q", v)
		}
		src, _ := migrations.FS.ReadFile(mig)
		if !strings.Contains(string(src), "-- write-class: inventory_search_trigrams system") {
			t.Error("the migration lacks the write-class annotation")
		}
		if v := one(`SELECT (to_regclass('public.inventory_search_keys_fuzzy') IS NULL)::text`); v != "true" {
			t.Error("the GIN inventory_search_keys_fuzzy still exists")
		}
		// The function: invoker, fixed search_path, schema-qualified show_trgm; exactly three statement triggers.
		if v := one(`SELECT prosecdef::text || ' ' || coalesce(array_to_string(proconfig, ','), '') FROM pg_proc WHERE oid = 'public.inventory_search_trigrams_sync()'::regprocedure`); v != "false search_path=pg_catalog, public" {
			t.Errorf("function security / config: %q", v)
		}
		if v := one(`SELECT prosrc FROM pg_proc WHERE oid = 'public.inventory_search_trigrams_sync()'::regprocedure`); strings.Contains(strings.ReplaceAll(v, "public.show_trgm(", ""), "show_trgm(") {
			t.Error("the function calls show_trgm without a schema")
		}
		trg := e.strings(t, `SELECT (tgtype & 1)::text || ':' || (tgtype & 2)::text || ':' || (tgtype & 28)::text || ':' || (tgattr::text = '')::text || ':' || (tgoldtable IS NOT NULL)::text || ':' || (tgnewtable IS NOT NULL)::text
			FROM pg_trigger WHERE tgrelid = 'public.inventory_search_keys'::regclass AND tgfoid = 'public.inventory_search_trigrams_sync()'::regprocedure ORDER BY tgtype`)
		// statement-level (row bit 0), AFTER (before bit 0), one event each, no column list; INSERT new only, DELETE old only, UPDATE both
		if strings.Join(trg, " ") != "0:0:4:true:false:true 0:0:8:true:true:false 0:0:16:true:true:true" {
			t.Errorf("triggers: %v", trg)
		}
		if v := one(`SELECT count(*)::text FROM pg_trigger WHERE tgrelid = 'public.inventory_search_keys'::regclass AND NOT tgisinternal`); v != "3" {
			t.Errorf("%s triggers on the key table, want exactly 3", v)
		}
		// VACUUM (ANALYZE) of the postings is the migration's own "-- after:" step (the storetest harness ran it), and the
		// planner has the tuple count. relallvisible is not asserted: whether VACUUM can mark a page all-visible depends on
		// sessions this test does not control (an autovacuum worker holds the xmin horizon back under load).
		var vacuumed bool
		for _, stmt := range migrations.After(string(src)) {
			vacuumed = vacuumed || strings.HasPrefix(stmt, "VACUUM (ANALYZE) public.inventory_search_trigrams")
		}
		if !vacuumed {
			t.Errorf("the migration has no -- after: VACUUM (ANALYZE) of the postings: %v", migrations.After(string(src)))
		}
		if v := one(`SELECT (reltuples > 0)::text FROM pg_class WHERE oid = 'public.inventory_search_trigrams'::regclass`); v != "true" {
			t.Errorf("the postings have not been analysed: %s", v)
		}
		// Privileges of the runtime role.
		for _, p := range []struct {
			priv string
			want bool
		}{{"SELECT", true}, {"INSERT", true}, {"DELETE", true}, {"UPDATE", false}, {"TRUNCATE", false}} {
			if v := one(fmt.Sprintf(`SELECT has_table_privilege(current_user, 'public.inventory_search_trigrams', '%s')::text`, p.priv)); v != fmt.Sprint(p.want) {
				t.Errorf("runtime role %s on the postings: %s, want %v", p.priv, v, p.want)
			}
		}
		// Every index of both tables leads with tenant_id.
		for _, ix := range e.strings(t, `SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename IN ('inventory_search_keys', 'inventory_search_trigrams') AND position('(tenant_id,' in indexdef) = 0`) {
			t.Errorf("an index that does not lead with tenant_id: %s", ix)
		}
		t.Logf("%d postings over two tenants", total)
	})
}
