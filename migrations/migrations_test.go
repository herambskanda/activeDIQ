package migrations_test

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/migrations"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

var name = regexp.MustCompile(`^\d{4}_[a-z0-9]+_[a-z0-9_]+\.sql$`)

func TestSequenceStartsAtTenantsAndIsNamedByOwner(t *testing.T) {
	ents, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var sqls []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".sql") {
			sqls = append(sqls, e.Name())
		}
	}
	if len(sqls) == 0 || sqls[0] != "0001_tenant_tenants.sql" {
		t.Fatalf("the sequence must start with 0001_tenant_tenants.sql, got %v", sqls)
	}
	for _, n := range sqls {
		if !name.MatchString(n) {
			t.Errorf("%s is not NNNN_<owner>_<what>.sql", n)
		}
	}
}

// Acceptance 1 (the part a unit test can prove; fitness-tenancy proves the rest): migration 0001
// creates only the tenants table, and leaves the runtime role able to use it and nothing else.
func TestMigration0001CreatesOnlyTenantsAndTheRoleSplit(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		ctx := context.Background()
		c, err := d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)

		rows, err := c.Query(ctx, `SELECT n.nspname || '.' || c.relname || ':' || c.relkind::text
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
			AND c.relkind IN ('r','p','v','m','f','S') ORDER BY 1`)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			got = append(got, s)
		}
		rows.Close()
		if strings.Join(got, ",") != "public.tenants:r" {
			t.Fatalf("migration 0001 created %v; want only public.tenants", got)
		}

		var owner string
		if err := c.QueryRow(ctx, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = 'public.tenants'::regclass`).Scan(&owner); err != nil || owner != storetest.OwnerRole {
			t.Fatalf("tenants owner = %q, %v; want %s", owner, err, storetest.OwnerRole)
		}
		var sel, ins, upd, del, trunc, create, usage bool
		if err := c.QueryRow(ctx, `SELECT
			has_table_privilege($1, 'public.tenants', 'SELECT'), has_table_privilege($1, 'public.tenants', 'INSERT'),
			has_table_privilege($1, 'public.tenants', 'UPDATE'), has_table_privilege($1, 'public.tenants', 'DELETE'),
			has_table_privilege($1, 'public.tenants', 'TRUNCATE'),
			has_schema_privilege($1, 'public', 'CREATE'), has_schema_privilege($1, 'public', 'USAGE')`, storetest.RuntimeRole).
			Scan(&sel, &ins, &upd, &del, &trunc, &create, &usage); err != nil {
			t.Fatal(err)
		}
		if !(sel && ins && upd && del && usage) || trunc || create {
			t.Fatalf("runtime role: select=%v insert=%v update=%v delete=%v usage=%v; truncate=%v create=%v (want DML and usage, no truncate, no create)",
				sel, ins, upd, del, usage, trunc, create)
		}
		// Tables the owner creates later reach the runtime role through the default privileges.
		if err := d.ExecOwner(ctx, `CREATE TABLE public.later (x int)`); err != nil {
			t.Fatal(err)
		}
		var laterTrunc, laterIns bool
		if err := c.QueryRow(ctx, `SELECT has_table_privilege($1, 'public.later', 'TRUNCATE'), has_table_privilege($1, 'public.later', 'INSERT')`, storetest.RuntimeRole).Scan(&laterTrunc, &laterIns); err != nil {
			t.Fatal(err)
		}
		if laterTrunc || !laterIns {
			t.Fatalf("default privileges on a later table: insert=%v truncate=%v; want insert and no truncate", laterIns, laterTrunc)
		}
	})
}

// The guard in the migration fails the run, and rolls it back, instead of creating tables under a broken
// role split: every way the runtime role can reach privilege, including the ones that only work through
// SET ROLE (a membership WITH INHERIT FALSE) or through ownership and CREATE.
func TestMigration0001RefusesABrokenRoleSplit(t *testing.T) {
	for _, b := range storetest.Breaches() {
		t.Run(b.Name, func(t *testing.T) {
			storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
				ctx := context.Background()
				d := s.NewDatabase(t)
				d.Break(t, b)
				err := d.Apply(ctx, migrations.FS)
				if err == nil || !strings.Contains(err.Error(), "ADR-0002 rule 4") || !strings.Contains(err.Error(), b.Want) {
					t.Fatalf("migration under %q = %v; want the guard to fail it mentioning %q", b.Name, err, b.Want)
				}
				admin, err := d.Admin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer admin.Close(ctx)
				var exists bool
				if err := admin.QueryRow(ctx, `SELECT to_regclass('public.tenants') IS NOT NULL`).Scan(&exists); err != nil || exists {
					t.Fatalf("public.tenants exists after a refused migration (%v, %v); the run must roll back", exists, err)
				}
			})
		})
	}
}
