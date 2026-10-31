package migrations_test

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

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

// T-0992: a migration's owner key is the second segment of its name, and it must name the package that
// writes the file's tables (ADR-0003 rule 6). Each table below is created by exactly one file, whose owner
// key is the top-level package that owns it (modules/agentfleet.md §Owned tables; invhost for DM-27).
func TestOwnerKeyMatchesTableOwner(t *testing.T) {
	want := map[string]string{ // table -> owner key
		"agent_policy_key":    "agentpolicy",
		"agent_policy_keyset": "agentpolicy",
		"agent_policy_head":   "agentpolicy",
		"agent_event":         "agentingest",
		"inventory_servers":   "invhost",
	}
	ents, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := migrations.FS.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for table := range want {
			if strings.Contains(string(b), "CREATE TABLE public."+table+" (") {
				if prev, dup := got[table]; dup {
					t.Errorf("%s is created by both %s and %s", table, prev, e.Name())
				}
				got[table] = e.Name()
			}
		}
	}
	for table, owner := range want {
		file, ok := got[table]
		if !ok {
			t.Errorf("no migration creates %s", table)
			continue
		}
		if key := strings.SplitN(file, "_", 3)[1]; key != owner {
			t.Errorf("%s is created by %s: owner key %q, want %q", table, file, key, owner)
		}
	}
}

// Acceptance 1 (the part a unit test can prove; fitness-tenancy proves the rest): migration 0001
// creates only the tenants table, and leaves the runtime role able to use it and nothing else.
func TestMigration0001CreatesOnlyTenantsAndTheRoleSplit(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		ctx := context.Background()
		// Only migration 0001: later migrations add their own tables (0002 is the job queue's).
		first, err := migrations.FS.ReadFile("0001_tenant_tenants.sql")
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Apply(ctx, fstest.MapFS{"0001_tenant_tenants.sql": {Data: first}}); err != nil {
			t.Fatal(err)
		}
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

// A migration number is used once: two files sharing a number leave the apply order to the file
// name alone, and a security migration (row security, authz) could then land in a different order
// on different installs (T-0501).
func TestMigrationNumbersAreUniqueAndContiguous(t *testing.T) {
	ents, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	next := 1
	for _, e := range ents { // ReadDir is sorted by file name
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(e.Name()[:4], "%d", &n); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if n != next {
			t.Errorf("%s: expected number %04d (numbers are unique and have no gap)", e.Name(), next)
		}
		next = n + 1
	}
}

// Upgrade proof for 0051 (T-0562): a database that already holds revoked and expired enrolments, in two
// tenants, upgrades cleanly. The backfill must reach every tenant's rows although the owner is bound by FORCE
// ROW LEVEL SECURITY, and the controls it lifted for that statement must be back afterwards.
func TestMigration0051UpgradeErasesTerminalSeedsInEveryTenant(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		ctx := context.Background()
		before := fstest.MapFS{}
		ents, err := migrations.FS.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".sql") && e.Name() < "0051" {
				b, err := migrations.FS.ReadFile(e.Name())
				if err != nil {
					t.Fatal(err)
				}
				before[e.Name()] = &fstest.MapFile{Data: b}
			}
		}
		if err := d.Apply(ctx, before); err != nil {
			t.Fatal(err)
		}

		tenants := []string{"00000000-0000-4000-8000-0000000000a1", "00000000-0000-4000-8000-0000000000b2"}
		c, err := d.Owner(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		seed := make([]byte, 40)
		for i, tid := range tenants {
			tx, err := c.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			steps := []string{
				`INSERT INTO public.tenants (id, name) VALUES ($1::uuid, 'upgrade')`,
				`SELECT set_config('app.tenant_id', $1, true)`,
			}
			for _, q := range steps {
				if _, err := tx.Exec(ctx, q, tid); err != nil {
					t.Fatal(err)
				}
			}
			acct := fmt.Sprintf("00000000-0000-4000-8000-00000000010%d", i)
			for j, final := range []string{"revoked", "expired", "active"} {
				id := fmt.Sprintf("00000000-0000-4000-8000-00000000%02d%02d", i+1, j+1)
				if _, err := tx.Exec(ctx, `INSERT INTO public.authn_authenticator_enrollments
					(tenant_id, id, account_id, method, sealed_secret, key_version, label, expires_at)
					VALUES ($1::uuid, $2::uuid, $3::uuid, 'totp', $4, 1, 'x', now() + interval '10 minutes')`, tid, id, acct, seed); err != nil {
					t.Fatal(err)
				}
				var q string
				switch final {
				case "revoked":
					q = `UPDATE public.authn_authenticator_enrollments SET state = 'active' WHERE id = $1::uuid`
					if _, err := tx.Exec(ctx, q, id); err != nil {
						t.Fatal(err)
					}
					q = `UPDATE public.authn_authenticator_enrollments SET state = 'revoked' WHERE id = $1::uuid`
				case "expired":
					q = `UPDATE public.authn_authenticator_enrollments SET state = 'expired' WHERE id = $1::uuid`
				default:
					q = `UPDATE public.authn_authenticator_enrollments SET state = 'active' WHERE id = $1::uuid`
				}
				if _, err := tx.Exec(ctx, q, id); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}

		// Apply 0051 on its own, over the seeded database.
		b, err := migrations.FS.ReadFile("0051_authn_enrollment_terminal_no_secret.sql")
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Apply(ctx, fstest.MapFS{"0051_authn_enrollment_terminal_no_secret.sql": {Data: b}}); err != nil {
			t.Fatalf("0051 over a database with terminal rows: %v", err)
		}

		// The admin role bypasses RLS, so it sees every tenant's rows.
		a, err := d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close(ctx)
		for state, wantNull := range map[string]bool{"revoked": true, "expired": true, "active": false} {
			var total, nulls int
			if err := a.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE sealed_secret IS NULL)
				FROM public.authn_authenticator_enrollments WHERE state = $1`, state).Scan(&total, &nulls); err != nil {
				t.Fatal(err)
			}
			if total != 2 || (wantNull && nulls != 2) || (!wantNull && nulls != 0) {
				t.Errorf("state %s: %d rows, %d without a seed; want 2 rows, seed erased=%v", state, total, nulls, wantNull)
			}
		}
		var force, validated bool
		var trig string
		if err := a.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid = 'public.authn_authenticator_enrollments'::regclass`).Scan(&force); err != nil || !force {
			t.Errorf("FORCE ROW LEVEL SECURITY is not back: %v %v", force, err)
		}
		if err := a.QueryRow(ctx, `SELECT tgenabled::text FROM pg_trigger WHERE tgname = 'authn_enrollments_guard' AND tgrelid = 'public.authn_authenticator_enrollments'::regclass`).Scan(&trig); err != nil || trig != "A" {
			t.Errorf("guard trigger tgenabled = %q (%v); want A (ENABLE ALWAYS)", trig, err)
		}
		if err := a.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conname = 'authn_enrollments_terminal_no_secret'`).Scan(&validated); err != nil || !validated {
			t.Errorf("terminal_no_secret CHECK validated = %v (%v)", validated, err)
		}
	})
}

// Upgrade proof for 0021 (T-0580): a database at 0020 holding pending enrolments in two tenants upgrades through
// every later migration. The expiry backfill must reach every tenant's rows although the owner is bound by FORCE
// ROW LEVEL SECURITY, and FORCE must be back afterwards.
func TestMigration0021UpgradeBackfillsPendingExpiryInEveryTenant(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		ctx := context.Background()
		before, after := fstest.MapFS{}, fstest.MapFS{}
		ents, err := migrations.FS.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".sql") {
				continue
			}
			b, err := migrations.FS.ReadFile(e.Name())
			if err != nil {
				t.Fatal(err)
			}
			if e.Name() < "0021" {
				before[e.Name()] = &fstest.MapFile{Data: b}
			} else {
				after[e.Name()] = &fstest.MapFile{Data: b}
			}
		}
		if err := d.Apply(ctx, before); err != nil {
			t.Fatal(err)
		}

		tenants := []string{"00000000-0000-4000-8000-0000000000a1", "00000000-0000-4000-8000-0000000000b2"}
		c, err := d.Owner(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		seed := make([]byte, 40)
		for i, tid := range tenants {
			tx, err := c.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{
				`INSERT INTO public.tenants (id, name) VALUES ($1::uuid, 'upgrade')`,
				`SELECT set_config('app.tenant_id', $1, true)`,
			} {
				if _, err := tx.Exec(ctx, q, tid); err != nil {
					t.Fatal(err)
				}
			}
			id := fmt.Sprintf("00000000-0000-4000-8000-00000000%02d01", i+1)
			acct := fmt.Sprintf("00000000-0000-4000-8000-00000000010%d", i)
			if _, err := tx.Exec(ctx, `INSERT INTO public.authn_authenticator_enrollments
				(tenant_id, id, account_id, method, sealed_secret, key_version, label)
				VALUES ($1::uuid, $2::uuid, $3::uuid, 'totp', $4, 1, 'x')`, tid, id, acct, seed); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}

		if err := d.Apply(ctx, after); err != nil {
			t.Fatalf("migrations from 0021 over a database with pending rows: %v", err)
		}

		a, err := d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close(ctx)
		var total, set int
		if err := a.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE expires_at IS NOT NULL)
			FROM public.authn_authenticator_enrollments WHERE state = 'pending'`).Scan(&total, &set); err != nil {
			t.Fatal(err)
		}
		if total != 2 || set != 2 {
			t.Errorf("pending rows: %d, with expires_at: %d; want 2 and 2", total, set)
		}
		var force bool
		if err := a.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid = 'public.authn_authenticator_enrollments'::regclass`).Scan(&force); err != nil || !force {
			t.Errorf("FORCE ROW LEVEL SECURITY is not back: %v %v", force, err)
		}
	})
}

// T-0881: 0058 admits the ou_one_level root kind, still refuses an unknown kind, keeps the 0037 tenant-root
// rule, and allows ou_one_level only as an include of an OU (never an exclude, never a connection's GUID).
func TestMigration0058AdmitsOULevelRootKind(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		ctx := context.Background()
		a, err := d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close(ctx)
		const (
			tid  = "00000000-0000-4000-8000-0000000000c1"
			rid  = "00000000-0000-4000-8000-0000000000c2"
			aid  = "00000000-0000-4000-8000-0000000000c3"
			acct = "00000000-0000-4000-8000-0000000000c4"
			conn = "00000000-0000-4000-8000-0000000000d1"
			ou   = "00000000-0000-4000-8000-0000000000d2"
		)
		for _, q := range []string{
			`INSERT INTO public.tenants (id, name) VALUES ('` + tid + `', 'one-level')`,
			`INSERT INTO public.authz_roles (tenant_id, id, role_name, tier) VALUES ('` + tid + `', '` + rid + `', 'desk', 2)`,
			`INSERT INTO public.authz_assignments (tenant_id, id, account_id, role_id, granted_by) VALUES ('` + tid + `', '` + aid + `', '` + acct + `', '` + rid + `', 'test')`,
		} {
			if _, err := a.Exec(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		ord := 0
		insert := func(kind string, exclude bool, connection, guid string) error {
			ord++
			_, err := a.Exec(ctx, `INSERT INTO public.authz_assignment_roots (tenant_id, assignment_id, ordinal, is_exclude, root_kind, connection_id, root_guid)
				VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7::uuid)`, tid, aid, ord, exclude, kind, connection, guid)
			return err
		}
		if err := insert("ou_one_level", false, conn, ou); err != nil {
			t.Errorf("ou_one_level include of an OU refused: %v", err)
		}
		if err := insert("ou_subtree", false, conn, ou); err != nil {
			t.Errorf("ou_subtree no longer accepted: %v", err)
		}
		if err := insert("ou_one_level", true, conn, ou); err == nil {
			t.Error("ou_one_level exclude accepted")
		}
		if err := insert("ou_one_level", false, conn, conn); err == nil {
			t.Error("ou_one_level root carrying the connection's GUID accepted")
		}
		if err := insert("ou_children", false, conn, ou); err == nil {
			t.Error("unknown root kind accepted")
		}
		// The 0037 tenant-root rule: root_guid = connection_id = tenant_id and never an exclude.
		if err := insert("tenant", false, tid, tid); err != nil {
			t.Errorf("tenant root refused: %v", err)
		}
		if err := insert("tenant", false, conn, ou); err == nil {
			t.Error("tenant root that is not the tenant's ID accepted")
		}
		if err := insert("tenant", true, tid, tid); err == nil {
			t.Error("tenant exclude accepted")
		}
	})
}
