package main

// Tests for T1–T4: every rule has a fixture that breaks only that rule and must be reported naming the
// object and the rule (ADR-0002 acceptance 2 and 3, 5 for the database-side registry entries). They run
// against real PostgreSQL containers; without Docker they are skipped locally and fail under CI.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	serverMu sync.Mutex
	servers  = map[string]*Server{}
)

// testServer starts (once per test binary) the PostgreSQL container of the given major version.
func testServer(t *testing.T, version string) *Server {
	t.Helper()
	serverMu.Lock()
	defer serverMu.Unlock()
	if s := servers[version]; s != nil {
		return s
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := dockerAvailable(ctx); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("Docker is required in CI: %v", err)
		}
		t.Skipf("SKIPPED, NOT PROVEN: %v (the fitness-tenancy tests need Docker; CI refuses to skip)", err)
	}
	s, err := StartServer(ctx, version, nil)
	if err != nil {
		t.Fatalf("start PostgreSQL %s: %v", version, err)
	}
	servers[version] = s
	return s
}

func TestMain(m *testing.M) {
	code := m.Run()
	for _, s := range servers {
		s.Stop()
	}
	os.Exit(code)
}

const testRegistry = `{
  "globalTables": [{"table": "public.tenants", "reason": "the tenant directory itself", "owner": "internal/platform/tenant"}]
}`

// fixture describes one run: the migrations, the registry and the checks.
type fixture struct {
	migrations map[string]string // file name -> SQL
	registry   string            // JSON; testRegistry when empty
	checks     string            // default T1,T2,T3,T4
	bootstrap  []string          // extra superuser SQL per database (%1$I owner, %2$I runtime)
	reset      []string          // superuser SQL run after the test to undo role changes (cluster-wide)
}

func readFixture(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// pair is migration 1 (tenants) plus the given file as migration 2.
func pair(t *testing.T, rel string) map[string]string {
	return map[string]string{
		"0001_tenant_tenants.sql": readFixture(t, "base/0001_tenant_tenants.sql"),
		"0002_app_items.sql":      readFixture(t, rel),
	}
}

// dirOf loads every file of testdata/t1/<name>.
func dirOf(t *testing.T, name string) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join("testdata", "t1", name))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, e := range ents {
		m[e.Name()] = readFixture(t, "t1/"+name+"/"+e.Name())
	}
	return m
}

func (f fixture) run(t *testing.T, version string) ([]Violation, string) {
	t.Helper()
	s := testServer(t, version)
	root := t.TempDir()
	if f.migrations != nil {
		dir := filepath.Join(root, "migrations")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for n, sql := range f.migrations {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(sql), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	reg := f.registry
	if reg == "" {
		reg = testRegistry
	}
	if err := os.WriteFile(filepath.Join(root, "registry.json"), []byte(reg), 0o644); err != nil {
		t.Fatal(err)
	}
	checks := map[string]bool{}
	cs := f.checks
	if cs == "" {
		cs = "T1,T2,T3,T4"
	}
	for _, c := range strings.Split(cs, ",") {
		checks[c] = true
	}
	s.extraBoot = f.bootstrap
	t.Cleanup(func() {
		s.extraBoot = nil
		if len(f.reset) == 0 {
			return
		}
		ctx := context.Background()
		c, err := s.connect(ctx, "postgres", s.adminPass, "postgres")
		if err != nil {
			t.Errorf("reset roles: %v", err)
			return
		}
		defer c.Close(ctx)
		for _, r := range f.reset {
			var stmt string
			if err := c.QueryRow(ctx, `SELECT format($1::text, $2::text, $3::text)`, r, s.ownerRole, s.appRole).Scan(&stmt); err != nil {
				t.Errorf("reset roles: %v", err)
				continue
			}
			if _, err := c.Exec(ctx, stmt); err != nil {
				t.Errorf("reset roles %q: %v", r, err)
			}
		}
	})
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	vs, err := Run(ctx, Options{
		Root: root, MigrationsDir: "migrations", RegistryPath: "registry.json",
		Versions: []string{version}, Checks: checks, Out: &out,
		Servers: map[string]*Server{version: s},
	})
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out.String())
	}
	return vs, out.String()
}

func format(vs []Violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString("  " + v.String() + "\n")
	}
	return b.String()
}

// want requires a violation of check/rule whose Where or message names `named`.
func want(t *testing.T, vs []Violation, check, rule, named string) {
	t.Helper()
	for _, v := range vs {
		if v.Check == check && v.Rule == rule && (strings.Contains(v.Where, named) || strings.Contains(v.Msg, named)) {
			return
		}
	}
	t.Errorf("no %s [%s] violation naming %q; got:\n%s", check, rule, named, format(vs))
}

func TestGoodSchemaPasses(t *testing.T) {
	for _, ver := range []string{"18", "16"} {
		t.Run("pg"+ver, func(t *testing.T) {
			vs, out := fixture{migrations: pair(t, "good/0002_app_items.sql")}.run(t, ver)
			if len(vs) > 0 {
				t.Fatalf("the good schema must pass; got:\n%s", format(vs))
			}
			for _, line := range []string{"T1 migration 1 creates tenants", "T2 catalog", "T3 roles", "T4 isolation probes"} {
				if !strings.Contains(out, line) {
					t.Errorf("output lacks %q:\n%s", line, out)
				}
			}
			t.Log("\n" + out)
		})
	}
}

func TestEmptySchemaPasses(t *testing.T) {
	vs, out := fixture{registry: "{}"}.run(t, "18")
	if len(vs) > 0 {
		t.Fatalf("an empty schema must pass; got:\n%s", format(vs))
	}
	if !strings.Contains(out, "no migration yet") {
		t.Errorf("output must say T1 activates with the first migration:\n%s", out)
	}
}

// TestBadFixtures: acceptance 2 — one failing fixture per rule, naming the object and the rule.
func TestBadFixtures(t *testing.T) {
	type exp struct{ check, rule, named string }
	cases := []struct {
		file string
		want []exp
	}{
		{"missing_force", []exp{{"T2", "rls-force", "public.items"}}},
		{"missing_rls", []exp{{"T2", "rls-enable", "public.items"}}},
		{"missing_tenant_id", []exp{{"T2", "tenant-id", "public.items"}}},
		{"tenant_id_not_leading_pk", []exp{{"T2", "key-leading-tenant-id", "public.items"}}},
		{"tenant_id_nullable", []exp{{"T2", "tenant-id", "public.items"}}},
		{"no_tenant_fk", []exp{{"T2", "tenant-fk", "public.items"}}},
		{"unique_index_global", []exp{{"T2", "key-leading-tenant-id", "public.items"}, {"T4", "unique-global", "public.items"}}},
		{"unique_index_partial_expression", []exp{{"T2", "key-leading-tenant-id", "public.items"}, {"T4", "unique-global", "public.items"}}},
		{"exclusion_not_leading", []exp{{"T2", "key-leading-tenant-id", "public.items"}}},
		{"fk_not_paired", []exp{{"T2", "fk-pairs-tenant-id", "public.item_notes"}, {"T4", "unique-global", "public.items"}}}, // the global key on items stops T4 seeding, so the FK probe cannot run,
		{"view_no_security_invoker", []exp{{"T2", "view-security-invoker", "public.item_names"}}},
		{"materialized_view", []exp{{"T2", "matview-over-tenant-table", "public."}}},
		{"security_definer_function", []exp{{"T2", "security-definer", "all_item_names"}}},
		{"policy_true", []exp{{"T2", "policy-shape", "public.items"}, {"T4", "read-cross-tenant", "public.items"}}},
		{"policy_no_check", []exp{{"T2", "policy-missing", "public.items"}}}, // USING alone also guards writes in PostgreSQL; the shape is still required
		{"policy_check_true", []exp{{"T2", "policy-shape", "public.items"}, {"T4", "write-cross-tenant", "public.items"}}},
		{"policy_coalesce", []exp{{"T2", "policy-shape", "public.items"}}},
		{"policy_extra_permissive", []exp{{"T2", "policy-shape", "public.items"}}},
		{"partition_without_rls", []exp{{"T2", "rls-enable", "public.events_2026"}}},
		{"truncate_granted", []exp{{"T3", "runtime-truncate", "public.items"}}},
		{"create_on_schema", []exp{{"T3", "runtime-create-schema", "public"}}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			vs, _ := fixture{migrations: pair(t, "bad/"+c.file+".sql")}.run(t, "18")
			if len(vs) == 0 {
				t.Fatal("expected the fixture to fail, got no violation")
			}
			for _, e := range c.want {
				want(t, vs, e.check, e.rule, e.named)
			}
		})
	}
}

// The runtime role owning a table needs the owner role to be allowed to hand it over.
func TestRuntimeOwnsTable(t *testing.T) {
	f := fixture{
		migrations: pair(t, "bad/runtime_owns_table.sql"),
		bootstrap:  []string{`GRANT %2$I TO %1$I`, `GRANT CREATE ON SCHEMA public TO %2$I`},
		reset:      []string{`REVOKE %2$I FROM %1$I`},
	}
	vs, _ := f.run(t, "18")
	want(t, vs, "T3", "runtime-owns-object", "public.items")
}

// T3 role attributes, injected through the bootstrap (the role changes are cluster-wide, so undone after).
func TestRoleAttributes(t *testing.T) {
	cases := []struct {
		name, boot, undo, rule, named string
	}{
		{"runtime_bypassrls", `ALTER ROLE %2$I BYPASSRLS`, `ALTER ROLE %2$I NOBYPASSRLS`, "role-bypassrls", "activediq_app"},
		{"owner_superuser", `ALTER ROLE %1$I SUPERUSER`, `ALTER ROLE %1$I NOSUPERUSER`, "role-superuser", "activediq_owner"},
		{"owner_bypassrls", `ALTER ROLE %1$I BYPASSRLS`, `ALTER ROLE %1$I NOBYPASSRLS`, "role-bypassrls", "activediq_owner"},
		{"runtime_superuser", `ALTER ROLE %2$I SUPERUSER`, `ALTER ROLE %2$I NOSUPERUSER`, "role-superuser", "activediq_app"},
		{"runtime_member_of_owner", `GRANT %1$I TO %2$I`, `REVOKE %1$I FROM %2$I`, "role-membership", "activediq_app"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := fixture{migrations: pair(t, "good/0002_app_items.sql"), checks: "T1,T2,T3", bootstrap: []string{c.boot}, reset: []string{c.undo}}
			vs, _ := f.run(t, "18")
			want(t, vs, "T3", c.rule, c.named)
		})
	}
}

// A membership that cannot inherit still lets the runtime role SET ROLE (T-0186): T3 must treat any
// membership, whatever its INHERIT or SET option, as a breach. WITH INHERIT FALSE needs PostgreSQL 16.
func TestRoleMembershipWithoutInherit(t *testing.T) {
	cases := []struct {
		name  string
		boot  []string
		undo  []string
		named string
	}{
		{"owner_role", []string{`GRANT %1$I TO %2$I WITH INHERIT FALSE`}, []string{`REVOKE %1$I FROM %2$I`}, "activediq_owner"},
		{"superuser_role",
			[]string{`DO $$ BEGIN CREATE ROLE t3_super SUPERUSER NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$`, `GRANT t3_super TO %2$I WITH INHERIT FALSE`},
			[]string{`DROP ROLE t3_super`}, "t3_super"},
		{"bypassrls_role",
			[]string{`DO $$ BEGIN CREATE ROLE t3_bypass BYPASSRLS NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$`, `GRANT t3_bypass TO %2$I WITH INHERIT FALSE`},
			[]string{`DROP ROLE t3_bypass`}, "t3_bypass"},
		{"indirect_superuser_role", // app -> t3_mid (no inherit) -> t3_top (superuser)
			[]string{`DO $$ BEGIN CREATE ROLE t3_top SUPERUSER NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$`, `DO $$ BEGIN CREATE ROLE t3_mid NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$`, `GRANT t3_top TO t3_mid`, `GRANT t3_mid TO %2$I WITH INHERIT FALSE`},
			[]string{`DROP ROLE t3_mid`, `DROP ROLE t3_top`}, "t3_top"},
		{"object_owning_role",
			[]string{`DO $$ BEGIN CREATE ROLE t3_owns NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$`, `CREATE TYPE public.t3_owned AS ENUM ('a')`, `ALTER TYPE public.t3_owned OWNER TO t3_owns`, `GRANT t3_owns TO %2$I WITH INHERIT FALSE`},
			[]string{`DROP ROLE t3_owns`}, "t3_owns"},
		{"database_owner_role", // ownership of the database sits in pg_shdepend with dbid 0
			[]string{`DO $$ BEGIN CREATE ROLE t3_dbo NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$`, `DO $$ BEGIN EXECUTE format('ALTER DATABASE %%I OWNER TO t3_dbo', current_database()); END $$`, `GRANT t3_dbo TO %2$I WITH INHERIT FALSE`},
			[]string{`DROP OWNED BY t3_dbo`, `DROP ROLE t3_dbo`}, "t3_dbo"},
		{"predefined_program", []string{`GRANT pg_execute_server_program TO %2$I WITH INHERIT FALSE`}, []string{`REVOKE pg_execute_server_program FROM %2$I`}, "pg_execute_server_program"},
		{"predefined_read_files", []string{`GRANT pg_read_server_files TO %2$I`}, []string{`REVOKE pg_read_server_files FROM %2$I`}, "pg_read_server_files"},
		{"predefined_write_files", []string{`GRANT pg_write_server_files TO %2$I`}, []string{`REVOKE pg_write_server_files FROM %2$I`}, "pg_write_server_files"},
	}
	for _, ver := range []string{"16", "18"} {
		for _, c := range cases {
			t.Run("pg"+ver+"/"+c.name, func(t *testing.T) {
				f := fixture{migrations: pair(t, "good/0002_app_items.sql"), checks: "T1,T3", bootstrap: c.boot, reset: c.undo}
				vs, _ := f.run(t, ver)
				want(t, vs, "T3", "role-membership", c.named)
			})
		}
	}
}

// TEMPORARY on the product database, granted directly or through a role the runtime role is a member of
// without INHERIT, is a breach (the bootstrap withholds it from PUBLIC).
func TestRuntimeTemporary(t *testing.T) {
	cases := []struct {
		name  string
		boot  []string
		undo  []string
		named string
	}{
		{"direct", []string{`DO $$ BEGIN EXECUTE format('GRANT TEMPORARY ON DATABASE %%I TO %%I', current_database(), %2$L); END $$`}, nil, "fit_"},
		{"via_non_inherited_role", []string{
			`DO $$ BEGIN CREATE ROLE t3_tmp NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$`,
			`DO $$ BEGIN EXECUTE format('GRANT TEMPORARY ON DATABASE %%I TO t3_tmp', current_database()); END $$`,
			`GRANT t3_tmp TO %2$I WITH INHERIT FALSE`}, []string{`DROP ROLE t3_tmp`}, "t3_tmp"},
	}
	for _, ver := range []string{"16", "18"} {
		for _, c := range cases {
			t.Run("pg"+ver+"/"+c.name, func(t *testing.T) {
				f := fixture{migrations: pair(t, "good/0002_app_items.sql"), checks: "T1,T3", bootstrap: c.boot, reset: c.undo}
				vs, _ := f.run(t, ver)
				want(t, vs, "T3", "runtime-temporary", c.named)
			})
		}
	}
}

// TRUNCATE on a tenant table and CREATE on a product schema, held by a role the runtime role is a member
// of WITH INHERIT FALSE: has_*_privilege(app, ...) is false, yet SET ROLE reaches them (T-0186).
func TestPrivilegeViaNonInheritedRole(t *testing.T) {
	mk := `DO $$ BEGIN CREATE ROLE t3_helper NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$`
	cases := []struct {
		name, rule, named string
		boot              []string
	}{
		{"truncate", "runtime-truncate", "public.items", []string{mk,
			`ALTER DEFAULT PRIVILEGES FOR ROLE %1$I IN SCHEMA public GRANT TRUNCATE ON TABLES TO t3_helper`}},
		{"create_schema", "runtime-create-schema", "t3_helper", []string{mk, `GRANT CREATE ON SCHEMA public TO t3_helper`}},
	}
	for _, ver := range []string{"16", "18"} {
		for _, c := range cases {
			t.Run("pg"+ver+"/"+c.name, func(t *testing.T) {
				f := fixture{
					migrations: pair(t, "good/0002_app_items.sql"), checks: "T1,T2,T3",
					bootstrap: append(c.boot, `GRANT t3_helper TO %2$I WITH INHERIT FALSE`),
					reset:     []string{`DROP OWNED BY t3_helper`, `DROP ROLE t3_helper`},
				}
				vs, _ := f.run(t, ver)
				want(t, vs, "T3", c.rule, c.named)
			})
		}
	}
}

// TestT1 covers the migration-1 rules.
func TestT1(t *testing.T) {
	cases := []struct{ dir, rule string }{
		{"table_before_tenants", "tenants-first"},
		{"no_tenants", "migration-1"},
		{"missing_parent_column", "tenants-columns"},
		{"bad_file_name", "migration-name"},
		{"starts_at_two", "migration-1"},
		{"does_not_apply", "migrations-apply"},
	}
	for _, c := range cases {
		t.Run(c.dir, func(t *testing.T) {
			vs, _ := fixture{migrations: dirOf(t, c.dir), checks: "T1,T2,T3"}.run(t, "18")
			found := false
			for _, v := range vs {
				if v.Check == "T1" && v.Rule == c.rule {
					found = true
				}
			}
			if !found {
				t.Errorf("no T1 [%s] violation; got:\n%s", c.rule, format(vs))
			}
		})
	}
}

// TestRegistry covers the database-side registry rules (acceptance 5).
func TestRegistry(t *testing.T) {
	good := pair(t, "good/0002_app_items.sql")
	t.Run("reasonless_global_table", func(t *testing.T) {
		reg := `{"globalTables": [{"table": "public.tenants", "reason": " ", "owner": "internal/platform/tenant"}]}`
		vs, _ := fixture{migrations: good, registry: reg}.run(t, "18")
		want(t, vs, "T2", "registry", "public.tenants")
	})
	t.Run("global_table_without_owner", func(t *testing.T) {
		reg := `{"globalTables": [{"table": "public.tenants", "reason": "the directory"}]}`
		vs, _ := fixture{migrations: good, registry: reg}.run(t, "18")
		want(t, vs, "T2", "registry", "public.tenants")
	})
	t.Run("stale_global_table", func(t *testing.T) {
		reg := `{"globalTables": [
		  {"table": "public.tenants", "reason": "the directory", "owner": "internal/platform/tenant"},
		  {"table": "public.gone", "reason": "was here", "owner": "internal/platform/gone"}]}`
		vs, _ := fixture{migrations: good, registry: reg}.run(t, "18")
		want(t, vs, "T2", "registry-stale", "public.gone")
	})
	t.Run("stale_security_definer", func(t *testing.T) {
		reg := `{"globalTables": [{"table": "public.tenants", "reason": "the directory", "owner": "internal/platform/tenant"}],
		  "securityDefiner": [{"function": "public.nothing(uuid)", "reason": "was here"}]}`
		vs, _ := fixture{migrations: good, registry: reg}.run(t, "18")
		want(t, vs, "T2", "registry-stale", "public.nothing(uuid)")
	})
	t.Run("non_definer_function_entry_is_stale", func(t *testing.T) {
		mig := map[string]string{
			"0001_tenant_tenants.sql": good["0001_tenant_tenants.sql"],
			"0002_app_items.sql":      good["0002_app_items.sql"] + "\nCREATE FUNCTION plain_fn() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;\n",
		}
		reg := `{"globalTables": [{"table": "public.tenants", "reason": "the directory", "owner": "internal/platform/tenant"}],
		  "securityDefiner": [{"function": "public.plain_fn()", "reason": "claims to be definer"}]}`
		vs, _ := fixture{migrations: mig, registry: reg}.run(t, "18")
		want(t, vs, "T2", "registry-stale", "public.plain_fn()")
	})
	t.Run("reasonless_security_definer", func(t *testing.T) {
		reg := `{"globalTables": [{"table": "public.tenants", "reason": "the directory", "owner": "internal/platform/tenant"}],
		  "securityDefiner": [{"function": "public.all_item_names()", "reason": ""}]}`
		vs, _ := fixture{migrations: pair(t, "bad/security_definer_function.sql"), registry: reg}.run(t, "18")
		want(t, vs, "T2", "registry", "public.all_item_names()")
	})
	t.Run("registered_security_definer_passes", func(t *testing.T) {
		reg := `{"globalTables": [{"table": "public.tenants", "reason": "the directory", "owner": "internal/platform/tenant"}],
		  "securityDefiner": [{"function": "public.all_item_names()", "reason": "the fixture needs one"}]}`
		vs, _ := fixture{migrations: pair(t, "bad/security_definer_function.sql"), registry: reg}.run(t, "18")
		if len(vs) > 0 {
			t.Fatalf("a registered SECURITY DEFINER function must pass; got:\n%s", format(vs))
		}
	})
	t.Run("registered_global_with_fk_to_tenant_table", func(t *testing.T) {
		mig := map[string]string{
			"0001_tenant_tenants.sql": good["0001_tenant_tenants.sql"],
			"0002_app_items.sql": good["0002_app_items.sql"] + `
CREATE TABLE catalog_entries (id uuid PRIMARY KEY, owner_tenant uuid NOT NULL, item_id uuid NOT NULL,
  FOREIGN KEY (owner_tenant, item_id) REFERENCES items (tenant_id, id));
`,
		}
		reg := `{"globalTables": [
		  {"table": "public.tenants", "reason": "the directory", "owner": "internal/platform/tenant"},
		  {"table": "public.catalog_entries", "reason": "shared catalogue", "owner": "internal/platform/catalog"}]}`
		vs, _ := fixture{migrations: mig, registry: reg, checks: "T1,T2"}.run(t, "18")
		want(t, vs, "T2", "global-references-tenant", "public.catalog_entries")
	})
}

// TestSessionLeakProbe proves the SQL-14 probe fires when the tenant is set for the session.
func TestSessionLeakProbe(t *testing.T) {
	leakIsLocal = false
	t.Cleanup(func() { leakIsLocal = true })
	vs, _ := fixture{migrations: pair(t, "good/0002_app_items.sql"), checks: "T1,T2,T4"}.run(t, "18")
	want(t, vs, "T4", "session-leak", "app.tenant_id")
}
