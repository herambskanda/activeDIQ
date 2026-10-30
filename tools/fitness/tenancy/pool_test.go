package main

// F-POOL-1, 2 and 4 against real PostgreSQL 16 and 18: a good pool schema passes, and every way the
// trust-anchor reader or its function can be widened is reported by rule.

import (
	"strings"
	"testing"
)

const poolRegistry = `{
  "globalTables": [{"table": "public.tenants", "reason": "the tenant directory itself", "owner": "internal/platform/tenant"}],
  "securityDefiner": [{"function": "public.fleet_ca_trust_anchors()", "reason": "the gateway client-CA pool"}],
  "platformPaths": [{"package": "internal/platform/fleet/fleetsql", "function": "TrustAnchors.Load", "reason": "the pool", "withPlatform": true}]
}`

func poolMigrations(t *testing.T, edit func(string) string) map[string]string {
	m := pair(t, "pool/0002_fleet_ca_trust.sql")
	if edit != nil {
		m["0002_app_items.sql"] = edit(m["0002_app_items.sql"])
	}
	return m
}

func TestPoolGoodPasses(t *testing.T) {
	for _, ver := range []string{"16", "18"} {
		t.Run("pg"+ver, func(t *testing.T) {
			vs, out := fixture{migrations: poolMigrations(t, nil), registry: poolRegistry, checks: "T1,T2,T3"}.run(t, ver)
			if len(vs) > 0 {
				t.Fatalf("the good pool schema must pass; got:\n%s\n%s", format(vs), out)
			}
		})
	}
}

// Role-level breaches, applied by the superuser bootstrap on top of the good schema or the bare roles.
func TestPoolRoleBreaches(t *testing.T) {
	cases := []struct {
		name        string
		boot, undo  []string
		rule, named string
	}{
		{"login", []string{`ALTER ROLE activediq_catrust LOGIN`}, []string{`ALTER ROLE activediq_catrust NOLOGIN`}, "pool-role-login", "activediq_catrust"},
		{"bypassrls", []string{`ALTER ROLE activediq_catrust BYPASSRLS`}, []string{`ALTER ROLE activediq_catrust NOBYPASSRLS`}, "pool-role-bypassrls", "activediq_catrust"},
		{"app_member", []string{`GRANT activediq_catrust TO %2$I`}, []string{`REVOKE activediq_catrust FROM %2$I`}, "pool-role-members", "runtime role"},
		{"app_member_noinherit", []string{`GRANT activediq_catrust TO %2$I WITH INHERIT FALSE`}, []string{`REVOKE activediq_catrust FROM %2$I`}, "pool-role-members", "runtime role"},
		{"extra_member", []string{`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='diq_extra') THEN CREATE ROLE diq_extra NOLOGIN; END IF; END $$`, `GRANT activediq_catrust TO diq_extra`},
			[]string{`DROP ROLE diq_extra`}, "pool-role-members", "diq_extra"},
		{"owner_not_member", []string{`REVOKE activediq_catrust FROM %1$I`}, []string{`GRANT activediq_catrust TO %1$I`}, "pool-role-members", "activediq_catrust"},
		{"member_of_other", []string{`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='diq_other') THEN CREATE ROLE diq_other NOLOGIN; END IF; END $$`, `GRANT diq_other TO activediq_catrust`},
			[]string{`DROP ROLE diq_other`}, "pool-role-memberships", "diq_other"},
		{"create_on_public", []string{`GRANT CREATE ON SCHEMA public TO activediq_catrust`}, []string{`REVOKE CREATE ON SCHEMA public FROM activediq_catrust`}, "pool-create-schema", "public"},
	}
	for _, ver := range []string{"16", "18"} {
		for _, c := range cases {
			t.Run("pg"+ver+"/"+c.name, func(t *testing.T) {
				// create_on_public needs the schema to exist at bootstrap time: it does (the database is created first).
				f := fixture{migrations: pair(t, "good/0002_app_items.sql"), checks: "T1,T2,T3", bootstrap: c.boot, reset: c.undo}
				vs, _ := f.run(t, ver)
				want(t, vs, "T3", c.rule, c.named)
			})
		}
	}
}

// Schema-level breaches: the migration itself widens the reader or its function.
func TestPoolSchemaBreaches(t *testing.T) {
	const fn = "public.fleet_ca_trust_anchors()"
	cases := []struct {
		name        string
		edit        func(string) string
		registry    string
		rule, named string
	}{
		{"select_sealed_key", add(`GRANT SELECT (sealed_key) ON public.fleet_ca TO activediq_catrust;`), "", "pool-secret-column", "sealed_key"},
		{"select_key_version", add(`GRANT SELECT (key_version) ON public.fleet_ca TO activediq_catrust;`), "", "pool-secret-column", "key_version"},
		{"select_created_at", add(`GRANT SELECT (created_at) ON public.fleet_ca TO activediq_catrust;`), "", "pool-secret-column", "created_at"},
		{"table_wide_select", add(`GRANT SELECT ON public.fleet_ca TO activediq_catrust;`), "", "pool-secret-column", "sealed_key"},
		{"write_column", add(`GRANT UPDATE (state) ON public.fleet_ca TO activediq_catrust;`), "", "pool-write-privilege", "public.fleet_ca"},
		{"write_table", add(`GRANT INSERT ON public.tenants TO activediq_catrust;`), "", "pool-write-privilege", "public.tenants"},
		{"owns_second_object", rep("REVOKE CREATE ON SCHEMA", "CREATE TABLE public.stray (x int); ALTER TABLE public.stray OWNER TO activediq_catrust;\nREVOKE CREATE ON SCHEMA"), "", "pool-owned-objects", "activediq_catrust"},
		{"not_security_definer", rep("SECURITY DEFINER ", ""), "", "pool-function", "not SECURITY DEFINER"},
		{"search_path_public", rep("pg_catalog, pg_temp AS", "public, pg_temp AS"), "", "pool-function", "proconfig"},
		{"search_path_missing", rep("SET search_path = pg_catalog, pg_temp ", ""), "", "pool-function", "proconfig"},
		{"owned_by_owner", rep("OWNER TO activediq_catrust", "OWNER TO activediq_owner"), "", "pool-function", "owned by activediq_owner"},
		{"execute_public", add(`GRANT EXECUTE ON FUNCTION ` + fn + ` TO PUBLIC;`), "", "pool-function-acl", "PUBLIC"},
		{"execute_default_acl", rep("REVOKE ALL ON FUNCTION public.fleet_ca_trust_anchors() FROM PUBLIC;", ""), "", "pool-function-acl", "PUBLIC"},
		{"execute_other_role", add(`GRANT EXECUTE ON FUNCTION ` + fn + ` TO activediq_owner;`), "", "pool-function-acl", "activediq_owner"},
		{"result_has_key", rep("not_after timestamptz)\nLANGUAGE", "not_after timestamptz, sealed_key bytea)\nLANGUAGE"), "", "pool-function", "returns TABLE"},
		{"callable_in_tenant_context", rep("IF NULLIF(current_setting('app.tenant_id', true), '') IS NOT NULL THEN", "IF false THEN"), "", "pool-tenant-context", "callable inside a tenant context"},
		{"wrong_sqlstate", rep("USING ERRCODE = '42501'", "USING ERRCODE = 'P0001'"), "", "pool-tenant-context", "P0001"},
		{"registry_missing_entry", nil, `{"globalTables": [{"table": "public.tenants", "reason": "x", "owner": "internal/platform/tenant"}], "platformPaths": [{"package": "internal/platform/fleet/fleetsql", "function": "f", "reason": "x", "withPlatform": true}]}`, "pool-registry", "securityDefiner entries"},
		{"registry_no_site", nil, `{"globalTables": [{"table": "public.tenants", "reason": "x", "owner": "internal/platform/tenant"}], "securityDefiner": [{"function": "public.fleet_ca_trust_anchors()", "reason": "x"}]}`, "pool-registry", "withPlatform call sites"},
	}
	for _, ver := range []string{"16", "18"} {
		for _, c := range cases {
			t.Run("pg"+ver+"/"+c.name, func(t *testing.T) {
				reg := c.registry
				if reg == "" {
					reg = poolRegistry
				}
				f := fixture{migrations: poolMigrations(t, c.edit), registry: reg, checks: "T1,T2,T3"}
				vs, _ := f.run(t, ver)
				want(t, vs, "T3", c.rule, c.named)
			})
		}
	}
}

// The reader reaching sealed_key by SET ROLE is the behaviour proof: a table-wide grant is caught both by the
// catalog rule and by the permission probe.
func TestPoolSetRoleProbe(t *testing.T) {
	m := poolMigrations(t, add(`GRANT SELECT ON public.fleet_ca TO activediq_catrust;`))
	vs, _ := fixture{migrations: m, registry: poolRegistry, checks: "T1,T2,T3"}.run(t, "18")
	want(t, vs, "T3", "pool-secret-select", "sealed_key")
}

func add(sql string) func(string) string {
	return func(s string) string { return s + "\n" + sql + "\n" }
}
func rep(old, nw string) func(string) string {
	return func(s string) string {
		if !strings.Contains(s, old) {
			panic("fixture edit does not apply: " + old)
		}
		return strings.Replace(s, old, nw, 1)
	}
}
