package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
	"github.com/skenzeriq/activediq/tools/fitness/tenancy/registry"
)

// The gateway client-CA pool reads every tenant's CA certificates through one SECURITY DEFINER function
// owned by a dedicated, column-limited role (fleet-contract.md "Gateway client-CA pool", T-0712). The
// database, not code review, keeps sealed_key out of its reach; these are the catalog fitness functions
// F-POOL-1 (registry), F-POOL-2 (catalog) and F-POOL-4 (behaviour) that prove it, run on every PostgreSQL
// major the job covers.
const (
	poolFunction = "fleet_ca_trust_anchors"
	poolRegName  = "public." + poolFunction + "()"
	poolTable    = "public.fleet_ca"
	// poolResult is the function's result as pg_get_function_result prints it: the four public columns.
	poolResult = "TABLE(tenant_id uuid, spki_sha256 bytea, cert_der bytea, not_after timestamp with time zone)"
	// poolSearchPath is the proconfig entry, spaces removed.
	poolSearchPath = "search_path=pg_catalog,pg_temp"
)

// secretColumns are the fleet_ca columns the reader must never touch.
var secretColumns = []string{"sealed_key", "key_version", "created_at"}

// checkPool runs F-POOL-1, 2 and 4. The role checks apply from the first migration (the installer creates
// the role before migrating); the function checks activate when fleet_ca_trust_anchors() exists, and from
// then on the role must own exactly that one object.
func checkPool(ctx context.Context, d *Database, reg *registry.Registry) ([]Violation, error) {
	var vs []Violation
	add := func(rule, where, msg string) { vs = append(vs, Violation{"T3", rule, where, msg}) }
	role := d.Server().CatrustRole()
	app, owner := d.Server().AppRole(), d.Server().OwnerRole()
	c, err := catalogConn(ctx, d)
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)

	var oid uint32
	var login, super, bypass, repl, createRole, createDB bool
	err = c.QueryRow(ctx, `SELECT oid, rolcanlogin, rolsuper, rolbypassrls, rolreplication, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = $1`, role).
		Scan(&oid, &login, &super, &bypass, &repl, &createRole, &createDB)
	if errors.Is(err, pgx.ErrNoRows) {
		add("pool-role-missing", role, "the trust-anchor reader role does not exist: the installer must create it (NOLOGIN) before the first migration")
		return vs, nil
	}
	if err != nil {
		return nil, err
	}
	for _, a := range []struct {
		on   bool
		rule string
		what string
	}{
		{login, "pool-role-login", "can LOG IN"},
		{super, "pool-role-superuser", "is a SUPERUSER"},
		{bypass, "pool-role-bypassrls", "has BYPASSRLS"},
		{repl, "pool-role-replication", "has REPLICATION"},
		{createRole, "pool-role-createrole", "has CREATEROLE"},
		{createDB, "pool-role-createdb", "has CREATEDB"},
	} {
		if a.on {
			add(a.rule, role, "the trust-anchor reader "+a.what+" (it must be NOLOGIN NOSUPERUSER NOBYPASSRLS and nothing more)")
		}
	}

	// Memberships must equal the installer spec: its members are exactly pgharness.CatrustMemberships, and it
	// is a member of nothing. pg_has_role 'MEMBER' catches indirect membership; the runtime role never is.
	rows, err := c.Query(ctx, `SELECT m.rolname FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member WHERE am.roleid = $1 ORDER BY 1`, oid)
	if err != nil {
		return nil, err
	}
	var members []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		members = append(members, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	want := slices.Clone(pgharness.CatrustMemberships)
	slices.Sort(want)
	if !slices.Equal(members, want) {
		add("pool-role-members", role, fmt.Sprintf("members are %v, the installer spec is %v", members, want))
	}
	var appMember bool
	if err := c.QueryRow(ctx, `SELECT pg_has_role($1::name, $2::oid, 'MEMBER')`, app, oid).Scan(&appMember); err != nil {
		return nil, err
	}
	if appMember {
		add("pool-role-members", role, "the runtime role "+app+" is a member of it, directly or indirectly: it may only EXECUTE the function")
	}
	rows, err = c.Query(ctx, `SELECT g.rolname FROM pg_auth_members am JOIN pg_roles g ON g.oid = am.roleid WHERE am.member = $1 ORDER BY 1`, oid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		add("pool-role-memberships", role, "is a member of role "+n+": the installer spec gives it no memberships")
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// CREATE on any schema, directly or through PUBLIC (the migration grants it for the ownership hand-over
	// and revokes it again in the same migration).
	rows, err = c.Query(ctx, `SELECT n.nspname FROM pg_namespace n WHERE `+productSchema+` AND has_schema_privilege($1::oid, n.oid, 'CREATE') ORDER BY 1`, oid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return nil, err
		}
		add("pool-create-schema", s, "the trust-anchor reader holds CREATE on schema "+s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Write privileges on any relation, at table or column level (INSERT/UPDATE/REFERENCES per column).
	rows, err = c.Query(ctx, `SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE `+productSchema+` AND c.relkind IN ('r','p','v','m','f')
		AND (has_table_privilege($1::oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
			OR has_any_column_privilege($1::oid, c.oid, 'INSERT, UPDATE, REFERENCES')) ORDER BY 1`, oid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return nil, err
		}
		add("pool-write-privilege", t, "the trust-anchor reader holds a write privilege on "+t+" (it is a read-only role)")
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Any privilege on the secret columns of fleet_ca, from a column grant or a table grant.
	rows, err = c.Query(ctx, `SELECT a.attname FROM pg_attribute a WHERE a.attrelid = to_regclass($1) AND a.attnum > 0 AND NOT a.attisdropped
		AND a.attname = ANY($2::name[]) AND has_column_privilege($3::oid, a.attrelid, a.attnum, 'SELECT, INSERT, UPDATE, REFERENCES') ORDER BY 1`,
		poolTable, secretColumns, oid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			rows.Close()
			return nil, err
		}
		add("pool-secret-column", poolTable+"."+col, "the trust-anchor reader holds a privilege on "+poolTable+"."+col+": the key material must be unreachable by privilege")
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Objects owned: none before the function exists, exactly the function after.
	var fn struct {
		oid       uint32
		sig       string
		secdef    bool
		owner     string
		config    []string
		result    string
		leaks     []string
		found     bool
		overloads int
	}
	if err := c.QueryRow(ctx, `SELECT count(*) FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname = $1`, poolFunction).Scan(&fn.overloads); err != nil {
		return nil, err
	}
	fn.found = fn.overloads > 0
	owned := []string{}
	rows, err = c.Query(ctx, `SELECT CASE WHEN s.classid = 'pg_database'::regclass THEN 'database ' || current_database()
			ELSE pg_describe_object(s.classid, s.objid, s.objsubid) END
		FROM pg_shdepend s WHERE s.refclassid = 'pg_authid'::regclass AND s.refobjid = $1 AND s.deptype = 'o' AND `+ownedHere+` ORDER BY 1`, oid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var o string
		if err := rows.Scan(&o); err != nil {
			rows.Close()
			return nil, err
		}
		owned = append(owned, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	wantOwned := 0
	if fn.found {
		wantOwned = 1
	}
	if len(owned) != wantOwned || (fn.found && !strings.HasPrefix(owned[0], "function public."+poolFunction+"(")) {
		add("pool-owned-objects", role, fmt.Sprintf("owns %d object(s) %v; it must own exactly the function %s() once that exists, and nothing before", len(owned), owned, poolFunction))
	}

	if !fn.found {
		// Registry entries for a function that does not exist are the existing registry-stale rule.
		return vs, nil
	}

	// F-POOL-1: exactly one registry entry, and exactly one WithPlatform call site naming it.
	nDef := 0
	for _, s := range reg.SecurityDefiner {
		if s.Function == poolRegName {
			nDef++
		}
	}
	if nDef != 1 {
		add("pool-registry", poolRegName, fmt.Sprintf("the registry has %d securityDefiner entries for %s, it must have exactly one", nDef, poolRegName))
	}
	nSite := 0
	for _, p := range reg.PlatformPaths {
		if p.Package == poolSQLDir && p.WithPlatform {
			nSite++
		}
	}
	if nSite != 1 {
		add("pool-registry", poolSQLDir, fmt.Sprintf("the registry has %d withPlatform call sites in %s, it must have exactly one (the function's only caller)", nSite, poolSQLDir))
	}

	// F-POOL-2/4: pg_proc.
	if fn.overloads != 1 {
		add("pool-function", poolFunction, fmt.Sprintf("%d overloads of %s exist, exactly one is allowed", fn.overloads, poolFunction))
	}
	rows, err = c.Query(ctx, `SELECT p.oid, p.oid::regprocedure::text, p.prosecdef, pg_get_userbyid(p.proowner),
			COALESCE(array(SELECT replace(x, ' ', '') FROM unnest(p.proconfig) x), '{}'), pg_get_function_result(p.oid),
			COALESCE(array(SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END
				FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
				WHERE a.privilege_type = 'EXECUTE' AND (a.grantee = 0 OR pg_get_userbyid(a.grantee) <> ALL($2::text[]))), '{}')
		FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname = $1 ORDER BY 1`, poolFunction, []string{app, role})
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		if err := rows.Scan(&fn.oid, &fn.sig, &fn.secdef, &fn.owner, &fn.config, &fn.result, &fn.leaks); err != nil {
			rows.Close()
			return nil, err
		}
		if !fn.secdef {
			add("pool-function", fn.sig, "is not SECURITY DEFINER (prosecdef false)")
		}
		if !slices.Equal(fn.config, []string{poolSearchPath}) {
			add("pool-function", fn.sig, fmt.Sprintf("proconfig is %v, it must be exactly {%s}", fn.config, poolSearchPath))
		}
		if fn.owner != role {
			add("pool-function", fn.sig, "is owned by "+fn.owner+", it must be owned by "+role)
		}
		if fn.result != poolResult {
			add("pool-function", fn.sig, "returns "+fn.result+", it must return "+poolResult+" (the four public columns, no key column)")
		}
		for _, g := range fn.leaks {
			add("pool-function-acl", fn.sig, "EXECUTE is granted to "+g+": only "+app+" and the owner may call it")
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var appExec bool
	if err := c.QueryRow(ctx, `SELECT has_function_privilege($1::name, 'public.fleet_ca_trust_anchors()'::regprocedure, 'EXECUTE')`, app).Scan(&appExec); err == nil && !appExec {
		add("pool-function-acl", poolRegName, "the runtime role "+app+" cannot EXECUTE it: the gateway could not load the pool")
	}

	// F-POOL-4, behaviour. Tenant context: refused with 42501. Platform context: works.
	bv, err := poolBehaviour(ctx, d, owner, role, app)
	if err != nil {
		return nil, err
	}
	for _, b := range bv {
		add(b[0], b[1], b[2])
	}
	return vs, nil
}

// poolSQLDir is the one package allowed to name the function in SQL and to call it under WithPlatform.
const poolSQLDir = "internal/platform/fleet/fleetsql"

// poolBehaviour runs the probes of F-POOL-4 and returns (rule, where, message) triples.
func poolBehaviour(ctx context.Context, d *Database, owner, role, app string) ([][3]string, error) {
	var out [][3]string
	// As the runtime role: inside a tenant context the function must fail 42501; in a platform context it must run.
	ac, err := d.App(ctx)
	if err != nil {
		return nil, err
	}
	defer ac.Close(ctx)
	probe := func(tenant string) (*pgconn.PgError, error) {
		tx, err := ac.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			return nil, err
		}
		rows, err := tx.Query(ctx, `SELECT * FROM public.fleet_ca_trust_anchors()`)
		if err == nil {
			for rows.Next() {
			}
			err = rows.Err()
			rows.Close()
		}
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			return pe, nil
		}
		return nil, err
	}
	pe, err := probe("00000000-0000-4000-8000-0000000000a1")
	switch {
	case err != nil:
		return nil, err
	case pe == nil:
		out = append(out, [3]string{"pool-tenant-context", poolRegName, "callable inside a tenant context: it must raise 42501 so that only a platform-scope transaction can read every tenant's CAs"})
	case pe.Code != "42501":
		out = append(out, [3]string{"pool-tenant-context", poolRegName, "inside a tenant context it failed with " + pe.Code + " (" + pe.Message + "), it must fail with 42501"})
	}
	pe, err = probe("")
	if err != nil {
		return nil, err
	}
	if pe != nil {
		out = append(out, [3]string{"pool-platform-context", poolRegName, "fails in a platform context with " + pe.Code + " (" + pe.Message + "): the gateway could not load the pool"})
	}

	// As the trust-anchor reader (SET ROLE from the owner, a member): the key column is a permission error.
	oc, err := d.Owner(ctx)
	if err != nil {
		return nil, err
	}
	defer oc.Close(ctx)
	var hasKey bool
	if err := oc.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass($1) AND attname = 'sealed_key' AND NOT attisdropped)`, poolTable).Scan(&hasKey); err != nil {
		return nil, err
	}
	if !hasKey {
		return out, nil
	}
	setRole := func(q string) (*pgconn.PgError, error) {
		tx, err := oc.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var stmt string
		if err := tx.QueryRow(ctx, `SELECT format('SET LOCAL ROLE %I', $1::text)`, role).Scan(&stmt); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return nil, fmt.Errorf("SET ROLE %s as %s: %w", role, owner, err)
		}
		rows, err := tx.Query(ctx, q)
		if err == nil {
			for rows.Next() {
			}
			err = rows.Err()
			rows.Close()
		}
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			return pe, nil
		}
		return nil, err
	}
	pe, err = setRole(`SELECT sealed_key FROM public.fleet_ca`)
	switch {
	case err != nil:
		return nil, err
	case pe == nil:
		out = append(out, [3]string{"pool-secret-select", poolTable + ".sealed_key", "SET ROLE " + role + " then SELECT sealed_key FROM fleet_ca succeeded: it must fail with permission denied (42501), not return rows"})
	case pe.Code != "42501":
		out = append(out, [3]string{"pool-secret-select", poolTable + ".sealed_key", "SELECT sealed_key as " + role + " failed with " + pe.Code + " (" + pe.Message + "), it must be permission denied (42501)"})
	}
	pe, err = setRole(`SELECT cert_der FROM public.fleet_ca`)
	if err != nil {
		return nil, err
	}
	if pe != nil {
		out = append(out, [3]string{"pool-public-select", poolTable + ".cert_der", "SELECT cert_der as " + role + " failed with " + pe.Code + " (" + pe.Message + "): the reader must read the public columns"})
	}
	return out, nil
}
