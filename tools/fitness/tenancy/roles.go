package main

import (
	"context"
	"fmt"
)

// superuserEquivalentRoles are the predefined roles that give a member the server's file system or a
// program execution as the database server user: superuser in all but name
// (https://www.postgresql.org/docs/16/predefined-roles.html).
var superuserEquivalentRoles = []string{"pg_execute_server_program", "pg_read_server_files", "pg_write_server_files"}

// checkT3 is the role check (ADR-0002 T3, safe-primitives FF-SP7): the runtime role owns nothing, is
// not a superuser, has no BYPASSRLS, holds no TRUNCATE on a tenant table and no CREATE on a product
// schema, and is not a member of any role that does; the migration (owner) role is neither superuser
// nor BYPASSRLS; the two are different roles.
func checkT3(ctx context.Context, d *Database, m *catalogModel) ([]Violation, error) {
	var vs []Violation
	add := func(rule, where, msg string) { vs = append(vs, Violation{"T3", rule, where, msg}) }
	app, owner := d.s.appRole, d.s.ownerRole
	if app == owner {
		add("roles-distinct", app, "migrations and the runtime use the same role")
	}
	c, err := catalogConn(ctx, d)
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)

	for _, role := range []struct{ name, label string }{{app, "runtime role"}, {owner, "migration role"}} {
		var super, bypass bool
		if err := c.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1`, role.name).Scan(&super, &bypass); err != nil {
			return nil, fmt.Errorf("reading %s %s: %w", role.label, role.name, err)
		}
		if super {
			add("role-superuser", role.name, role.label+" is a superuser: it bypasses row-level security")
		}
		if bypass {
			add("role-bypassrls", role.name, role.label+" has BYPASSRLS: it bypasses row-level security")
		}
	}

	// Membership: the runtime role must not be a member of a superuser, a BYPASSRLS role, the migration
	// role, a superuser-equivalent predefined role or a role that owns an object in this database. 'MEMBER'
	// counts every direct or indirect membership whatever its INHERIT or SET option: 'USAGE' is false for a
	// membership granted WITH INHERIT FALSE (or to a NOINHERIT role), yet that role can still SET ROLE to
	// the other and act with its rights, including ALTER TABLE ... NO FORCE ROW LEVEL SECURITY.
	rows, err := c.Query(ctx, `SELECT r.rolname,
			CASE WHEN r.rolsuper THEN 'a superuser'
			     WHEN r.rolbypassrls THEN 'a BYPASSRLS role'
			     WHEN r.rolname = $2 THEN 'the migration role'
			     WHEN r.rolname = ANY($3::name[]) THEN 'a predefined role equivalent to superuser (server-side program, file read or write)'
			     ELSE 'a role that owns objects in this database' END
		FROM pg_roles r
		WHERE r.rolname <> $1 AND pg_has_role($1::name, r.oid, 'MEMBER') AND (
			r.rolsuper OR r.rolbypassrls OR r.rolname = $2 OR r.rolname = ANY($3::name[]) OR EXISTS (
				SELECT 1 FROM pg_shdepend s WHERE s.refclassid = 'pg_authid'::regclass AND s.refobjid = r.oid
				AND s.deptype = 'o' AND s.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())))
		ORDER BY 1`, app, owner, superuserEquivalentRoles)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var via, why string
		if err := rows.Scan(&via, &why); err != nil {
			rows.Close()
			return nil, err
		}
		add("role-membership", app, "runtime role is a member of "+via+", "+why+": it can SET ROLE to it or inherit its rights, whatever the INHERIT option of the grant")
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// TEMPORARY on the product database: the runtime role must not create temporary objects (they live in
	// a schema that precedes the product schemas on the default search path and can shadow product objects).
	var temp bool
	if err := c.QueryRow(ctx, `SELECT has_database_privilege($1::name, current_database(), 'TEMPORARY')`, app).Scan(&temp); err != nil {
		return nil, err
	}
	if temp {
		add("runtime-temporary", d.Name, "runtime role holds TEMPORARY on the product database (directly or through PUBLIC): it could shadow product tables and functions with temporary objects")
	}

	// Ownership: pg_shdepend records every object a role owns in this database.
	rows, err = c.Query(ctx, `SELECT pg_describe_object(s.classid, s.objid, s.objsubid)
		FROM pg_shdepend s JOIN pg_roles r ON r.oid = s.refobjid
		WHERE s.refclassid = 'pg_authid'::regclass AND s.deptype = 'o' AND s.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
		AND r.rolname = $1 ORDER BY 1`, app)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var obj string
		if err := rows.Scan(&obj); err != nil {
			rows.Close()
			return nil, err
		}
		add("runtime-owns-object", app, "runtime role owns "+obj+" (an owner bypasses RLS unless FORCE is set, and can alter or drop it)")
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// TRUNCATE on tenant tables (TRUNCATE is not subject to row security).
	for _, r := range m.tenants {
		var trunc bool
		if err := c.QueryRow(ctx, `SELECT has_table_privilege($1::name, $2::oid, 'TRUNCATE')`, app, r.oid).Scan(&trunc); err != nil {
			return nil, err
		}
		if trunc {
			add("runtime-truncate", r.qname(), "runtime role holds TRUNCATE on a tenant table (TRUNCATE ignores row-level security)")
		}
	}
	// CREATE on product schemas.
	rows, err = c.Query(ctx, `SELECT n.nspname FROM pg_namespace n WHERE `+productSchema+` AND has_schema_privilege($1::name, n.oid, 'CREATE') ORDER BY 1`, app)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return nil, err
		}
		add("runtime-create-schema", s, "runtime role holds CREATE on a product schema (it could create objects, such as a view or function, in the product's namespace)")
	}
	rows.Close()
	return vs, rows.Err()
}
