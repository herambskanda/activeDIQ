package main

import (
	"context"
	"fmt"
)

// checkT3 is the role check (ADR-0002 T3, safe-primitives FF-SP7): the runtime role owns nothing, is
// not a superuser, has no BYPASSRLS and no REPLICATION (logical decoding reads every tenant's rows
// from the WAL, past row-level security), holds no TRUNCATE on a tenant table and no CREATE on a
// product schema, and is not a member of any role that does (any membership, with or without INHERIT,
// direct or indirect: SET ROLE reaches it); the migration (owner) role has none of those three
// attributes and is not a member of a role that does; the two are different roles.
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
		var super, bypass, repl bool
		if err := c.QueryRow(ctx, `SELECT rolsuper, rolbypassrls, rolreplication FROM pg_roles WHERE rolname = $1`, role.name).Scan(&super, &bypass, &repl); err != nil {
			return nil, fmt.Errorf("reading %s %s: %w", role.label, role.name, err)
		}
		if super {
			add("role-superuser", role.name, role.label+" is a superuser: it bypasses row-level security")
		}
		if bypass {
			add("role-bypassrls", role.name, role.label+" has BYPASSRLS: it bypasses row-level security")
		}
		if repl {
			add("role-replication", role.name, role.label+" has REPLICATION: logical decoding streams every tenant's rows from the WAL past row-level security")
		}
	}

	// Membership. pg_has_role(.., 'MEMBER') is true for any direct or indirect membership, whatever its
	// INHERIT or SET options: a role that is not inherited can still be reached with SET ROLE (and
	// 'USAGE' would miss exactly that), so it is the conservative test.
	// The runtime role must not be a member of a superuser, BYPASSRLS or REPLICATION role or the owner
	// role; the owner role must not be a member of a superuser, BYPASSRLS or REPLICATION role.
	for _, m := range []struct{ member, label, also string }{
		{app, "runtime role", owner},
		{owner, "migration role", ""},
	} {
		rows, err := c.Query(ctx, `SELECT r.rolname FROM pg_roles r
			WHERE r.rolname <> $1 AND (r.rolsuper OR r.rolbypassrls OR r.rolreplication OR r.rolname = $2) AND pg_has_role($1::name, r.oid, 'MEMBER') ORDER BY 1`, m.member, m.also)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var via string
			if err := rows.Scan(&via); err != nil {
				rows.Close()
				return nil, err
			}
			what := "a superuser, a BYPASSRLS role or a REPLICATION role"
			if m.also != "" {
				what = "a superuser, a BYPASSRLS role, a REPLICATION role or the migration role"
			}
			add("role-membership", m.member, m.label+" is a member of "+via+" ("+what+"): it can reach those rights, with or without INHERIT, through SET ROLE")
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	// Ownership: pg_shdepend records every object a role owns in this database.
	rows, err := c.Query(ctx, `SELECT pg_describe_object(s.classid, s.objid, s.objsubid)
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
