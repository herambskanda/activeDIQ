package main

import (
	"context"
	"fmt"
)

// ownedHere restricts a pg_shdepend row (alias s) to objects of the database being checked. Ownership of
// the database itself is a shared dependency recorded with dbid = 0, classid = pg_database and objid = the
// database's OID, so a plain dbid filter misses it.
const ownedHere = `(s.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
	OR (s.dbid = 0 AND s.classid = 'pg_database'::regclass AND s.objid = (SELECT oid FROM pg_database WHERE datname = current_database())))`

// checkT3 is the role check (ADR-0002 T3, safe-primitives FF-SP7): the runtime role owns nothing, is
// not a superuser, has no BYPASSRLS, holds no TRUNCATE on a tenant table and no CREATE on a product
// schema or on the product database, and is not a member of any role that does; the migration (owner)
// role is neither superuser nor BYPASSRLS; the two are different roles.
func checkT3(ctx context.Context, d *Database, m *catalogModel) ([]Violation, error) {
	var vs []Violation
	add := func(rule, where, msg string) { vs = append(vs, Violation{"T3", rule, where, msg}) }
	app, owner := d.Server().AppRole(), d.Server().OwnerRole()
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

	// Membership: the runtime role must not inherit a superuser, a BYPASSRLS role or the owner role.
	rows, err := c.Query(ctx, `SELECT r.rolname FROM pg_roles r
		WHERE r.rolname <> $1 AND (r.rolsuper OR r.rolbypassrls OR r.rolname = $2) AND pg_has_role($1::name, r.oid, 'USAGE')`, app, owner)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var via string
		if err := rows.Scan(&via); err != nil {
			rows.Close()
			return nil, err
		}
		add("role-membership", app, "runtime role inherits the rights of "+via+" (a superuser, a BYPASSRLS role or the migration role)")
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Ownership: pg_shdepend records every object a role owns (ownedHere), the database itself included.
	rows, err = c.Query(ctx, `SELECT CASE WHEN s.classid = 'pg_database'::regclass THEN 'database ' || current_database()
			ELSE pg_describe_object(s.classid, s.objid, s.objsubid) END
		FROM pg_shdepend s JOIN pg_roles r ON r.oid = s.refobjid
		WHERE s.refclassid = 'pg_authid'::regclass AND s.deptype = 'o' AND `+ownedHere+`
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
		add("runtime-owns-object", app, "runtime role owns "+obj+" (an owner bypasses RLS unless FORCE is set, and can alter or drop it; a database owner can also create schemas and set search_path for every session)")
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// CREATE on the product database: a role that can CREATE SCHEMA can ALTER ROLE itself SET search_path
	// (an ordinary role may), so unqualified product table names resolve to its own objects first.
	// The ACL is read directly so that every grantee that reaches the runtime role is found: PUBLIC, the
	// role itself or any role it is a MEMBER of, whatever the INHERIT or SET option of the membership
	// (a role granted WITH INHERIT FALSE can still SET ROLE to it).
	rows, err = c.Query(ctx, `SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END
		FROM pg_database db, aclexplode(COALESCE(db.datacl, acldefault('d', db.datdba))) a
		WHERE db.datname = current_database() AND a.privilege_type = 'CREATE'
		AND (a.grantee = 0 OR pg_has_role($1::name, a.grantee, 'MEMBER')) ORDER BY 1`, app)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var via string
		if err := rows.Scan(&via); err != nil {
			rows.Close()
			return nil, err
		}
		if via == app {
			via = "the runtime role itself"
		} else if via != "PUBLIC" {
			via = "role " + via + ", which the runtime role is a member of"
		}
		add("runtime-create-database", d.Name, "runtime role holds CREATE on the product database through "+via+": it could create a schema and set its own search_path to shadow product tables")
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
