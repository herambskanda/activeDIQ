package main

import (
	"context"
	"fmt"
)

// superuserEquivalentRoles are the predefined roles that give a member the server's file system or a
// program execution as the database server user: superuser in all but name
// (https://www.postgresql.org/docs/16/predefined-roles.html).
var superuserEquivalentRoles = []string{"pg_execute_server_program", "pg_read_server_files", "pg_write_server_files"}

// ownedHere restricts a pg_shdepend row (alias s) to objects of the database being checked. Ownership of
// the database itself is a shared dependency recorded with dbid = 0, classid = pg_database and objid = the
// database's OID, so a plain dbid filter misses it.
const ownedHere = `(s.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
	OR (s.dbid = 0 AND s.classid = 'pg_database'::regclass AND s.objid = (SELECT oid FROM pg_database WHERE datname = current_database())))`

// checkT3 is the role check (ADR-0002 T3, safe-primitives FF-SP7): the runtime role owns nothing, is
// not a superuser, has no BYPASSRLS and no REPLICATION (logical decoding reads every tenant's rows
// from the WAL, past row-level security), holds no TRUNCATE on a tenant table, no CREATE on a product
// schema or on the product database and no TEMPORARY on the database, directly or through any role it
// is a member of, INHERIT or not; it is not a member of a superuser, BYPASSRLS, REPLICATION, owner or
// object-owning role; the migration (owner) role has none of the three attributes and is not a member
// of a superuser, BYPASSRLS or REPLICATION role; the two are different roles.
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

	// Membership. 'MEMBER' counts every direct or indirect membership whatever its INHERIT or SET option:
	// 'USAGE' is false for a membership granted WITH INHERIT FALSE (or to a NOINHERIT role), yet that role
	// can still SET ROLE to the other and act with its rights, including ALTER TABLE ... NO FORCE ROW
	// LEVEL SECURITY or logical decoding. One query serves both roles; the extra triggers are parameters.
	// Neither role may be a member of a superuser, BYPASSRLS or REPLICATION role. The runtime role also
	// may not be a member of the migration role, a superuser-equivalent predefined role or a role that
	// owns an object in this database or the database itself (a database owner's ownership is recorded
	// with dbid 0).
	for _, mem := range []struct {
		member, label, migration string
		equivalent               []string
		owning                   bool
	}{
		{app, "runtime role", owner, superuserEquivalentRoles, true},
		{owner, "migration role", "", nil, false},
	} {
		rows, err := c.Query(ctx, `SELECT r.rolname,
				CASE WHEN r.rolsuper THEN 'a superuser'
				     WHEN r.rolbypassrls THEN 'a BYPASSRLS role'
				     WHEN r.rolreplication THEN 'a REPLICATION role (logical decoding reads every tenant''s rows from the WAL)'
				     WHEN r.rolname = $2 THEN 'the migration role'
				     WHEN r.rolname = ANY($3::name[]) THEN 'a predefined role equivalent to superuser (server-side program, file read or write)'
				     ELSE 'a role that owns objects in this database or owns the database' END
			FROM pg_roles r
			WHERE r.rolname <> $1 AND pg_has_role($1::name, r.oid, 'MEMBER') AND (
				r.rolsuper OR r.rolbypassrls OR r.rolreplication OR r.rolname = $2 OR r.rolname = ANY($3::name[]) OR ($4 AND EXISTS (
					SELECT 1 FROM pg_shdepend s WHERE s.refclassid = 'pg_authid'::regclass AND s.refobjid = r.oid
					AND s.deptype = 'o' AND `+ownedHere+`)))
			ORDER BY 1`, mem.member, mem.migration, mem.equivalent, mem.owning)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var via, why string
			if err := rows.Scan(&via, &why); err != nil {
				rows.Close()
				return nil, err
			}
			add("role-membership", mem.member, mem.label+" is a member of "+via+", "+why+": it can SET ROLE to it or inherit its rights, whatever the INHERIT option of the grant")
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	// TEMPORARY on the product database, held by the runtime role or by any role it is a member of (a
	// non-inherited membership does not show in has_database_privilege(app, ...) yet SET ROLE reaches it).
	// Temporary tables, views and types live in a schema that precedes the product schemas on the default
	// search path and can shadow product relations and types (never functions or operators:
	// https://www.postgresql.org/docs/16/runtime-config-client.html#GUC-SEARCH-PATH).
	rows, err := c.Query(ctx, `SELECT r.rolname FROM pg_roles r
		WHERE pg_has_role($1::name, r.oid, 'MEMBER') AND has_database_privilege(r.oid, current_database(), 'TEMPORARY') ORDER BY 1`, app)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var via string
		if err := rows.Scan(&via); err != nil {
			rows.Close()
			return nil, err
		}
		add("runtime-temporary", d.Name, "runtime role holds TEMPORARY on the product database "+through(app, via)+": it could shadow product tables, views and types with temporary objects")
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

	// TRUNCATE on tenant tables (TRUNCATE is not subject to row security), held by the runtime role or by
	// any role it is a member of: has_table_privilege(app, ...) misses a role granted WITH INHERIT FALSE,
	// which the runtime role reaches with SET ROLE.
	for _, r := range m.tenants {
		rows, err = c.Query(ctx, `SELECT g.rolname FROM pg_roles g
			WHERE pg_has_role($1::name, g.oid, 'MEMBER') AND has_table_privilege(g.oid, $2::oid, 'TRUNCATE') ORDER BY 1`, app, r.oid)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var via string
			if err := rows.Scan(&via); err != nil {
				rows.Close()
				return nil, err
			}
			add("runtime-truncate", r.qname(), "runtime role holds TRUNCATE on a tenant table "+through(app, via)+" (TRUNCATE ignores row-level security)")
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	// CREATE on product schemas, directly or through any role the runtime role is a member of.
	rows, err = c.Query(ctx, `SELECT n.nspname, g.rolname FROM pg_namespace n, pg_roles g
		WHERE `+productSchema+` AND pg_has_role($1::name, g.oid, 'MEMBER') AND has_schema_privilege(g.oid, n.oid, 'CREATE') ORDER BY 1, 2`, app)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s, via string
		if err := rows.Scan(&s, &via); err != nil {
			rows.Close()
			return nil, err
		}
		add("runtime-create-schema", s, "runtime role holds CREATE on a product schema "+through(app, via)+" (it could create objects, such as a view or function, in the product's namespace)")
	}
	rows.Close()
	return vs, rows.Err()
}

// through words where a privilege comes from: the runtime role itself, or a role it is a member of
// (reachable with SET ROLE whatever the INHERIT option of the grant).
func through(app, via string) string {
	if via == app {
		return "(directly or through PUBLIC)"
	}
	return "through membership of role " + via + " (SET ROLE reaches it whatever the INHERIT option)"
}
