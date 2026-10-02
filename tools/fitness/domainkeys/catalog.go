package main

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

// productTable selects the tables that belong to the product: ordinary and partitioned tables outside
// the system schemas and outside extensions.
const productTable = `c.relkind IN ('r','p')
  AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
  AND NOT EXISTS (SELECT 1 FROM pg_depend ed WHERE ed.objid = c.oid AND ed.classid = 'pg_class'::regclass AND ed.deptype = 'e')`

type column struct {
	name, typ, typname, typtype, comment string
}

type table struct {
	oid        uint32
	qname      string
	partition  bool
	root       *table
	decl       *Declaration // the declaration of the root, nil when undeclared
	cols       []column
	colByName  map[string]column
	keyColumns map[string]bool // columns seen in a key, unique index or foreign key
}

func (t *table) kind() tablekind.Kind {
	if t.decl == nil {
		return ""
	}
	return t.decl.Kind
}

func (t *table) appendOnly() bool { return t.decl != nil && t.decl.AppendOnly }

// Options for the catalog checks.
type catalogOptions struct {
	runtimeRole   string
	retentionRole string
	secretAttrs   []string
	globalTables  map[string]bool // the tenancy exemption registry's global tables
}

// checkCatalog reads the migrated schema of d and applies X3, X4 and X5 and the declaration rules
// against decls. It returns the violations and the number of tables it looked at.
func checkCatalog(ctx context.Context, d *pgharness.Database, decls []Declaration, o catalogOptions) ([]Violation, int, error) {
	c, err := d.Admin(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, `SET search_path = ''`); err != nil {
		return nil, 0, err
	}
	tables, err := loadTables(ctx, c)
	if err != nil {
		return nil, 0, err
	}
	var vs []Violation
	byName := map[string]*table{}
	for _, t := range tables {
		byName[t.qname] = t
	}
	declared := map[string]*Declaration{}
	for i := range decls {
		declared[decls[i].Name] = &decls[i]
	}
	for _, t := range tables {
		t.decl = declared[t.root.qname]
		if t.decl == nil && !t.partition {
			vs = append(vs, Violation{"REG", "table-undeclared", t.qname,
				"no tablekind.Declare for this table: declare its kind (P, T or D), its domain-model entity and whether it is append-only, in the package that owns it (domain-model.md §0, kind map)"})
		}
	}
	for _, dl := range decls {
		if byName[dl.Name] == nil {
			vs = append(vs, Violation{"REG", "declaration-stale", dl.Name, "declared at " + dl.Pos + " but no migration creates this table"})
			continue
		}
		global := o.globalTables[dl.Name]
		switch {
		case dl.Kind == tablekind.Platform && !global:
			vs = append(vs, Violation{"REG", "kind-global-mismatch", dl.Name, "declared kind P (platform) but the tenancy exemption registry does not list it as a global table (ADR-0002 rule 4): add it there, or declare it T or D"})
		case dl.Kind != tablekind.Platform && global:
			vs = append(vs, Violation{"REG", "kind-global-mismatch", dl.Name, "declared kind " + string(dl.Kind) + " but the tenancy exemption registry lists it as a global table: only a P table is global"})
		}
	}
	used := map[string]map[string]bool{} // table → NameOK columns that suppressed a finding
	vs = append(vs, checkSealed(tables, byName)...)
	vs = append(vs, checkX4(tables, o)...)
	x3, err := checkX3(ctx, c, tables, used)
	if err != nil {
		return nil, 0, err
	}
	vs = append(vs, x3...)
	x5, err := checkX5(ctx, c, tables, o, used)
	if err != nil {
		return nil, 0, err
	}
	vs = append(vs, x5...)
	vs = append(vs, checkNameOK(decls, byName, used)...)
	return vs, len(tables), nil
}

func loadTables(ctx context.Context, c *pgx.Conn) ([]*table, error) {
	rows, err := c.Query(ctx, `SELECT c.oid::int8, n.nspname || '.' || c.relname, c.relispartition,
		COALESCE((SELECT i.inhparent::int8 FROM pg_inherits i WHERE i.inhrelid = c.oid), 0)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE `+productTable+` ORDER BY 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byOID := map[uint32]*table{}
	parent := map[uint32]uint32{}
	var tables []*table
	for rows.Next() {
		var oid, par int64
		t := &table{colByName: map[string]column{}, keyColumns: map[string]bool{}}
		if err := rows.Scan(&oid, &t.qname, &t.partition, &par); err != nil {
			return nil, err
		}
		t.oid = uint32(oid)
		byOID[t.oid] = t
		parent[t.oid] = uint32(par)
		tables = append(tables, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, t := range tables {
		r := t
		for r.partition && parent[r.oid] != 0 && byOID[parent[r.oid]] != nil {
			r = byOID[parent[r.oid]]
		}
		t.root = r
	}
	cols, err := c.Query(ctx, `SELECT a.attrelid::int8, a.attname::text, format_type(a.atttypid, a.atttypmod), ty.typname::text, ty.typtype::text,
		COALESCE(col_description(a.attrelid, a.attnum), '')
		FROM pg_attribute a JOIN pg_type ty ON ty.oid = a.atttypid JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE a.attnum > 0 AND NOT a.attisdropped AND `+productTable+` ORDER BY a.attrelid, a.attnum`)
	if err != nil {
		return nil, err
	}
	defer cols.Close()
	for cols.Next() {
		var oid int64
		var col column
		if err := cols.Scan(&oid, &col.name, &col.typ, &col.typname, &col.typtype, &col.comment); err != nil {
			return nil, err
		}
		if t := byOID[uint32(oid)]; t != nil {
			t.cols = append(t.cols, col)
			t.colByName[col.name] = col
		}
	}
	return tables, cols.Err()
}

// checkSealed validates the Sealed allow-list of each declaration: the column exists and is bytea.
func checkSealed(tables []*table, byName map[string]*table) []Violation {
	var vs []Violation
	for _, t := range tables {
		if t.partition || t.decl == nil {
			continue
		}
		for _, s := range t.decl.Sealed {
			col, ok := t.colByName[s]
			switch {
			case !ok:
				vs = append(vs, Violation{"REG", "declaration-stale", t.qname + "." + s, "declared Sealed at " + t.decl.Pos + " but the table has no such column"})
			case col.typname != "bytea":
				vs = append(vs, Violation{"X4", "sealed-type", t.qname + "." + s, "a Sealed column holds ciphertext and must be bytea, not " + col.typ + " (X4: sealed under the tenant data key)"})
			}
		}
	}
	return vs
}

// checkX4: no column is named for, or annotated as holding, a SecretAttrs attribute unless the table's
// declaration lists it as Sealed. Partitions share their root's columns and are not read twice.
func checkX4(tables []*table, o catalogOptions) []Violation {
	var vs []Violation
	for _, t := range tables {
		if t.partition {
			continue
		}
		for _, col := range t.cols {
			attr := secretAttrFor(col.name, col.comment, o.secretAttrs)
			if attr == "" || t.decl != nil && slices.Contains(t.decl.Sealed, col.name) {
				continue
			}
			vs = append(vs, Violation{"X4", "secret-attr-column", t.qname + "." + col.name,
				fmt.Sprintf("the column is named for or annotated as the SecretAttrs attribute %s: secrets never persist in clear (X4, safe-primitives §3.7, LF-38); store a sealed value in a bytea column listed as Sealed in the table's tablekind.Declare", attr)})
		}
	}
	return vs
}

// checkX3: on a directory (D) table, no primary key, unique index, exclusion constraint or foreign key
// uses a column that holds a DN, SID, sAMAccountName, UPN or display name; and no foreign key of any
// table references such a column of a D table. A directory object is (tenant_id, connection_id,
// object_guid).
func checkX3(ctx context.Context, c *pgx.Conn, tables []*table, used map[string]map[string]bool) ([]Violation, error) {
	byOID := map[uint32]*table{}
	for _, t := range tables {
		byOID[t.oid] = t
	}
	var vs []Violation
	nameOK := func(t *table, col string) bool {
		if t.decl != nil && slices.Contains(t.decl.NameOK, col) {
			if used[t.root.qname] == nil {
				used[t.root.qname] = map[string]bool{}
			}
			used[t.root.qname][col] = true
			return true
		}
		return false
	}
	// reported dedupes the same finding on a table and its partitions.
	reported := map[string]bool{}
	report := func(rule, where, msg string) {
		if k := rule + where; !reported[k] {
			reported[k] = true
			vs = append(vs, Violation{"X3", rule, where, msg})
		}
	}
	rows, err := c.Query(ctx, `SELECT i.indrelid::int8, ic.relname::text, i.indisprimary, i.indisunique, i.indisexclusion,
		ARRAY(SELECT pg_get_indexdef(i.indexrelid, k, true) FROM generate_series(1, i.indnkeyatts::int) k ORDER BY k)
		FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid JOIN pg_class c ON c.oid = i.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE (i.indisunique OR i.indisexclusion) AND `+productTable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var oid int64
		var name string
		var pk, uniq, excl bool
		var elems []string
		if err := rows.Scan(&oid, &name, &pk, &uniq, &excl, &elems); err != nil {
			return nil, err
		}
		t := byOID[uint32(oid)]
		if t == nil || t.kind() != tablekind.Directory {
			continue
		}
		what := "unique index"
		switch {
		case pk:
			what = "primary key"
		case excl:
			what = "exclusion constraint"
		}
		for _, el := range elems {
			col := t.colByName[el]
			holds, byName := keyHolds(el, col.comment)
			if holds == "" || byName && nameOK(t, el) {
				continue
			}
			t.keyColumns[el] = true
			report("key-identity-column", t.root.qname+" ("+what+" "+name+")",
				fmt.Sprintf("%s %s of the directory table %s includes %s, a column that holds a %s: a directory object is (tenant_id, connection_id, object_guid), never a DN, SID, sAMAccountName, UPN or name, because they change on rename, move and cross-domain move (X3)",
					what, name, t.root.qname, quoteElem(el), holdsWord(holds)))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	fks, err := c.Query(ctx, `SELECT con.conname::text, con.conrelid::int8, con.confrelid::int8,
		ARRAY(SELECT a.attname::text FROM unnest(con.conkey) WITH ORDINALITY k(n, o) JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.n ORDER BY k.o),
		ARRAY(SELECT a.attname::text FROM unnest(con.confkey) WITH ORDINALITY k(n, o) JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.n ORDER BY k.o)
		FROM pg_constraint con WHERE con.contype = 'f'`)
	if err != nil {
		return nil, err
	}
	defer fks.Close()
	for fks.Next() {
		var name string
		var from, to int64
		var local, remote []string
		if err := fks.Scan(&name, &from, &to, &local, &remote); err != nil {
			return nil, err
		}
		child, parent := byOID[uint32(from)], byOID[uint32(to)]
		check := func(owner *table, cols []string, what string) {
			for _, el := range cols {
				holds, byName := keyHolds(el, owner.colByName[el].comment)
				if holds == "" || byName && nameOK(owner, el) {
					continue
				}
				owner.keyColumns[el] = true
				report("fk-identity-column", owner.root.qname+" (foreign key "+name+")",
					fmt.Sprintf("foreign key %s %s column %s of the directory table %s, a column that holds a %s: directory references are (tenant_id, connection_id, object_guid), never a DN, SID, sAMAccountName, UPN or name (X3)",
						name, what, el, owner.root.qname, holdsWord(holds)))
			}
		}
		if child != nil && child.kind() == tablekind.Directory {
			check(child, local, "is built on")
		}
		if parent != nil && parent.kind() == tablekind.Directory {
			check(parent, remote, "joins on")
		}
	}
	if err := fks.Err(); err != nil {
		return nil, err
	}
	return vs, nil
}

func quoteElem(el string) string {
	if strings.ContainsAny(el, "() ") {
		return "the expression " + el
	}
	return "the column " + el
}

func holdsWord(h string) string {
	return map[string]string{"dn": "DN", "sid": "SID", "sam": "sAMAccountName", "upn": "UPN", "name": "name or display name"}[h]
}

// checkX5: an append-only table is never UPDATEd and deleted only by the retention role, and has no
// lifecycle-state column.
func checkX5(ctx context.Context, c *pgx.Conn, tables []*table, o catalogOptions, used map[string]map[string]bool) ([]Violation, error) {
	var vs []Violation
	appendOnly := map[uint32]*table{}
	for _, t := range tables {
		if t.appendOnly() {
			appendOnly[t.oid] = t
		}
	}
	// State columns.
	for _, t := range tables {
		if !t.appendOnly() || t.partition {
			continue
		}
		for _, col := range t.cols {
			if !stateName(col.name) && !(col.typtype == "e" && stateName(col.typname)) {
				continue
			}
			if slices.Contains(t.decl.NameOK, col.name) {
				if used[t.qname] == nil {
					used[t.qname] = map[string]bool{}
				}
				used[t.qname][col.name] = true
				continue
			}
			vs = append(vs, Violation{"X5", "state-column", t.qname + "." + col.name,
				fmt.Sprintf("%s is an append-only table (%s) and has a state-like column: its lifecycle states are derived from other records and never stored, because a stored state is an UPDATE (X5; if the column is a fact written once at insert and not a state, list it in NameOK)", t.qname, t.decl.Entity)})
		}
	}
	// The runtime role's effective rights, through grants, PUBLIC and role membership.
	rows, err := c.Query(ctx, `SELECT c.oid::int8,
		has_table_privilege($1, c.oid, 'UPDATE'), has_any_column_privilege($1, c.oid, 'UPDATE'),
		has_table_privilege($1, c.oid, 'DELETE'), has_table_privilege($1, c.oid, 'TRUNCATE')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE `+productTable, o.runtimeRole)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var oid int64
		var upd, updCol, del, trunc bool
		if err := rows.Scan(&oid, &upd, &updCol, &del, &trunc); err != nil {
			return nil, err
		}
		t := appendOnly[uint32(oid)]
		if t == nil {
			continue
		}
		role := fmt.Sprintf("the runtime role %q", o.runtimeRole)
		why := " (X5, " + t.decl.Entity + "): an append-only table is never updated; REVOKE UPDATE, DELETE ON " + t.qname + " FROM " + o.runtimeRole + " in the migration that creates it (the default privileges grant them)"
		switch {
		case upd:
			vs = append(vs, Violation{"X5", "runtime-update", t.qname, role + " holds UPDATE on " + t.qname + why})
		case updCol:
			vs = append(vs, Violation{"X5", "runtime-update-column", t.qname, role + " holds UPDATE on a column of " + t.qname + why})
		}
		if del {
			vs = append(vs, Violation{"X5", "runtime-delete", t.qname, role + " holds DELETE on " + t.qname + ": only the retention role (" + o.retentionRole + ") deletes append-only records (X5, " + t.decl.Entity + ")"})
		}
		if trunc {
			vs = append(vs, Violation{"X5", "runtime-truncate", t.qname, role + " holds TRUNCATE on " + t.qname + ": only the retention role (" + o.retentionRole + ") removes append-only records (X5, " + t.decl.Entity + ")"})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Every other grantee: the owner may do anything to its own table; the retention role may delete.
	grants, err := c.Query(ctx, `SELECT c.oid::int8, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, a.privilege_type, ''
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, aclexplode(c.relacl) a
		WHERE `+productTable+` AND a.grantee <> c.relowner AND a.privilege_type IN ('UPDATE','DELETE','TRUNCATE')
		UNION ALL
		SELECT c.oid::int8, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END, a.privilege_type, att.attname::text
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_attribute att ON att.attrelid = c.oid, aclexplode(att.attacl) a
		WHERE `+productTable+` AND a.grantee <> c.relowner AND a.privilege_type = 'UPDATE'`)
	if err != nil {
		return nil, err
	}
	defer grants.Close()
	for grants.Next() {
		var oid int64
		var grantee, priv, col string
		if err := grants.Scan(&oid, &grantee, &priv, &col); err != nil {
			return nil, err
		}
		t := appendOnly[uint32(oid)]
		if t == nil || grantee == o.runtimeRole {
			continue // the runtime role is judged on its effective rights above
		}
		if priv != "UPDATE" && grantee == o.retentionRole {
			continue
		}
		on := t.qname
		if col != "" {
			on += " (column " + col + ")"
		}
		vs = append(vs, Violation{"X5", "grant-" + strings.ToLower(priv), t.qname,
			fmt.Sprintf("%s holds %s on %s: append-only records (X5, %s) are updated by no role and deleted only by the retention role (%s)", grantee, priv, on, t.decl.Entity, o.retentionRole)})
	}
	return vs, grants.Err()
}

// checkNameOK reports NameOK entries that name a missing column or that suppressed nothing.
func checkNameOK(decls []Declaration, byName map[string]*table, used map[string]map[string]bool) []Violation {
	var vs []Violation
	for _, d := range decls {
		t := byName[d.Name]
		if t == nil {
			continue
		}
		for _, col := range d.NameOK {
			switch {
			case t.colByName[col].name == "":
				vs = append(vs, Violation{"REG", "declaration-stale", d.Name + "." + col, "listed in NameOK at " + d.Pos + " but the table has no such column"})
			case !used[d.Name][col]:
				vs = append(vs, Violation{"REG", "exemption-stale", d.Name + "." + col, "listed in NameOK at " + d.Pos + " but no X3 or X5 rule needs the exemption: remove it"})
			}
		}
	}
	sort.SliceStable(vs, func(i, j int) bool { return vs[i].Where < vs[j].Where })
	return vs
}
