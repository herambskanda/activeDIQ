package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/tools/fitness/tenancy/registry"
)

// productSchema selects the schemas that belong to the product: everything but the system schemas.
// Objects that belong to an extension are left out (they are not ours to alter).
const productSchema = `n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'`
const notExtensionMember = `NOT EXISTS (SELECT 1 FROM pg_depend ed WHERE ed.objid = %s AND ed.classid = '%s'::regclass AND ed.deptype = 'e')`

// canonPolicy is the only policy shape (safe-primitives §7 rule 10). Its deparsed form is read back
// from the server being checked, so the comparison holds on every PostgreSQL version.
const canonPolicy = `tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid`

type relInfo struct {
	oid         uint32
	schema      string
	name        string
	kind        string
	isPartition bool
	rls, force  bool
	global      *registry.GlobalTable
	tenantAtt   int16 // attnum of tenant_id, 0 when absent
	tenantOK    bool  // tenant_id is uuid NOT NULL
}

func (r *relInfo) qname() string { return r.schema + "." + r.name }

// catalogModel is what checkT2 learned about the migrated schema; T3 and T4 reuse it.
type catalogModel struct {
	tables  []*relInfo
	byOID   map[uint32]*relInfo
	tenants []*relInfo // tenant-scoped tables (global tables excluded), partitions included
}

func (m *catalogModel) tenantTable(oid uint32) bool {
	r := m.byOID[oid]
	return r != nil && r.global == nil
}

// catalogConn opens a superuser connection with an empty search_path, so every name the catalog prints
// is schema-qualified and matches what the registry holds.
func catalogConn(ctx context.Context, d *Database) (*pgx.Conn, error) {
	c, err := d.admin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := c.Exec(ctx, `SET search_path = ''`); err != nil {
		_ = c.Close(ctx)
		return nil, err
	}
	return c, nil
}

// canonicalPolicyExpr deparses canonPolicy through a scratch table.
func canonicalPolicyExpr(ctx context.Context, d *Database) (string, error) {
	c, err := catalogConn(ctx, d)
	if err != nil {
		return "", err
	}
	defer c.Close(ctx)
	tx, err := c.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	for _, s := range []string{
		`CREATE SCHEMA fitness_canon`,
		`CREATE TABLE fitness_canon.t (tenant_id uuid)`,
		`ALTER TABLE fitness_canon.t ENABLE ROW LEVEL SECURITY`,
		`CREATE POLICY p ON fitness_canon.t USING (` + canonPolicy + `) WITH CHECK (` + canonPolicy + `)`,
	} {
		if _, err := tx.Exec(ctx, s); err != nil {
			return "", err
		}
	}
	var qual, check string
	if err := tx.QueryRow(ctx, `SELECT pg_get_expr(polqual, polrelid), pg_get_expr(polwithcheck, polrelid)
		FROM pg_policy WHERE polname = 'p'`).Scan(&qual, &check); err != nil {
		return "", err
	}
	if qual != check {
		return "", fmt.Errorf("canonical USING and WITH CHECK differ: %q vs %q", qual, check)
	}
	return qual, nil
}

// checkT2 is the catalog check (ADR-0002 T2, safe-primitives FF-SP7 rules 2, 9, 10).
func checkT2(ctx context.Context, d *Database, reg *registry.Registry) ([]Violation, *catalogModel, error) {
	canon, err := canonicalPolicyExpr(ctx, d)
	if err != nil {
		return nil, nil, fmt.Errorf("computing the canonical policy: %w", err)
	}
	c, err := catalogConn(ctx, d)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close(ctx)
	var vs []Violation
	add := func(rule, where, msg string) { vs = append(vs, Violation{"T2", rule, where, msg}) }

	for _, p := range reg.Validate() {
		add("registry", p.Entry, p.Msg)
	}

	// Tables, partitions included.
	m := &catalogModel{byOID: map[uint32]*relInfo{}}
	rows, err := c.Query(ctx, `SELECT c.oid, n.nspname, c.relname, c.relkind::text, c.relispartition, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r','p','f') AND `+productSchema+` AND `+fmt.Sprintf(notExtensionMember, "c.oid", "pg_class")+`
		ORDER BY n.nspname, c.relname`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		r := &relInfo{}
		if err := rows.Scan(&r.oid, &r.schema, &r.name, &r.kind, &r.isPartition, &r.rls, &r.force); err != nil {
			rows.Close()
			return nil, nil, err
		}
		m.tables = append(m.tables, r)
		m.byOID[r.oid] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// Registry: global tables must exist, and become exempt from the tenant rules.
	globalSeen := map[string]bool{}
	for i := range reg.GlobalTables {
		g := &reg.GlobalTables[i]
		var found *relInfo
		for _, r := range m.tables {
			if r.qname() == g.Table {
				found = r
			}
		}
		if found == nil {
			add("registry-stale", "globalTables["+g.Table+"]", "names a table that does not exist in the migrated schema")
			continue
		}
		found.global = g
		globalSeen[g.Table] = true
	}

	// tenant_id per table.
	for _, r := range m.tables {
		var typ string
		var notNull bool
		err := c.QueryRow(ctx, `SELECT attnum, atttypid::regtype::text, attnotnull FROM pg_attribute
			WHERE attrelid = $1 AND attname = 'tenant_id' AND attnum > 0 AND NOT attisdropped`, r.oid).Scan(&r.tenantAtt, &typ, &notNull)
		if err != nil && err != pgx.ErrNoRows {
			return nil, nil, err
		}
		r.tenantOK = err == nil && typ == "uuid" && notNull
		if r.global == nil {
			m.tenants = append(m.tenants, r)
		}
	}
	tenantsRel := (*relInfo)(nil)
	var tenantsIDAtt int16
	for _, r := range m.tables {
		if r.qname() == "public.tenants" {
			tenantsRel = r
			if err := c.QueryRow(ctx, `SELECT attnum FROM pg_attribute WHERE attrelid = $1 AND attname = 'id' AND NOT attisdropped`, r.oid).Scan(&tenantsIDAtt); err != nil && err != pgx.ErrNoRows {
				return nil, nil, err
			}
		}
	}

	tenantOIDs := make([]uint32, 0, len(m.tenants))
	allOIDs := make([]uint32, 0, len(m.tables))
	for _, r := range m.tables {
		allOIDs = append(allOIDs, r.oid)
	}
	for _, r := range m.tenants {
		tenantOIDs = append(tenantOIDs, r.oid)
	}

	// Foreign keys.
	type fk struct {
		oid                     uint32
		name                    string
		child, parent           uint32
		conkey, confkey         []int16
		clone                   bool
		childName, parentName   string
		columnsText, parentCols string
	}
	var fks []fk
	rows, err = c.Query(ctx, `SELECT con.oid, con.conname, con.conrelid, con.confrelid, con.conkey, con.confkey, con.conparentid <> 0,
		(SELECT string_agg(a.attname, ', ' ORDER BY k.ord) FROM unnest(con.conkey) WITH ORDINALITY k(attnum, ord)
			JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum)
		FROM pg_constraint con WHERE con.contype = 'f' AND con.conrelid = ANY($1)`, allOIDs)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var f fk
		if err := rows.Scan(&f.oid, &f.name, &f.child, &f.parent, &f.conkey, &f.confkey, &f.clone, &f.columnsText); err != nil {
			rows.Close()
			return nil, nil, err
		}
		fks = append(fks, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// Indexes that make a key unique (the primary key, unique constraints, CREATE UNIQUE INDEX,
	// partial and expression indexes) and exclusion constraints. pg_index, not pg_constraint.
	type idx struct {
		name      string
		rel       uint32
		unique    bool
		primary   bool
		exclusion bool
		key       []int16
		partial   bool
		excl1Op   string
	}
	var idxs []idx
	rows, err = c.Query(ctx, `SELECT ic.relname, i.indrelid, i.indisunique, i.indisprimary, i.indisexclusion, i.indkey::int2[], i.indpred IS NOT NULL,
		COALESCE((SELECT o.oprname FROM pg_constraint con JOIN pg_operator o ON o.oid = con.conexclop[1]
			WHERE con.conindid = i.indexrelid AND con.contype = 'x'), '')
		FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid
		WHERE i.indrelid = ANY($1) AND (i.indisunique OR i.indisexclusion) AND NOT ic.relispartition`, allOIDs)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var x idx
		if err := rows.Scan(&x.name, &x.rel, &x.unique, &x.primary, &x.exclusion, &x.key, &x.partial, &x.excl1Op); err != nil {
			rows.Close()
			return nil, nil, err
		}
		idxs = append(idxs, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// Policies.
	type pol struct {
		name        string
		cmd         string
		permissive  bool
		qual, check *string
	}
	pols := map[uint32][]pol{}
	rows, err = c.Query(ctx, `SELECT p.polrelid, p.polname, p.polcmd::text, p.polpermissive,
		pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid)
		FROM pg_policy p WHERE p.polrelid = ANY($1)`, allOIDs)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var oid uint32
		var p pol
		if err := rows.Scan(&oid, &p.name, &p.cmd, &p.permissive, &p.qual, &p.check); err != nil {
			rows.Close()
			return nil, nil, err
		}
		pols[oid] = append(pols[oid], p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// ---- per tenant table ----
	for _, r := range m.tenants {
		q := r.qname()
		what := "table"
		if r.isPartition {
			what = "partition"
		}
		if !r.tenantOK {
			add("tenant-id", q, what+" has no tenant_id uuid NOT NULL column (if it is deliberately global, register it in the exemption registry with a reason and an owning package)")
		}
		// FK tenant_id -> tenants(id).
		if r.tenantOK && tenantsRel != nil {
			ok := false
			for _, f := range fks {
				if f.child == r.oid && f.parent == tenantsRel.oid && slices.Equal(f.conkey, []int16{r.tenantAtt}) &&
					slices.Equal(f.confkey, []int16{tenantsIDAtt}) {
					ok = true
				}
			}
			if !ok {
				add("tenant-fk", q, what+" has no foreign key from tenant_id to tenants(id)")
			}
		}
		if !r.rls {
			add("rls-enable", q, what+" has no ROW LEVEL SECURITY enabled")
		}
		if !r.force {
			add("rls-force", q, what+" has no FORCE ROW LEVEL SECURITY (the owner would bypass the policy)")
		}
		// Policies.
		ps := pols[r.oid]
		all := false
		for _, p := range ps {
			canonQual := p.qual != nil && *p.qual == canon
			canonCheck := p.check != nil && *p.check == canon
			if p.permissive {
				if (p.qual != nil && !canonQual) || (p.check != nil && !canonCheck) {
					add("policy-shape", q, fmt.Sprintf("policy %q is permissive and not the fail-closed shape; want USING and WITH CHECK (%s), got USING %s WITH CHECK %s",
						p.name, canon, deparse(p.qual), deparse(p.check)))
				}
				if p.cmd == "*" && canonQual && canonCheck {
					all = true
				}
			}
		}
		if !all {
			add("policy-missing", q, "no permissive FOR ALL policy with USING and WITH CHECK ("+canon+")")
		}
	}

	// Primary keys, unique indexes and exclusion constraints lead with tenant_id.
	for _, x := range idxs {
		r := m.byOID[x.rel]
		if r == nil || r.global != nil {
			continue
		}
		kind := "unique index"
		switch {
		case x.primary:
			kind = "primary key"
		case x.exclusion:
			kind = "exclusion constraint"
		}
		if !r.tenantOK || len(x.key) == 0 || x.key[0] != r.tenantAtt {
			add("key-leading-tenant-id", r.qname(), fmt.Sprintf("%s %q does not lead with tenant_id (key checks bypass RLS, so a global key tells tenant A that tenant B holds a value)", kind, x.name))
			continue
		}
		if x.exclusion && x.excl1Op != "=" {
			add("key-leading-tenant-id", r.qname(), fmt.Sprintf("exclusion constraint %q must lead with tenant_id WITH =", x.name))
		}
	}

	// Foreign keys.
	for _, f := range fks {
		child, parent := m.byOID[f.child], m.byOID[f.parent]
		if child == nil {
			continue
		}
		if child.global != nil && parent != nil && parent.global == nil {
			add("global-references-tenant", child.qname(), fmt.Sprintf("registered-global table has foreign key %q to tenant table %s", f.name, parent.qname()))
			continue
		}
		if f.clone || child.global != nil || parent == nil || parent.global != nil {
			continue
		}
		paired := false
		for i := range f.conkey {
			if i < len(f.confkey) && child.tenantOK && f.conkey[i] == child.tenantAtt && f.confkey[i] == parent.tenantAtt && parent.tenantOK {
				paired = true
			}
		}
		if !paired {
			add("fk-pairs-tenant-id", child.qname(), fmt.Sprintf("foreign key %q (%s) references tenant table %s without pairing tenant_id with tenant_id (FK checks bypass RLS)", f.name, f.columnsText, parent.qname()))
		}
	}

	// Views and materialized views.
	type vw struct {
		oid          uint32
		qname, kind  string
		opts         []string
		tenantTables []string
	}
	var views []*vw
	rows, err = c.Query(ctx, `SELECT c.oid, n.nspname || '.' || c.relname, c.relkind::text, COALESCE(c.reloptions, '{}')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('v','m') AND `+productSchema+` AND `+fmt.Sprintf(notExtensionMember, "c.oid", "pg_class")+` ORDER BY 2`)
	if err != nil {
		return nil, nil, err
	}
	byView := map[uint32]*vw{}
	for rows.Next() {
		v := &vw{}
		if err := rows.Scan(&v.oid, &v.qname, &v.kind, &v.opts); err != nil {
			rows.Close()
			return nil, nil, err
		}
		views = append(views, v)
		byView[v.oid] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(views) > 0 {
		rows, err = c.Query(ctx, `WITH RECURSIVE edges(src, dst) AS (
				SELECT DISTINCT r.ev_class, d.refobjid FROM pg_depend d
				JOIN pg_rewrite r ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid
				WHERE d.refclassid = 'pg_class'::regclass AND d.refobjid <> r.ev_class),
			reach(root, dep) AS (
				SELECT src, dst FROM edges
				UNION
				SELECT reach.root, edges.dst FROM reach JOIN edges ON edges.src = reach.dep)
			SELECT root, dep FROM reach WHERE dep = ANY($1) ORDER BY 1, 2`, tenantOIDs)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var root, dep uint32
			if err := rows.Scan(&root, &dep); err != nil {
				rows.Close()
				return nil, nil, err
			}
			if v := byView[root]; v != nil {
				v.tenantTables = append(v.tenantTables, m.byOID[dep].qname())
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
	}
	for _, v := range views {
		if len(v.tenantTables) == 0 {
			continue
		}
		over := strings.Join(v.tenantTables, ", ")
		if v.kind == "m" {
			add("matview-over-tenant-table", v.qname, "materialized view reads tenant table(s) "+over+": a materialized view cannot carry RLS and no registry entry can exempt it")
			continue
		}
		if !hasBoolOption(v.opts, "security_invoker") {
			add("view-security-invoker", v.qname, "view over tenant table(s) "+over+" lacks security_invoker = true (the view owner's RLS context would apply, not the caller's)")
		}
	}

	// SECURITY DEFINER functions.
	secdef := map[string]bool{}
	rows, err = c.Query(ctx, `SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE p.prosecdef AND `+productSchema+` AND `+fmt.Sprintf(notExtensionMember, "p.oid", "pg_proc")+` ORDER BY 1`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			rows.Close()
			return nil, nil, err
		}
		secdef[f] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	exempt := map[string]bool{}
	for _, s := range reg.SecurityDefiner {
		exempt[s.Function] = true
		if !secdef[s.Function] {
			add("registry-stale", "securityDefiner["+s.Function+"]", "names a function that does not exist or is not SECURITY DEFINER")
		}
	}
	for f := range secdef {
		if !exempt[f] {
			add("security-definer", f, "SECURITY DEFINER function without a registry entry (it runs with its owner's rights and can read data the caller cannot)")
		}
	}

	// Probe-value overrides must name a column.
	for _, pv := range reg.ProbeValues {
		parts := strings.Split(pv.Column, ".")
		if len(parts) != 3 {
			continue
		}
		var n int
		if err := c.QueryRow(ctx, `SELECT count(*) FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relname = $2 AND a.attname = $3 AND a.attnum > 0 AND NOT a.attisdropped`, parts[0], parts[1], parts[2]).Scan(&n); err != nil {
			return nil, nil, err
		}
		if n == 0 {
			add("registry-stale", "probeValues["+pv.Column+"]", "names a column that does not exist in the migrated schema")
		}
	}
	return vs, m, nil
}

func deparse(s *string) string {
	if s == nil {
		return "(none)"
	}
	return *s
}

// hasBoolOption reports whether reloptions holds name set to a true value.
func hasBoolOption(opts []string, name string) bool {
	for _, o := range opts {
		k, v, _ := strings.Cut(o, "=")
		if k == name {
			switch strings.ToLower(v) {
			case "true", "on", "yes", "1", "t", "y":
				return true
			}
		}
	}
	return false
}
