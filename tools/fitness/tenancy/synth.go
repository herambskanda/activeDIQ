package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// The isolation probes (T4) need one valid row per tenant table and tenant. They are generated from
// the catalog: every column the row needs gets a deterministic value derived from its type, and the
// rows of tenants A and B are identical except for tenant_id, so a key that is not tenant-led collides.

type colInfo struct {
	num       int16
	name      string
	typ       string // format_type, for messages
	base      string // pg_type.typname of the base type (a domain resolves to its base)
	typtype   string
	category  string
	notNull   bool
	hasDef    bool
	generated string
	identity  string
	typmod    int32
	enumFirst string
}

type fkInfo struct {
	name            string
	parent          uint32
	conkey, confkey []int16
}

type tableModel struct {
	rel     *relInfo
	cols    []*colInfo
	keyCols map[int16]bool // columns of the primary key and of every unique index
	fks     []fkInfo       // foreign keys that are not partition clones
}

func (tm *tableModel) col(num int16) *colInfo {
	for _, c := range tm.cols {
		if c.num == num {
			return c
		}
	}
	return nil
}

func loadTableModel(ctx context.Context, c *pgx.Conn, rel *relInfo) (*tableModel, error) {
	tm := &tableModel{rel: rel, keyCols: map[int16]bool{}}
	rows, err := c.Query(ctx, `SELECT a.attnum, a.attname, format_type(a.atttypid, a.atttypmod),
			COALESCE(bt.typname, t.typname)::text, t.typtype::text, t.typcategory::text,
			a.attnotnull, a.atthasdef, a.attgenerated::text, a.attidentity::text, a.atttypmod,
			COALESCE((SELECT e.enumlabel FROM pg_enum e WHERE e.enumtypid = COALESCE(bt.oid, t.oid) ORDER BY e.enumsortorder LIMIT 1), '')
		FROM pg_attribute a JOIN pg_type t ON t.oid = a.atttypid
		LEFT JOIN pg_type bt ON t.typtype = 'd' AND bt.oid = t.typbasetype
		WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`, rel.oid)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		ci := &colInfo{}
		if err := rows.Scan(&ci.num, &ci.name, &ci.typ, &ci.base, &ci.typtype, &ci.category, &ci.notNull, &ci.hasDef,
			&ci.generated, &ci.identity, &ci.typmod, &ci.enumFirst); err != nil {
			rows.Close()
			return nil, err
		}
		tm.cols = append(tm.cols, ci)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	krows, err := c.Query(ctx, `SELECT unnest(i.indkey::int2[]) FROM pg_index i WHERE i.indrelid = $1 AND (i.indisunique OR i.indisprimary)`, rel.oid)
	if err != nil {
		return nil, err
	}
	for krows.Next() {
		var n int16
		if err := krows.Scan(&n); err != nil {
			krows.Close()
			return nil, err
		}
		if n > 0 {
			tm.keyCols[n] = true
		}
	}
	krows.Close()
	if err := krows.Err(); err != nil {
		return nil, err
	}
	frows, err := c.Query(ctx, `SELECT conname, confrelid, conkey, confkey FROM pg_constraint
		WHERE contype = 'f' AND conrelid = $1 AND conparentid = 0 ORDER BY conname`, rel.oid)
	if err != nil {
		return nil, err
	}
	for frows.Next() {
		var f fkInfo
		if err := frows.Scan(&f.name, &f.parent, &f.conkey, &f.confkey); err != nil {
			frows.Close()
			return nil, err
		}
		tm.fks = append(tm.fks, f)
	}
	frows.Close()
	return tm, frows.Err()
}

// uuidFor derives a stable version-4-shaped UUID from a label.
func uuidFor(label string) string {
	h := sha256.Sum256([]byte(label))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

var (
	tenantA = uuidFor("activediq/fitness-tenancy/tenant-A")
	tenantB = uuidFor("activediq/fitness-tenancy/tenant-B")
)

// errUnsupported marks a column whose type the generator cannot fill.
type errUnsupported struct{ col, typ string }

func (e errUnsupported) Error() string {
	return fmt.Sprintf("cannot generate a probe value for column %s of type %s: add a probeValues entry to the exemption registry", e.col, e.typ)
}

// synth returns a deterministic text value for a column; it is bound as a text parameter, so the
// server's own input function turns it into the column's type.
func synth(tm *tableModel, c *colInfo) (string, error) {
	label := tm.rel.qname() + "." + c.name
	if c.category == "A" {
		return "{}", nil
	}
	switch c.typtype {
	case "e":
		return c.enumFirst, nil
	case "r", "m": // range and multirange
		return "empty", nil
	}
	maxLen := -1
	if c.typmod > 4 {
		maxLen = int(c.typmod) - 4 // varchar(n), char(n)
	}
	text := func(s string) string {
		if maxLen >= 0 && len(s) > maxLen {
			return s[:maxLen]
		}
		return s
	}
	switch c.base {
	case "uuid":
		return uuidFor(label), nil
	case "bool":
		return "true", nil
	case "int2", "int4", "int8", "oid", "float4", "float8", "numeric", "money":
		return "1", nil
	case "text", "varchar", "bpchar", "name", "citext":
		return text("probe_" + c.name), nil
	case "char":
		return "p", nil
	case "timestamp", "timestamptz":
		return "2026-01-01 00:00:00+00", nil
	case "date":
		return "2026-01-01", nil
	case "time", "timetz":
		return "00:00:00", nil
	case "interval":
		return "1 day", nil
	case "json", "jsonb":
		return "{}", nil
	case "bytea":
		return `\x70`, nil
	case "inet":
		return "10.0.0.1", nil
	case "cidr":
		return "10.0.0.0/8", nil
	case "macaddr":
		return "08:00:2b:01:02:03", nil
	case "bit", "varbit":
		return "1", nil
	case "xml":
		return "<a/>", nil
	case "tsvector", "tsquery":
		return "probe", nil
	}
	return "", errUnsupported{label, c.typ}
}

// prober holds what row generation needs: every probed table, and the registry's value overrides.
type prober struct {
	models    map[uint32]*tableModel
	overrides map[string]string
}

// include says whether a column gets a value in the probe row. A column is left to its default (or
// NULL) unless it is the tenant column, part of a key, part of a foreign key, or NOT NULL with no
// default: the fewer values we invent, the fewer CHECK constraints we can trip.
func (p *prober) include(tm *tableModel, c *colInfo) bool {
	if c.generated != "" || c.identity == "a" {
		return false
	}
	if _, ok := p.overrides[tm.rel.qname()+"."+c.name]; ok {
		return true
	}
	if p.isTenantCol(tm, c) || tm.keyCols[c.num] {
		return true
	}
	for _, f := range tm.fks {
		for _, k := range f.conkey {
			if k == c.num {
				return true
			}
		}
	}
	return c.notNull && !c.hasDef && c.identity == ""
}

func (p *prober) isTenantCol(tm *tableModel, c *colInfo) bool {
	if tm.rel.qname() == "public.tenants" {
		return c.name == "id"
	}
	return c.name == "tenant_id"
}

// value returns the bound value of a column for tenant. A foreign-key column takes the value of the
// column it references, so a row's references resolve to the parent row generated the same way.
func (p *prober) value(tm *tableModel, c *colInfo, tenant string, depth int) (any, error) {
	if ov, ok := p.overrides[tm.rel.qname()+"."+c.name]; ok {
		return ov, nil
	}
	if p.isTenantCol(tm, c) {
		return tenant, nil
	}
	if depth < 8 {
		for _, f := range tm.fks {
			for i, k := range f.conkey {
				if k != c.num || i >= len(f.confkey) {
					continue
				}
				parent := p.models[f.parent]
				if parent == nil || (parent == tm && f.confkey[i] == c.num) {
					continue
				}
				pc := parent.col(f.confkey[i])
				if pc == nil || p.isTenantCol(parent, pc) {
					continue
				}
				return p.value(parent, pc, tenant, depth+1)
			}
		}
	}
	if !c.notNull && !tm.keyCols[c.num] {
		// A nullable column that is only here because a foreign key names it, with a parent we
		// cannot map: NULL satisfies the key.
		return nil, nil
	}
	s, err := synth(tm, c)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// row builds the column list and bound values of the probe row of a tenant.
func (p *prober) row(tm *tableModel, tenant string) ([]string, []any, error) {
	var cols []string
	var args []any
	for _, c := range tm.cols {
		if !p.include(tm, c) {
			continue
		}
		v, err := p.value(tm, c, tenant, 0)
		if err != nil {
			return nil, nil, err
		}
		cols = append(cols, c.name)
		args = append(args, v)
	}
	return cols, args, nil
}

// qident quotes schema and name with pgx's identifier sanitiser. Identifiers in this file come from
// the catalog, never from input; every value is a bind parameter.
func qident(parts ...string) string { return pgx.Identifier(parts).Sanitize() }

func insertSQL(tm *tableModel, cols []string) string {
	var b strings.Builder
	b.WriteString("INSERT INTO " + qident(tm.rel.schema, tm.rel.name) + " (")
	ph := make([]string, len(cols))
	for i, c := range cols {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(qident(c))
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	b.WriteString(") VALUES (" + strings.Join(ph, ", ") + ")")
	return b.String()
}
