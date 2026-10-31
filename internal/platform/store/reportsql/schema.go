package reportsql

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// ColKind is the storage class of a table column, as far as the registry's type rules care.
type ColKind uint8

// Column kinds. KindEnum is a PostgreSQL enum, or text bounded by a CHECK (col = ANY (ARRAY[...])):
// a closed set of values cannot carry a name.
const (
	KindOther ColKind = iota
	KindGUID
	KindInt
	KindBool
	KindTime
	KindEnum
	KindText
	KindJSON
	KindBytes
	KindGUIDList
	KindTextList
)

func (k ColKind) String() string {
	return [...]string{"other", "guid", "int", "bool", "time", "enum", "text", "json", "bytes", "guid list", "text list"}[k]
}

// Schema says which tables and columns exist. The registry checks every identifier of a dataset
// against it (contract §3.1), so a typo or a renamed column stops start-up and never reaches a run.
type Schema interface {
	// Tables lists every relation of the schema, whatever its kind (table, view, materialized view,
	// sequence, foreign table), for the "a fragment names no table" check: a name a fragment may
	// not declare is any name a FROM would resolve to. It may list more than Column knows.
	Tables() []string
	// Column returns the kind of a column, or false when the table or column does not exist.
	Column(table, column string) (ColKind, bool)
}

// MapSchema is an in-memory Schema: table -> column -> kind. Tests and the migration snapshot use it.
type MapSchema map[string]map[string]ColKind

// Tables implements Schema.
func (m MapSchema) Tables() []string {
	out := make([]string, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Column implements Schema.
func (m MapSchema) Column(table, column string) (ColKind, bool) {
	k, ok := m[table][column]
	return k, ok
}

// A text column is bounded (KindEnum) only when one of its single-column CHECKs is, as a whole,
// "col is one of these literals". PostgreSQL prints that as
//
//	CHECK ((col = ANY (ARRAY['a'::text, 'b'::text])))                      text
//	CHECK (((col)::text = ANY ((ARRAY['a'::character varying, …])::text[])))  varchar
//
// (col IN ('a','b') prints the same way). The match is anchored on both ends and the list holds
// literals only, so an open check such as CHECK (c = ANY (ARRAY['a']) OR c ~ '^x'), an AND with
// another condition, or a list holding an expression is not bounded: the column stays KindText and
// no Rel or MaskAnchor can project it (T-1033).
const (
	enumLit  = `''(?:[^'']|'''')*''(?:::[a-z]+(?: varying)?)?` // the regexp, inside an SQL string literal: quotes doubled
	enumList = enumLit + `(?:, ` + enumLit + `)*`
	// qcol is the column name as quote_ident prints it, with regex metacharacters escaped.
	qcol = `regexp_replace(quote_ident(a.attname), '([^a-zA-Z0-9_])', '\\\1', 'g')`

	catalogSQL = `
SELECT c.relname::text, a.attname::text, format_type(a.atttypid, NULL)::text, ty.typtype::text,
  EXISTS (SELECT 1 FROM pg_constraint k
          WHERE k.conrelid = c.oid AND k.contype = 'c' AND k.conkey = ARRAY[a.attnum]
            AND pg_get_constraintdef(k.oid) ~ (
              '^CHECK \(\((?:' || ` + qcol + ` || ' = ANY \(ARRAY\[` + enumList + `\]\)'
              || '|\(' || ` + qcol + ` || '\)::text = ANY \(\(ARRAY\[` + enumList + `\]\)::text\[\]\)'
              || ')\)\)$'))
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid
JOIN pg_type ty ON ty.oid = a.atttypid
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped`
)

// relationsSQL lists every relation a bare name in a FROM could resolve to in public: ordinary and
// partitioned tables, views, materialized views, sequences and foreign tables (T-1087).
const relationsSQL = `
SELECT c.relname::text
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')`

// catalogSchema is MapSchema's columns (tables only: a view's columns are not typed for the
// registry's rules) with the names of every relation of public.
type catalogSchema struct {
	MapSchema
	relations []string
}

// Tables implements Schema: every relation of public, not only the tables Column knows.
func (c catalogSchema) Tables() []string { return c.relations }

// CatalogSchema reads the public schema from the database the transaction is on. The composition
// root builds the registry from it at start-up. Tables() lists every relation kind; Column() answers
// for ordinary and partitioned tables only.
func CatalogSchema(ctx context.Context, tx store.Tx) (Schema, error) {
	out, err := catalogColumns(ctx, tx)
	if err != nil {
		return nil, err
	}
	rels, err := catalogRelations(ctx, tx)
	if err != nil {
		return nil, err
	}
	return catalogSchema{MapSchema: out, relations: rels}, nil
}

func catalogRelations(ctx context.Context, tx store.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, relationsSQL)
	if err != nil {
		return nil, fmt.Errorf("reportsql: reading the schema: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("reportsql: reading the schema: %w", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reportsql: reading the schema: %w", err)
	}
	sort.Strings(out)
	return out, nil
}

func catalogColumns(ctx context.Context, tx store.Tx) (MapSchema, error) {
	rows, err := tx.Query(ctx, catalogSQL)
	if err != nil {
		return nil, fmt.Errorf("reportsql: reading the schema: %w", err)
	}
	defer rows.Close()
	out := MapSchema{}
	for rows.Next() {
		var table, col, typ, typtype string
		var bounded bool
		if err := rows.Scan(&table, &col, &typ, &typtype, &bounded); err != nil {
			return nil, fmt.Errorf("reportsql: reading the schema: %w", err)
		}
		if out[table] == nil {
			out[table] = map[string]ColKind{}
		}
		out[table][col] = classify(typ, typtype, bounded)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reportsql: reading the schema: %w", err)
	}
	return out, nil
}

func classify(typ, typtype string, bounded bool) ColKind {
	switch {
	case typtype == "e":
		return KindEnum
	case typ == "uuid":
		return KindGUID
	case slices.Contains([]string{"smallint", "integer", "bigint"}, typ):
		return KindInt
	case typ == "boolean":
		return KindBool
	case slices.Contains([]string{"timestamp with time zone", "timestamp without time zone", "date"}, typ):
		return KindTime
	case typ == "jsonb" || typ == "json":
		return KindJSON
	case typ == "bytea":
		return KindBytes
	case typ == "uuid[]":
		return KindGUIDList
	case typ == "text[]" || typ == "character varying[]":
		return KindTextList
	case typ == "text" || typ == "character" || typ == "character varying" || typ == "name":
		if bounded {
			return KindEnum
		}
		return KindText
	}
	return KindOther
}

// projectable says whether a column may be projected by a Rel or by a MaskAnchor's non-identity
// list: GUID, int, bool, time or enum, never text or jsonb (contract §3.3), so no name can leave
// through a relation the compiler does not scope row by row.
func projectable(k ColKind) bool {
	switch k {
	case KindGUID, KindInt, KindBool, KindTime, KindEnum:
		return true
	}
	return false
}
