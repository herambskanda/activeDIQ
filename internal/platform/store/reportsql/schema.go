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
	// Tables lists every table of the schema, for the "a fragment names no table" check.
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

const catalogSQL = `
SELECT c.relname::text, a.attname::text, format_type(a.atttypid, NULL)::text, ty.typtype::text,
  EXISTS (SELECT 1 FROM pg_constraint k
          WHERE k.conrelid = c.oid AND k.contype = 'c' AND k.conkey = ARRAY[a.attnum]
            AND pg_get_constraintdef(k.oid) ~ '= ANY \(ARRAY\[')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid
JOIN pg_type ty ON ty.oid = a.atttypid
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped`

// CatalogSchema reads the public schema from the database the transaction is on. The composition
// root builds the registry from it at start-up.
func CatalogSchema(ctx context.Context, tx store.Tx) (Schema, error) {
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
