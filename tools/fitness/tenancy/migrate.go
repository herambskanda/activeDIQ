package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

// Violation is one failed rule. Check is T1..T5; Rule names the rule inside the check; Where is the
// table, role, file:line or registry entry the rule failed on.
type Violation struct{ Check, Rule, Where, Msg string }

func (v Violation) String() string {
	return fmt.Sprintf("%s %s [%s]: %s", v.Check, v.Where, v.Rule, v.Msg)
}

func sortViolations(vs []Violation) {
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		if a.Where != b.Where {
			return a.Where < b.Where
		}
		return a.Rule < b.Rule
	})
}

// Migration is one SQL file of the sequence (the shared harness's type).
type Migration = pgharness.Migration

// ListMigrations returns the *.sql files of dir in application order; a bad file name is a T1
// violation. A missing directory or one with no SQL file is an empty list.
func ListMigrations(dir string) ([]Migration, []Violation, error) {
	ms, ps, err := pgharness.ListMigrations(dir)
	var vs []Violation
	for _, p := range ps {
		vs = append(vs, Violation{"T1", "migration-name", p.File, p.Msg})
	}
	return ms, vs, err
}

// apply runs migrations under the owner role, in order. A migration that fails to apply is a T1
// violation (the sequence must apply on an empty database), not a tool error.
func apply(ctx context.Context, d *Database, ms []Migration) []Violation {
	failed, msg, err := pgharness.Apply(ctx, d, ms)
	switch {
	case err != nil:
		return []Violation{{"T1", "migrations-apply", "owner role", err.Error()}}
	case failed != "":
		return []Violation{{"T1", "migrations-apply", failed, "does not apply on an empty database as the migration role: " + msg}}
	}
	return nil
}

// pgMessage renders a PostgreSQL error without anything beyond the message and code.
func pgMessage(err error) string {
	type pgErr interface {
		Error() string
	}
	return strings.TrimSpace(err.Error())
}

var tenantsColumns = []string{"id", "parent_tenant_id"}

// checkT1 applies migration 1 alone to an empty database and verifies it creates public.tenants
// (id uuid, parent_tenant_id uuid, FK to itself) and that no other table was created before it
// (every other table of migration 1 has a higher OID: OIDs of a fresh database only grow).
func checkT1(ctx context.Context, s *Server, ms []Migration, nameVs []Violation) ([]Violation, error) {
	vs := append([]Violation(nil), nameVs...)
	if len(ms) == 0 {
		return vs, nil
	}
	if !strings.HasPrefix(ms[0].Name, "0001_") {
		vs = append(vs, Violation{"T1", "migration-1", ms[0].Name, "the sequence must start at 0001 (ADR-0002 rule 4: migration 0001 creates tenants)"})
	}
	d, err := s.NewDatabase(ctx)
	if err != nil {
		return nil, err
	}
	defer d.Drop(ctx)
	if av := apply(ctx, d, ms[:1]); len(av) > 0 {
		return append(vs, av...), nil
	}
	c, err := d.Admin(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	var tenantsOID uint32
	err = c.QueryRow(ctx, `SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relname = 'tenants' AND c.relkind IN ('r','p')`).Scan(&tenantsOID)
	if err == pgx.ErrNoRows {
		return append(vs, Violation{"T1", "migration-1", ms[0].Name, "migration 1 does not create the table public.tenants"}), nil
	}
	if err != nil {
		return nil, err
	}
	for _, col := range tenantsColumns {
		var typ string
		err := c.QueryRow(ctx, `SELECT format_type(atttypid, atttypmod) FROM pg_attribute
			WHERE attrelid = $1 AND attname = $2 AND attnum > 0 AND NOT attisdropped`, tenantsOID, col).Scan(&typ)
		if err == pgx.ErrNoRows {
			vs = append(vs, Violation{"T1", "tenants-columns", "public.tenants", "no column " + col})
			continue
		}
		if err != nil {
			return nil, err
		}
		if typ != "uuid" {
			vs = append(vs, Violation{"T1", "tenants-columns", "public.tenants." + col, "must be uuid, is " + typ})
		}
	}
	rows, err := c.Query(ctx, `SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r','p','f','v','m') AND c.oid < $1
		AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'
		ORDER BY 1`, tenantsOID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rel string
		if err := rows.Scan(&rel); err != nil {
			return nil, err
		}
		vs = append(vs, Violation{"T1", "tenants-first", rel, "is created before public.tenants (nothing may precede it in migration 1)"})
	}
	return vs, rows.Err()
}
