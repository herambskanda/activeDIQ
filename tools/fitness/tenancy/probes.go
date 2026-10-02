package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/skenzeriq/activediq/tools/fitness/tenancy/registry"
)

// SQLSTATEs the probes expect.
const (
	sqlstateRLS        = "42501" // new row violates row-level security policy
	sqlstateForeignKey = "23503"
)

// checkT4 runs the generated isolation probes (ADR-0002 T4; safe-primitives SQL-13, SQL-14, SQL-19,
// FF-SP7) against the migrated schema with two seeded tenants. It writes nothing that outlives the
// run: every probe that changes data runs in a transaction it rolls back.
func checkT4(ctx context.Context, d *Database, m *catalogModel, reg *registry.Registry, out func(string, ...any)) ([]Violation, int, error) {
	var vs []Violation
	add := func(rule, where, msg string) { vs = append(vs, Violation{"T4", rule, where, msg}) }
	probes := 0

	adm, err := catalogConn(ctx, d)
	if err != nil {
		return nil, 0, err
	}
	defer adm.Close(ctx)

	var tenantsRel *relInfo
	for _, r := range m.tables {
		if r.qname() == "public.tenants" {
			tenantsRel = r
		}
	}
	var roots []*relInfo // tenant tables that are not partitions: writes route through the root
	for _, r := range m.tenants {
		if !r.isPartition && r.tenantOK {
			roots = append(roots, r)
		}
	}
	if tenantsRel == nil || len(m.tenants) == 0 {
		// No tenant table: nothing to isolate. The session-leak probe below still runs.
		lv, err := probeSessionLeak(ctx, d)
		return append(vs, lv...), 1, err
	}

	p := &prober{models: map[uint32]*tableModel{}, overrides: map[string]string{}}
	for _, o := range reg.ProbeValues {
		p.overrides[o.Column] = o.Value
	}
	for _, r := range append([]*relInfo{tenantsRel}, roots...) {
		tm, err := loadTableModel(ctx, adm, r)
		if err != nil {
			return nil, 0, err
		}
		p.models[r.oid] = tm
	}

	// Seed both tenants as the superuser with foreign keys and triggers off (session_replication_role
	// = replica), so seeding order does not matter. The superuser bypasses RLS: the policies are not
	// what is under test here.
	seed := func(tx pgx.Tx, tm *tableModel, tenant string) error {
		cols, args, err := p.row(tm, tenant)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, insertSQL(tm, cols), args...)
		return err
	}
	stx, err := adm.Begin(ctx)
	if err != nil {
		return nil, 0, err
	}
	if _, err := stx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		_ = stx.Rollback(ctx)
		return nil, 0, err
	}
	tenantsTM := p.models[tenantsRel.oid]
	for _, t := range []string{tenantA, tenantB} {
		if err := seed(stx, tenantsTM, t); err != nil {
			_ = stx.Rollback(ctx)
			add("probe-seed", "public.tenants", "cannot seed a tenant row: "+pgMessage(err))
			return vs, probes, nil
		}
	}
	var seedFailed bool
	for _, r := range roots {
		for _, t := range []string{tenantA, tenantB} {
			sp, err := stx.Begin(ctx)
			if err != nil {
				_ = stx.Rollback(ctx)
				return nil, 0, err
			}
			if err := seed(sp, p.models[r.oid], t); err != nil {
				_ = sp.Rollback(ctx)
				var pe *pgconn.PgError
				if errors.As(err, &pe) && (pe.Code == "23505" || pe.Code == "23P01") {
					// The rows differ only in tenant_id, so a collision means the key ignores the tenant.
					add("unique-global", r.qname(), fmt.Sprintf("tenant B cannot insert a row that tenant A already has: key %q is global, not per tenant", pe.ConstraintName))
					seedFailed = true
					break
				}
				add("probe-seed", r.qname(), "cannot seed a probe row for the isolation probes: "+pgMessage(err)+" (add a probeValues entry to the exemption registry if a CHECK constraint or domain needs a specific value)")
				seedFailed = true
				break
			}
			if err := sp.Commit(ctx); err != nil {
				_ = stx.Rollback(ctx)
				return nil, 0, err
			}
		}
	}
	if err := stx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	seeded := map[uint32]bool{}
	if !seedFailed {
		for _, r := range roots {
			seeded[r.oid] = true
		}
	} else {
		// A table that failed to seed has no row for one of the tenants; probe only tables that have both.
		for _, r := range roots {
			var n int
			if err := adm.QueryRow(ctx, `SELECT (SELECT count(*) FROM `+qident(r.schema, r.name)+` WHERE tenant_id = $1) +
				(SELECT count(*) FROM `+qident(r.schema, r.name)+` WHERE tenant_id = $2)`, tenantA, tenantB).Scan(&n); err != nil {
				return nil, 0, err
			}
			seeded[r.oid] = n >= 2
		}
	}

	app, err := d.App(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer app.Close(ctx)
	fresh, err := d.App(ctx) // a connection that has never had a tenant set: SQL-19
	if err != nil {
		return nil, 0, err
	}
	defer fresh.Close(ctx)

	// inTenant runs fn in a transaction with app.tenant_id set (as WithTenantTx does) and rolls back.
	inTenant := func(c *pgx.Conn, tenant string, fn func(tx pgx.Tx) error) error {
		tx, err := c.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if tenant != "" {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
				return err
			}
		}
		return fn(tx)
	}
	count := func(tx pgx.Tx, q string, args ...any) (int, error) {
		var n int
		err := tx.QueryRow(ctx, q, args...).Scan(&n)
		return n, err
	}
	rejectedByRLS := func(err error) bool {
		var pe *pgconn.PgError
		return errors.As(err, &pe) && pe.Code == sqlstateRLS
	}
	describe := func(err error) string {
		if err == nil {
			return "it succeeded"
		}
		return pgMessage(err)
	}

	// Reads: every tenant table and partition.
	for _, r := range m.tenants {
		if !r.tenantOK {
			continue
		}
		q := qident(r.schema, r.name)
		probes++
		err := inTenant(app, tenantA, func(tx pgx.Tx) error {
			nB, err := count(tx, `SELECT count(*) FROM `+q+` WHERE tenant_id = $1`, tenantB)
			if err != nil {
				return err
			}
			if nB != 0 {
				add("read-cross-tenant", r.qname(), fmt.Sprintf("tenant A reads %d row(s) of tenant B (SQL-13)", nB))
			}
			nAll, err := count(tx, `SELECT count(*) FROM `+q)
			if err != nil {
				return err
			}
			if !r.isPartition && seeded[r.oid] && nAll != 1 {
				add("read-own-rows", r.qname(), fmt.Sprintf("tenant A sees %d rows, want exactly its own 1 (a policy that hides everything is not isolation)", nAll))
			}
			return nil
		})
		if err != nil {
			add("probe-error", r.qname(), "tenant read probe failed: "+pgMessage(err))
		}
		probes++
		err = inTenant(fresh, "", func(tx pgx.Tx) error {
			n, err := count(tx, `SELECT count(*) FROM `+q)
			if err != nil {
				return err
			}
			if n != 0 {
				add("read-no-context", r.qname(), fmt.Sprintf("with no tenant set, %d row(s) are visible (SQL-19: the policy must fail closed)", n))
			}
			return nil
		})
		if err != nil {
			add("probe-error", r.qname(), "no-context read probe failed: "+pgMessage(err))
		}
	}

	// Writes, uniqueness and foreign keys: root tables only.
	for _, r := range roots {
		tm := p.models[r.oid]
		if !seeded[r.oid] {
			continue
		}
		q := qident(r.schema, r.name)
		rowFor := func(tenant string) (string, []any, error) {
			cols, args, err := p.row(tm, tenant)
			return insertSQL(tm, cols), args, err
		}

		// Cross-tenant write: A inserts a row carrying B's tenant_id.
		probes++
		sqlB, argsB, err := rowFor(tenantB)
		if err != nil {
			return nil, 0, err
		}
		err = inTenant(app, tenantA, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, sqlB, argsB...)
			if !rejectedByRLS(e) {
				add("write-cross-tenant", r.qname(), "tenant A can write a row carrying tenant B's tenant_id: not rejected by row security ("+describe(e)+")")
			}
			return nil
		})
		if err != nil {
			add("probe-error", r.qname(), "cross-tenant insert probe failed: "+pgMessage(err))
		}
		// A moves its own row to B; A updates and deletes B's rows.
		probes++
		err = inTenant(app, tenantA, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE `+q+` SET tenant_id = $1 WHERE tenant_id = $2`, tenantB, tenantA)
			if !rejectedByRLS(e) {
				add("write-cross-tenant", r.qname(), "tenant A can re-assign its own row to tenant B: not rejected by row security ("+describe(e)+")")
			}
			return nil
		})
		if err != nil {
			add("probe-error", r.qname(), "cross-tenant update probe failed: "+pgMessage(err))
		}
		probes++
		err = inTenant(app, tenantA, func(tx pgx.Tx) error {
			u, e := tx.Exec(ctx, `UPDATE `+q+` SET tenant_id = tenant_id WHERE tenant_id = $1`, tenantB)
			if e != nil {
				return e
			}
			dl, e := tx.Exec(ctx, `DELETE FROM `+q+` WHERE tenant_id = $1`, tenantB)
			if e != nil {
				return e
			}
			if u.RowsAffected() != 0 || dl.RowsAffected() != 0 {
				add("write-cross-tenant", r.qname(), fmt.Sprintf("tenant A updated %d and deleted %d row(s) of tenant B", u.RowsAffected(), dl.RowsAffected()))
			}
			return nil
		})
		if err != nil {
			add("probe-error", r.qname(), "cross-tenant update/delete probe failed: "+pgMessage(err))
		}
		// No context: insert rejected, update and delete touch nothing.
		probes++
		sqlA, argsA, err := rowFor(tenantA)
		if err != nil {
			return nil, 0, err
		}
		err = inTenant(fresh, "", func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, sqlA, argsA...)
			if !rejectedByRLS(e) {
				add("write-no-context", r.qname(), "with no tenant set, a write is not rejected by row security ("+describe(e)+")")
			}
			return nil
		})
		if err != nil {
			add("probe-error", r.qname(), "no-context insert probe failed: "+pgMessage(err))
		}
		probes++
		err = inTenant(fresh, "", func(tx pgx.Tx) error {
			u, e := tx.Exec(ctx, `UPDATE `+q+` SET tenant_id = tenant_id`)
			if e != nil {
				return e
			}
			dl, e := tx.Exec(ctx, `DELETE FROM `+q)
			if e != nil {
				return e
			}
			if u.RowsAffected() != 0 || dl.RowsAffected() != 0 {
				add("write-no-context", r.qname(), fmt.Sprintf("with no tenant set, %d row(s) were updated and %d deleted", u.RowsAffected(), dl.RowsAffected()))
			}
			return nil
		})
		if err != nil {
			add("probe-error", r.qname(), "no-context update/delete probe failed: "+pgMessage(err))
		}

		// "B's value blocks A": with B's row present and A's removed, A's identical row must insert.
		probes++
		err = adminProbe(ctx, adm, func(tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `DELETE FROM `+q+` WHERE tenant_id = $1`, tenantA); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, sqlA, argsA...); e != nil {
				var pe *pgconn.PgError
				if errors.As(e, &pe) && pe.Code == "23505" {
					add("unique-global", r.qname(), fmt.Sprintf("tenant A cannot insert a key value that tenant B already holds: unique index %q is global, not per tenant", pe.ConstraintName))
					return nil
				}
				if errors.As(e, &pe) && pe.Code == "23P01" {
					add("unique-global", r.qname(), fmt.Sprintf("tenant A conflicts with tenant B on exclusion constraint %q: it is not per tenant", pe.ConstraintName))
					return nil
				}
				return e
			}
			return nil
		})
		if err != nil {
			add("probe-error", r.qname(), "uniqueness probe failed: "+pgMessage(err))
		}

		// Foreign keys: A's row must not be able to reference B's parent row.
		for _, f := range tm.fks {
			parent := p.models[f.parent]
			if parent == nil || parent.rel.global != nil {
				continue // references a global table such as tenants
			}
			if parent == tm {
				out("T4   %s: foreign key %s is self-referencing; its shape is covered by T2", r.qname(), f.name)
				continue
			}
			probes++
			pq := qident(parent.rel.schema, parent.rel.name)
			err = adminProbe(ctx, adm, func(tx pgx.Tx) error {
				if _, e := tx.Exec(ctx, `DELETE FROM `+q+` WHERE tenant_id = $1`, tenantA); e != nil {
					return e
				}
				if _, e := tx.Exec(ctx, `DELETE FROM `+pq+` WHERE tenant_id = $1`, tenantA); e != nil {
					return e
				}
				// Back to origin mode so foreign keys are enforced for the insert under test.
				if _, e := tx.Exec(ctx, `SET LOCAL session_replication_role = origin`); e != nil {
					return e
				}
				_, e := tx.Exec(ctx, sqlA, argsA...)
				var pe *pgconn.PgError
				switch {
				case e == nil:
					add("fk-cross-tenant", r.qname(), fmt.Sprintf("a row of tenant A references a row of tenant B through foreign key %q to %s: the key does not pair tenant_id", f.name, parent.rel.qname()))
				case errors.As(e, &pe) && pe.Code == sqlstateForeignKey && pe.ConstraintName == f.name:
				default:
					add("probe-error", r.qname(), fmt.Sprintf("foreign key %q probe: expected a violation of that key, got %s", f.name, describe(e)))
				}
				return nil
			})
			if err != nil {
				add("probe-error", r.qname(), "foreign key probe failed: "+pgMessage(err))
			}
		}
	}

	lv, err := probeSessionLeak(ctx, d)
	if err != nil {
		return nil, 0, err
	}
	probes++
	return append(vs, lv...), probes, nil
}

// adminProbe runs fn as the superuser in a transaction that is always rolled back. replicaFirst
// starts it in session_replication_role = replica (no foreign-key or trigger enforcement).
func adminProbe(ctx context.Context, c *pgx.Conn, fn func(tx pgx.Tx) error) error {
	tx, err := c.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		return err
	}
	return fn(tx)
}

// leakIsLocal is the is_local argument of the set_config call the session-leak probe makes. It is true
// (transaction-scoped, what the product does); a test flips it to prove the probe notices a leak.
var leakIsLocal = true

// probeSessionLeak is SQL-14: after a transaction that set app.tenant_id with set_config(..., true)
// commits (and after one that rolls back), the same connection shows no tenant.
func probeSessionLeak(ctx context.Context, d *Database) ([]Violation, error) {
	c, err := d.App(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	var vs []Violation
	for _, commit := range []bool{true, false} {
		tx, err := c.Begin(ctx)
		if err != nil {
			return nil, err
		}
		var in string
		if err := tx.QueryRow(ctx, `SELECT set_config('app.tenant_id', $1, $2)`, tenantA, leakIsLocal).Scan(&in); err != nil {
			_ = tx.Rollback(ctx)
			return nil, err
		}
		if commit {
			err = tx.Commit(ctx)
		} else {
			err = tx.Rollback(ctx)
		}
		if err != nil {
			return nil, err
		}
		var after *string
		if err := c.QueryRow(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&after); err != nil {
			return nil, err
		}
		if after != nil && *after != "" {
			end := "rollback"
			if commit {
				end = "commit"
			}
			vs = append(vs, Violation{"T4", "session-leak", "app.tenant_id", fmt.Sprintf("after %s, the same connection still shows app.tenant_id = %q (SQL-14; PatchIQ NC2)", end, *after)})
		}
	}
	return vs, nil
}
