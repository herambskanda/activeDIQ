package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

// Violation is one failed rule. Check is A1..A9; Rule names the rule inside the check; Where is the
// table, role or test the rule failed on.
type Violation struct{ Check, Rule, Where, Msg string }

func (v Violation) String() string {
	return fmt.Sprintf("%s %s [%s]: %s", v.Check, v.Where, v.Rule, v.Msg)
}

// appendOnlyTables are the audit tables the runtime role may only INSERT into and read (ADR-0005 A1,
// threat model AG-4). audit_checkpoint_key is included: its one mutation, wiping a retired seed, goes
// through a SECURITY DEFINER function, never a runtime UPDATE.
var appendOnlyTables = []string{"audit_event", "audit_checkpoint", "audit_checkpoint_key"}

// noUpdateTables are the personal-data and secret side tables on which the runtime role holds no UPDATE
// (ADR-0005 rule 11 and the transient-secret rule): a value is written once and deleted, never edited.
var noUpdateTables = []string{"personal_subject", "personal_value", "operation_secrets"}

// checkA1 is the catalogue half of fitness-audit: privileges of the runtime role on the audit tables,
// the genesis-only trigger of audit_head (read from the catalogue and exercised as the runtime role),
// and the three powers that would let the role bypass a trigger (ownership, superuser,
// session_replication_role). It runs against a migrated database.
func checkA1(ctx context.Context, d *pgharness.Database) ([]Violation, error) {
	var vs []Violation
	add := func(rule, where, msg string) { vs = append(vs, Violation{"A1", rule, where, msg}) }
	app := d.Server().AppRole()
	c, err := d.Admin(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)

	var verNum int
	if err := c.QueryRow(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&verNum); err != nil {
		return nil, err
	}
	exists := func(t string) (bool, error) {
		var ok bool
		err := c.QueryRow(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, t).Scan(&ok)
		return ok, err
	}
	// priv reports the runtime role's privilege. UPDATE, INSERT, SELECT and REFERENCES are asked at
	// column level as well, so a column grant counts; DELETE, TRUNCATE and TRIGGER exist only on tables.
	priv := func(table, p string) (bool, error) {
		var ok bool
		var q string
		switch p {
		case "UPDATE", "INSERT", "SELECT", "REFERENCES":
			q = `SELECT has_any_column_privilege($1, 'public.' || $2, $3)`
		default:
			q = `SELECT has_table_privilege($1, 'public.' || $2, $3)`
		}
		err := c.QueryRow(ctx, q, app, table, p).Scan(&ok)
		return ok, err
	}
	all := append(append([]string{}, appendOnlyTables...), "audit_head")
	all = append(all, noUpdateTables...)
	for _, t := range all {
		ok, err := exists(t)
		if err != nil {
			return nil, err
		}
		if !ok {
			add("table-missing", t, "the table ADR-0005 A1 names does not exist, so its privileges cannot be proven")
		}
	}
	check := func(table string, forbidden []string) error {
		if ok, err := exists(table); err != nil || !ok {
			return err
		}
		for _, p := range forbidden {
			has, err := priv(table, p)
			if err != nil {
				return err
			}
			if has {
				add("runtime-privilege", table, "the runtime role holds "+p)
			}
		}
		return nil
	}
	for _, t := range appendOnlyTables {
		if err := check(t, []string{"UPDATE", "DELETE", "TRUNCATE"}); err != nil {
			return nil, err
		}
	}
	for _, t := range noUpdateTables {
		if err := check(t, []string{"UPDATE"}); err != nil {
			return nil, err
		}
	}
	beyond := []string{"DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
	if verNum >= 170000 {
		beyond = append(beyond, "MAINTAIN") // PostgreSQL 17 added MAINTAIN
	}
	if err := check("audit_head", beyond); err != nil {
		return nil, err
	}

	// Bypass powers: a trigger protects only against a role that cannot disable or skip it.
	var super, owns, setSRR bool
	if err := c.QueryRow(ctx, `SELECT rolsuper FROM pg_roles WHERE rolname = $1`, app).Scan(&super); err != nil {
		return nil, fmt.Errorf("reading runtime role %s: %w", app, err)
	}
	if super {
		add("role-superuser", app, "the runtime role is a superuser: it bypasses the audit_head trigger and row-level security")
	}
	if ok, _ := exists("audit_head"); ok {
		if err := c.QueryRow(ctx, `SELECT c.relowner = r.oid FROM pg_class c, pg_roles r WHERE c.oid = 'public.audit_head'::regclass AND r.rolname = $1`, app).Scan(&owns); err != nil {
			return nil, err
		}
		if owns {
			add("owns-audit-head", "audit_head", "the runtime role owns audit_head: an owner can disable its trigger")
		}
	}
	if err := c.QueryRow(ctx, `SELECT has_parameter_privilege($1, 'session_replication_role', 'SET')`, app).Scan(&setSRR); err != nil {
		return nil, err
	}
	if setSRR {
		add("session-replication-role", app, "the runtime role can SET session_replication_role: 'replica' skips ordinary triggers")
	}

	// The genesis-only BEFORE INSERT trigger: present, enabled, row-level, then exercised.
	trigOK := false
	if ok, _ := exists("audit_head"); ok {
		var n int
		if err := c.QueryRow(ctx, `SELECT count(*) FROM pg_trigger
			WHERE tgrelid = 'public.audit_head'::regclass AND NOT tgisinternal
			  AND tgenabled = 'O' AND (tgtype & 1) = 1 AND (tgtype & 2) = 2 AND (tgtype & 4) = 4 AND (tgtype & 64) = 0`).Scan(&n); err != nil {
			return nil, err
		}
		trigOK = n > 0
		if !trigOK {
			add("genesis-trigger", "audit_head", "no enabled row-level BEFORE INSERT trigger: a head can be created at any seq and hash")
		}
	}
	if trigOK {
		pv, err := probeGenesis(ctx, d)
		if err != nil {
			return nil, err
		}
		vs = append(vs, pv...)
	}
	return vs, nil
}

// probeGenesis exercises audit_head's insert trigger as the runtime role, in transactions it always
// rolls back, for a throw-away tenant created by the owner role: a row other than seq 0, a seq 0 row
// with the wrong hash, and a genesis row with a caller-supplied future `at`.
func probeGenesis(ctx context.Context, d *pgharness.Database) ([]Violation, error) {
	var vs []Violation
	add := func(rule, msg string) { vs = append(vs, Violation{"A1", rule, "audit_head", msg}) }
	o, err := d.Owner(ctx)
	if err != nil {
		return nil, err
	}
	defer o.Close(ctx)
	var tid string
	if err := o.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&tid); err != nil {
		return nil, err
	}
	if _, err := o.Exec(ctx, `INSERT INTO public.tenants (id, name) VALUES ($1::uuid, 'fitness-audit probe')`, tid); err != nil {
		return nil, fmt.Errorf("creating the probe tenant: %w", err)
	}
	app, err := d.App(ctx)
	if err != nil {
		return nil, err
	}
	defer app.Close(ctx)
	u, err := uuidBytes(tid)
	if err != nil {
		return nil, err
	}
	g := chain.Genesis(u)
	wrong := make([]byte, 32)
	try := func(seq int, hash []byte, atExpr string, fn func(tx pgx.Tx) error) (err error) {
		tx, err := app.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tid); err != nil {
			return err
		}
		// atExpr is one of this file's constants, never input.
		_, err = tx.Exec(ctx, `INSERT INTO public.audit_head (tenant_id, seq, hash, at) VALUES ($1::uuid, $2, $3, `+atExpr+`)`, tid, seq, hash)
		if err == nil && fn != nil {
			err = fn(tx)
		}
		return err
	}
	if err := try(5, g[:], "now()", nil); err == nil {
		add("genesis-seq", "the trigger accepted a head row with seq 5; only seq 0 may be inserted")
	}
	if err := try(0, wrong, "now()", nil); err == nil {
		add("genesis-hash", "the trigger accepted a seq 0 head whose hash is not the tenant's hash_0")
	}
	skewed := false
	err = try(0, g[:], "now() + interval '10 years'", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT at > now() + interval '1 day' FROM public.audit_head WHERE tenant_id = $1::uuid`, tid).Scan(&skewed)
	})
	switch {
	case err != nil:
		add("genesis-valid", "the correct genesis head was refused for the runtime role: "+strings.TrimSpace(err.Error()))
	case skewed:
		add("genesis-at", "a caller-supplied future `at` survived the trigger: it would skew every later timestamp")
	}
	return vs, nil
}

func uuidBytes(s string) ([16]byte, error) {
	var b [16]byte
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != 16 {
		return b, fmt.Errorf("bad uuid %q", s)
	}
	copy(b[:], raw)
	return b, nil
}
