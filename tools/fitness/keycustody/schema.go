package main

import (
	"context"
	"strings"

	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

// checkFFKey1 judges the migrated schema as the owner/admin sees it. The behavioural transition
// matrix (retired -> active refused, and so on) is bound to keys.TestTransitionTriggerAndRuntimeGrants
// in bindings.go; here the catalogue must show that the guards exist and are not weakened.
func checkFFKey1(ctx context.Context, d *pgharness.Database) (vs []Violation, pending []string, err error) {
	add := func(rule, where, msg string) { vs = append(vs, Violation{"FF-KEY-1", rule, where, msg}) }
	app := d.Server().AppRole()
	c, err := d.Admin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close(ctx)

	exists := func(t string) (bool, error) {
		var ok bool
		err := c.QueryRow(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, t).Scan(&ok)
		return ok, err
	}
	tblPriv := func(t, p string) (bool, error) {
		var ok bool
		err := c.QueryRow(ctx, `SELECT has_table_privilege($1, 'public.' || $2, $3)`, app, t, p).Scan(&ok)
		return ok, err
	}
	colPriv := func(t, col, p string) (bool, error) {
		var ok bool
		err := c.QueryRow(ctx, `SELECT has_column_privilege($1, 'public.' || $2, $3, $4)`, app, t, col, p).Scan(&ok)
		return ok, err
	}

	ok, err := exists("tenant_keys")
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		add("table-missing", "tenant_keys", "the table does not exist on the migrated schema")
	} else {
		var rls, force bool
		if err := c.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'public.tenant_keys'::regclass`).Scan(&rls, &force); err != nil {
			return nil, nil, err
		}
		if !rls || !force {
			add("rls", "tenant_keys", "row-level security is not both enabled and FORCEd")
		}
		var defs []string
		rows, err := c.Query(ctx, `SELECT pg_get_indexdef(i.indexrelid) FROM pg_index i WHERE i.indrelid = 'public.tenant_keys'::regclass AND i.indisunique AND i.indpred IS NOT NULL`)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return nil, nil, err
			}
			defs = append(defs, s)
		}
		rows.Close()
		found := false
		for _, s := range defs {
			if strings.Contains(s, "(tenant_id)") && strings.Contains(s, "state = 'active'") {
				found = true
			}
		}
		if !found {
			add("one-active", "tenant_keys", "no partial unique index on (tenant_id) WHERE state = 'active' (DM-02.I1)")
		}
		var trg int
		if err := c.QueryRow(ctx, `SELECT count(*) FROM pg_trigger WHERE tgrelid = 'public.tenant_keys'::regclass AND NOT tgisinternal
		  AND tgenabled = 'A' AND (tgtype & 1) = 1 AND (tgtype & 2) = 2 AND (tgtype & 16) = 16`).Scan(&trg); err != nil {
			return nil, nil, err
		}
		if trg == 0 {
			add("transition-trigger", "tenant_keys", "no BEFORE UPDATE row trigger enabled ALWAYS: the state transition guard is missing or can be switched off by replication role")
		}
		for _, p := range []string{"DELETE", "TRUNCATE"} {
			has, err := tblPriv("tenant_keys", p)
			if err != nil {
				return nil, nil, err
			}
			if has {
				add("runtime-privilege", "tenant_keys", "the runtime role holds "+p)
			}
		}
		for _, col := range []string{"tenant_id", "version", "created_at"} {
			has, err := colPriv("tenant_keys", col, "UPDATE")
			if err != nil {
				return nil, nil, err
			}
			if has {
				add("runtime-privilege", "tenant_keys."+col, "the runtime role holds UPDATE on an identity column")
			}
		}
	}

	ok, err = exists("installation_kek")
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		pending = append(pending, "FF-KEY-1 installation_kek: the table has not landed (boot self-test ticket); its privilege rule is checked the moment it exists")
	} else {
		for _, p := range []string{"UPDATE", "DELETE", "TRUNCATE"} {
			var has bool
			var err error
			if p == "UPDATE" {
				err = c.QueryRow(ctx, `SELECT has_any_column_privilege($1, 'public.installation_kek', 'UPDATE')`, app).Scan(&has)
			} else {
				has, err = tblPriv("installation_kek", p)
			}
			if err != nil {
				return nil, nil, err
			}
			if has {
				add("runtime-privilege", "installation_kek", "the runtime role holds "+p)
			}
		}
	}
	return vs, pending, nil
}
