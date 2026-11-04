package inventory_test

import (
	"context"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// T-1073: group-linked PSOs are read from the closure. When the closure cannot be trusted (a dirty group,
// or a PSO-linked group over budget) and no direct PSO exists, the policy is unresolved, never the
// domain policy; a direct PSO still wins.
func Test_users_policy_fails_closed_on_untrusted_closure(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		now := hBase.Add(100 * 24 * time.Hour)
		at := now.Add(-time.Hour)
		n := func(k int) string { return hGUID(1, k) }
		g := func(k int) string { return hGUID(2, k) }
		p := func(k int) string { return hGUID(3, k) }
		mk := func(k int, sam string) hUser {
			return hUser{guid: n(k), sam: sam, rid: uint32(1100 + k), uac: i64(uacNormal), read: 15, pwdLastSet: now.Add(-20 * 24 * time.Hour)}
		}
		w := world8{dom: domPol{max: sec(42 * 86400), lock: sec(1800), psosRead: true},
			users:  []hUser{mk(1, "via-group"), mk(2, "direct"), mk(3, "plain")},
			groups: []grpM{{guid: g(1), name: "Big", rid: 2001, members: []string{n(1), n(2)}}},
			psos: []psoM{
				{guid: p(1), name: "PSO-group", prec: i64(1), max: sec(10 * 86400), lock: sec(60), stored: true, applies: []string{g(1)}},
				{guid: p(2), name: "PSO-direct", prec: i64(5), max: sec(15 * 86400), lock: sec(60), stored: true, applies: []string{n(2)}},
			}}
		row := func(label string) map[string]map[report.ColumnID]report.Cell {
			res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: []report.ColumnID{"sam_account_name", "policy_source", "password_state_reason"},
				scope: e.scopeNC(e.adA), now: now})
			out := map[string]map[report.ColumnID]report.Cell{}
			for _, r := range res.rows {
				out[string(r["sam_account_name"].DigestValue())] = r
			}
			if len(out) != 3 {
				t.Fatalf("%s: %d rows", label, len(out))
			}
			return out
		}
		check := func(label string, by map[string]map[report.ColumnID]report.Cell, sam, src, why string) {
			t.Helper()
			r := by[sam]
			if got := string(r["policy_source"].DigestValue()); got != src {
				t.Errorf("%s %s: policy_source %q, want %q", label, sam, got, src)
			}
			if got := string(r["password_state_reason"].DigestValue()); got != why {
				t.Errorf("%s %s: reason %q, want %q", label, sam, got, why)
			}
		}
		const unres = "Unknown (policy not resolved)"

		// 1. a dirty group: the closure is behind the links
		e.seed8(t, e.adA, w, at)
		check("fresh", row("fresh"), "via-group", "PSO-group", "none")
		check("fresh", row("fresh"), "plain", "Domain policy", "none")
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.inventory_group_closure_dirty (tenant_id, connection_id, group_guid)
				VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid)`, string(e.adA), g(1))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		by := row("dirty")
		check("dirty", by, "via-group", unres, "group_closure_incomplete")
		check("dirty", by, "plain", unres, "group_closure_incomplete")
		check("dirty", by, "direct", "PSO-direct", "none")
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := inventory.Writer{}.RefreshClosure(ctx, tx, e.adA)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		check("refreshed", row("refreshed"), "via-group", "PSO-group", "none")

		// 2. a PSO-linked group over budget: its members are not listed
		defer inventory.SetClosureBudget(1, 100)()
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.inventory_group_closure_dirty (tenant_id, connection_id, group_guid)
				VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid)`, string(e.adA), g(1))
			if err != nil {
				return err
			}
			_, err = inventory.Writer{}.RefreshClosure(ctx, tx, e.adA)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		by = row("over budget")
		check("over budget", by, "via-group", unres, "group_closure_incomplete")
		check("over budget", by, "plain", unres, "group_closure_incomplete")
		check("over budget", by, "direct", "PSO-direct", "none")
	})
}
