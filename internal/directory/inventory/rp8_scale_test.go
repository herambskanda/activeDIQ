package inventory_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// T-1073 acceptance: password_state over a large directory reads the closure, not a per-row walk of
// links. ADIQ_PSO_SCALE_USERS sets the user count (T-1073 measured 200000); unset, the test skips.
func Test_password_state_reads_closure_at_scale(t *testing.T) {
	users, err := strconv.Atoi(os.Getenv("ADIQ_PSO_SCALE_USERS"))
	if err != nil || users <= 0 {
		t.Skip("set ADIQ_PSO_SCALE_USERS (200000 for the T-1073 measurement)")
	}
	const groups, psos = 200, 20
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		now := hBase.Add(100 * 24 * time.Hour)
		var batch []inventory.Observation
		flush := func() {
			if len(batch) > 0 {
				if _, err := e.populate(t, e.adA, now.Add(-time.Hour), batch...); err != nil {
					t.Fatal(err)
				}
				batch = batch[:0]
			}
		}
		add := func(o inventory.Observation) {
			batch = append(batch, o)
			if len(batch) == 1000 {
				flush()
			}
		}
		// Groups first, so one closure refresh covers them; users then only add objects. About 1.1 groups per
		// user and nesting two deep for half the groups keeps the closure near 1.6 rows per user, inside the
		// declared budget (an over-budget closure would make every user unresolved, which is the other test).
		members := make([][]string, groups)
		for i := 0; i < users; i++ {
			g := hGUID(1, i+1)
			members[i%groups] = append(members[i%groups], g)
			if i%10 == 0 {
				members[(i*7+1)%groups] = append(members[(i*7+1)%groups], g)
			}
		}
		for i := 0; i < groups; i++ {
			m := members[i]
			if i%2 == 0 {
				m = append(m, hGUID(2, i+2))
			}
			add(hGroup(hGUID(2, i+1), fmt.Sprintf("G%04d", i), uint32(2000+i), m...))
		}
		flush()
		for i := 0; i < users; i++ {
			add(hUser{guid: hGUID(1, i+1), sam: fmt.Sprintf("u%06d", i), rid: uint32(10000 + i), uac: i64(uacNormal), read: 15,
				pwdLastSet: now.Add(-day(i % 80))}.obs())
		}
		for i := 0; i < psos; i++ {
			add(hPSOObj(hGUID(3, i+1), fmt.Sprintf("PSO%02d", i)))
		}
		flush()
		for _, stmt := range []string{"SELECT gin_clean_pending_list('directory_objects_by_ancestry')", "ANALYZE"} {
			if err := e.d.ExecOwner(context.Background(), stmt); err != nil {
				t.Fatal(err)
			}
		}
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			if err := pw.SetDomainPolicy(ctx, tx, e.adA, inventory.GUID(hDom),
				inventory.DomainPolicy{MaxPwdAge: days(42), LockoutDuration: mins(30), PSOsReadAt: hBase}, hBase); err != nil {
				return err
			}
			for i := 0; i < psos; i++ {
				if err := pw.SetPSO(ctx, tx, e.adA, inventory.GUID(hGUID(3, i+1)), inventory.GUID(hDom),
					inventory.PSO{Precedence: i64(int64(i + 1)), MaxPwdAge: days(int64(10 + i)), LockoutDuration: mins(5)}, hBase); err != nil {
					return err
				}
				if err := pw.SetPSOApplies(ctx, tx, e.adA, inventory.GUID(hGUID(3, i+1)), inventory.GUID(hGUID(2, i*10+1)), hBase); err != nil {
					return err
				}
			}
			return nil
		})
		if err := e.d.ExecOwner(context.Background(), "ANALYZE"); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: []report.ColumnID{"sam_account_name", "password_state", "policy_source"},
			scope: e.scopeNC(e.adA), now: now})
		took := time.Since(start)
		if len(res.rows) != users {
			t.Fatalf("%d rows, want %d", len(res.rows), users)
		}
		viaPSO := 0
		for _, r := range res.rows {
			if string(r["policy_source"].DigestValue()) != "Domain policy" {
				viaPSO++
			}
		}
		var plan strings.Builder
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.Query(ctx, "EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF) "+res.sql[0], res.args[0]...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var l string
				if err := rows.Scan(&l); err != nil {
					return err
				}
				plan.WriteString(l + "\n")
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		t.Logf("plan:\n%s", plan.String())
		t.Logf("T-1073 measurement: %d users, %d groups, %d PSOs: password_state run %s, %d users on a PSO", users, groups, psos, took, viaPSO)
		if !strings.Contains(plan.String(), "inventory_group_members") {
			t.Errorf("plan does not read inventory_group_members:\n%s", plan.String())
		}
		if strings.Contains(plan.String(), "WorkTable") || strings.Contains(plan.String(), "Recursive Union") {
			t.Errorf("plan still walks links recursively:\n%s", plan.String())
		}
	})
}
