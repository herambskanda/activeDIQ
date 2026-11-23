package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// TM-D32 / TM-F-AMPLIFY, the tables T-0961 did not cover (T-1528).

// inventory_group_closure_dirty is a set: 10,000 edge changes to one group leave one row, a refresh clears
// it, and a second refresh has nothing to do.
func Test_group_closure_dirty_set_is_one_row_per_group(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		c := e.adA
		e.hStructure(t, c)
		g := hGUID(2, 1)
		if _, err := e.populate(t, c, hBase.Add(time.Hour), hGroup(g, "Big", 3001)); err != nil {
			t.Fatal(err)
		}
		const n = 10_000
		at := hBase.Add(2 * time.Hour)
		err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			var w inventory.Writer
			for i := 0; i < n; i++ {
				if err := w.SetMember(ctx, tx, c, inventory.GUID(g), inventory.GUID(hGUID(1, i+1)), at); err != nil {
					return err
				}
				if i%2 == 0 { // churn: half of them are removed again
					if err := w.RemoveMember(ctx, tx, c, inventory.GUID(g), inventory.GUID(hGUID(1, i+1)), at.Add(time.Second)); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		const dirty = `SELECT count(*) FROM public.inventory_group_closure_dirty WHERE connection_id = $1::uuid`
		if rows := e.count(t, dirty, string(c)); rows != 1 {
			t.Fatalf("%d dirty rows after %d edge changes to one group, want 1 (a set, not a log)", rows, n+n/2)
		}
		var refreshed int
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
			refreshed, err = inventory.Writer{}.RefreshClosure(ctx, tx, c)
			return
		}); err != nil {
			t.Fatal(err)
		}
		if rows := e.count(t, dirty, string(c)); rows != 0 {
			t.Errorf("%d dirty rows after the refresh, want 0", rows)
		}
		if live := e.count(t, `SELECT count(*) FROM public.links WHERE source_guid = $1::uuid AND link_attr = 'member' AND state = 'active'`, g); live != n/2 {
			t.Errorf("%d live edges, want %d", live, n/2)
		}
		t.Logf("refresh touched %d groups", refreshed)
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			again, err := inventory.Writer{}.RefreshClosure(ctx, tx, c)
			if again != 0 {
				t.Errorf("second refresh did %d groups of work, want 0", again)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		e.requireStoredDecisionIsFromScratch(t, c, "after the churn")
	})
}

// ---- inventory_pso_applies ------------------------------------------------------------------------

// A PSO that names more targets than the budget keeps only the budget, is marked, the write does not fail,
// and every account of the naming context reads Unknown with the over-budget cause (never the domain policy).
// Bringing the directory back under the cap clears the marker from the current count alone.
func Test_pso_applies_over_budget_is_a_marker_and_unknown(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		defer inventory.SetPSOAppliesBudget(3, 5)()
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		pso, other := hGUID(5, 1), hGUID(5, 2)
		alice := hUser{guid: hGUID(1, 1), sam: "alice", rid: 1100, uac: i64(uacNormal), read: 15, pwdLastSet: hBase}
		obs := []inventory.Observation{alice.obs(), hPSOObj(pso, "Strict"), hPSOObj(other, "Other")}
		var targets []string
		for i := 0; i < 6; i++ {
			g := hGUID(2, i+1)
			targets = append(targets, g)
			obs = append(obs, hGroup(g, fmt.Sprintf("tg%d", i), uint32(2000+i)))
		}
		if _, err := e.populate(t, c, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		cols := []report.ColumnID{"sam_account_name", "password_state", "password_state_reason", "policy_source"}
		state := func() map[report.ColumnID]string {
			res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: cols, scope: e.scopeNC(c), now: hBase.Add(24 * time.Hour)})
			if len(res.rows) != 1 {
				t.Fatalf("%d rows", len(res.rows))
			}
			out := map[report.ColumnID]string{}
			for k, v := range res.rows[strings.ToLower(alice.guid)] {
				out[k] = cellKey(v)
			}
			return out
		}
		active := func(p string) int {
			return e.count(t, `SELECT count(*) FROM public.inventory_pso_applies WHERE pso_guid = $1::uuid AND state = 'active'`, p)
		}
		over := func(p string) bool {
			return e.count(t, `SELECT count(*) FROM public.inventory_psos WHERE pso_guid = $1::uuid AND applies_over_budget`, p) == 1
		}
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			if err := w.SetDomainPolicy(ctx, tx, c, inventory.GUID(hDom), inventory.DomainPolicy{MaxPwdAge: days(42), LockoutDuration: mins(30), PSOsReadAt: hBase, FunctionalLevel: lvl(7)}, hBase); err != nil {
				return err
			}
			p1 := int64(1)
			return w.SetPSO(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hDom), inventory.PSO{Precedence: &p1, MaxPwdAge: days(7), LockoutDuration: mins(5)}, hBase)
		})
		// A PSO under its cap resolves normally.
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			for _, g := range targets[:3] {
				if err := w.SetPSOApplies(ctx, tx, c, inventory.GUID(pso), inventory.GUID(g), hBase); err != nil {
					return err
				}
			}
			return w.SetPSOAppliesRead(ctx, tx, c, inventory.GUID(pso), 3)
		})
		if over(pso) || active(pso) != 3 {
			t.Fatalf("at the cap: over=%v active=%d, want false and 3", over(pso), active(pso))
		}
		if got := state()["password_state_reason"]; strings.Contains(got, "over_budget") {
			t.Fatalf("under the cap the reason is %s", got)
		}

		// The 4th and 5th targets arrive: the cycle commits (no error), nothing is stored past the cap.
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			for _, g := range targets[3:] {
				if err := w.SetPSOApplies(ctx, tx, c, inventory.GUID(pso), inventory.GUID(g), hBase.Add(time.Minute)); err != nil {
					return fmt.Errorf("an oversize PSO must not fail the cycle: %w", err)
				}
			}
			return w.SetPSOAppliesRead(ctx, tx, c, inventory.GUID(pso), 6)
		})
		if !over(pso) || active(pso) != 3 {
			t.Fatalf("past the cap: over=%v active=%d, want true and 3 stored rows", over(pso), active(pso))
		}
		got := state()
		if !strings.HasPrefix(got["password_state"], "u:") || !strings.Contains(got["password_state_reason"], "pso_applies_over_budget") ||
			!strings.Contains(got["policy_source"], "Unknown") {
			t.Errorf("over-budget PSO: %v, want Unknown with pso_applies_over_budget", got)
		}

		// A removal of a stored edge and a re-read under the cap restore the resolution: decided from the
		// current directory count alone.
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			if err := w.RemovePSOApplies(ctx, tx, c, inventory.GUID(pso), inventory.GUID(targets[0]), hBase.Add(2*time.Minute)); err != nil {
				return err
			}
			return w.SetPSOAppliesRead(ctx, tx, c, inventory.GUID(pso), 2)
		})
		if over(pso) || active(pso) != 2 {
			t.Errorf("after the re-read: over=%v active=%d, want false and 2", over(pso), active(pso))
		}
		if reason := state()["password_state_reason"]; strings.Contains(reason, "over_budget") {
			t.Errorf("after the re-read the reason is %s", reason)
		}

		// The connection cap: 2 stored on pso, three more on another PSO reach 5; the next is refused.
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			p2 := int64(2)
			if err := w.SetPSO(ctx, tx, c, inventory.GUID(other), inventory.GUID(hDom), inventory.PSO{Precedence: &p2, MaxPwdAge: days(9), LockoutDuration: mins(5)}, hBase); err != nil {
				return err
			}
			for _, g := range targets {
				if err := w.SetPSOApplies(ctx, tx, c, inventory.GUID(other), inventory.GUID(g), hBase.Add(3*time.Minute)); err != nil {
					return err
				}
			}
			return nil
		})
		if n := active(other); n != 3 || !over(other) {
			t.Errorf("connection cap: other holds %d rows, over=%v; want 3 and true", n, over(other))
		}
		// A read under the per-PSO cap must not clear the marker while stored edges are short of the directory:
		// (a) an edge refused by the connection cap is never sent again; (b) a value refused earlier by the
		// per-PSO cap stays missing after the directory drops back under it.
		third := hGUID(5, 3)
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			p3 := int64(3)
			if err := w.SetPSO(ctx, tx, c, inventory.GUID(third), inventory.GUID(hDom), inventory.PSO{Precedence: &p3, MaxPwdAge: days(1), LockoutDuration: mins(5)}, hBase); err != nil {
				return err
			}
			if err := w.SetPSOApplies(ctx, tx, c, inventory.GUID(third), inventory.GUID(targets[0]), hBase.Add(4*time.Minute)); err != nil {
				return err
			}
			return w.SetPSOAppliesRead(ctx, tx, c, inventory.GUID(third), 1)
		})
		if !over(third) || active(third) != 0 {
			t.Errorf("connection-cap refusal then a read under the cap: over=%v active=%d, want true and 0", over(third), active(third))
		}
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			return w.SetPSOAppliesRead(ctx, tx, c, inventory.GUID(pso), 3) // 2 stored, directory says 3
		})
		if !over(pso) {
			t.Errorf("directory count 3 with 2 stored edges: over=false, want true")
		}
		if reason := state()["password_state_reason"]; !strings.Contains(reason, "pso_applies_over_budget") {
			t.Errorf("reason = %s, want pso_applies_over_budget", reason)
		}
		// An edge past the budget for a PSO with no stored values cannot carry a marker: a typed error.
		ghost := hGUID(5, 9)
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			err := w.SetPSOApplies(ctx, tx, c, inventory.GUID(ghost), inventory.GUID(targets[0]), hBase)
			if err != inventory.ErrPSONotStored {
				t.Errorf("edge past the budget of an unstored PSO: %v, want ErrPSONotStored", err)
			}
			return nil
		})
	})
}

// ---- ancestry rewrite on move ---------------------------------------------------------------------

// A moved OU whose subtree is larger than the budget is not rewritten: the cycle commits, the result names
// the container, the descendants fail closed (incomplete, out of scope) with their old, stale chains left
// alone; an oscillating move does no more work and a move back inside the budget repairs everything.
func Test_ancestry_rewrite_over_budget_is_a_marker(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		defer inventory.SetAncestryBudget(5, 8)()
		e := setup(t, s)
		f := newForest()
		obs := []inventory.Observation{head(), f.at(ouA, inventory.KindOU, nc1), f.at(ouB, inventory.KindOU, nc1)}
		obs = append(obs, f.subtree(ouA)...) // X + 9 descendants: 9 rows below X
		if _, err := e.populate(t, e.adA, t1, obs...); err != nil {
			t.Fatal(err)
		}
		g := newForest()
		g.chains = map[string][]string{nc1: nil, ouB: f.chains[ouB]}
		res, err := e.populate(t, e.adA, t2, g.at(ouX, inventory.KindOU, ouB))
		if err != nil {
			t.Fatalf("an oversize move must not fail the cycle: %v", err)
		}
		if res.AncestryOverBudget != 1 {
			t.Errorf("AncestryOverBudget = %d, want 1", res.AncestryOverBudget)
		}
		rows := e.rows(t, e.a, e.adA)
		if r := rows[ouX]; !r.Complete || r.Ancestry[0] != ouB {
			t.Errorf("the moved OU itself = %+v, want complete under B", r)
		}
		for _, d := range []string{uX, ouY, uZ, cZ} {
			if rows[d].Complete {
				t.Errorf("%s is still complete after an over-budget move; it must fail closed", d)
			}
		}
		// Moving X back and forth again is cheap and still a marker; a full pass of the subtree repairs it.
		res, err = e.populate(t, e.adA, t3, f.at(ouX, inventory.KindOU, ouA))
		if err != nil || res.AncestryOverBudget != 1 {
			t.Fatalf("second move: %+v, %v", res, err)
		}
		restore := inventory.SetAncestryBudget(50, 100)
		defer restore()
		if _, err := e.populate(t, e.adA, t4, f.subtree(ouA)...); err != nil {
			t.Fatal(err)
		}
		rows = e.rows(t, e.a, e.adA)
		for _, d := range subtreeGUIDs {
			if !rows[d].Complete {
				t.Errorf("%s still incomplete after the subtree was observed again under budget", d)
			}
		}
	})
}

// The per-cycle budget: two moves of small trees in one Populate, the second passes the cycle total.
func Test_ancestry_rewrite_cycle_budget(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		defer inventory.SetAncestryBudget(100, 5)()
		e := setup(t, s)
		f := newForest()
		first, second := guidN(7001), guidN(7002)
		obs := []inventory.Observation{head(), f.at(ouA, inventory.KindOU, nc1), f.at(ouB, inventory.KindOU, nc1),
			f.at(first, inventory.KindOU, ouA), f.at(second, inventory.KindOU, ouA)}
		for i := 0; i < 4; i++ {
			obs = append(obs, f.at(guidN(7100+i), inventory.KindUser, first), f.at(guidN(7200+i), inventory.KindUser, second))
		}
		if _, err := e.populate(t, e.adA, t1, obs...); err != nil {
			t.Fatal(err)
		}
		g := newForest()
		g.chains = map[string][]string{nc1: nil, ouB: f.chains[ouB]}
		res, err := e.populate(t, e.adA, t2, g.at(first, inventory.KindOU, ouB), g.at(second, inventory.KindOU, ouB))
		if err != nil {
			t.Fatal(err)
		}
		if res.AncestryOverBudget != 1 {
			t.Fatalf("AncestryOverBudget = %d, want 1 (4 rows fit the 5-row cycle budget, the next 4 do not)", res.AncestryOverBudget)
		}
		rows := e.rows(t, e.a, e.adA)
		if !rows[guidN(7100)].Complete || rows[guidN(7200)].Complete {
			t.Errorf("first subtree complete=%v, second complete=%v; want true and false", rows[guidN(7100)].Complete, rows[guidN(7200)].Complete)
		}
	})
}

// ---- the policy CTE (resInner) ----------------------------------------------------------------------

// Cyclic and 128-deep nesting under a user: resInner walks groups with UNION (a visited set), so the ring
// ends, and it resolves the PSO of the top group inside the report timeout. T-1073 replaces the walk with
// the closure; until then this is the proof that the walk terminates on attacker-shaped nesting.
func Test_policy_cte_terminates_on_deep_and_cyclic_nesting(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		const depth, users = 128, 200
		pso := hGUID(5, 1)
		// g[0] holds the users; g[i] holds g[i-1]; g[depth-1] holds g[0] again (a cycle through all 128).
		obs := []inventory.Observation{hPSOObj(pso, "Deep")}
		var members []string
		for i := 0; i < users; i++ {
			u := hUser{guid: hGUID(1, i+1), sam: fmt.Sprintf("u%04d", i), rid: uint32(10000 + i), uac: i64(uacNormal), read: 15, pwdLastSet: hBase}
			obs = append(obs, u.obs())
			members = append(members, u.guid)
		}
		for i := 0; i < depth; i++ {
			var m []string
			switch {
			case i == 0:
				m = append(members, hGUID(2, depth)) // the ring closes: the top group is a member of g[0]
			default:
				m = []string{hGUID(2, i)}
			}
			obs = append(obs, hGroup(hGUID(2, i+1), fmt.Sprintf("g%03d", i), uint32(3000+i), m...))
		}
		if _, err := e.populate(t, c, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			if err := w.SetDomainPolicy(ctx, tx, c, inventory.GUID(hDom), inventory.DomainPolicy{MaxPwdAge: days(42), LockoutDuration: mins(30), PSOsReadAt: hBase, FunctionalLevel: lvl(7)}, hBase); err != nil {
				return err
			}
			p := int64(1)
			if err := w.SetPSO(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hDom), inventory.PSO{Precedence: &p, MaxPwdAge: days(7), LockoutDuration: mins(5)}, hBase); err != nil {
				return err
			}
			return w.SetPSOApplies(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hGUID(2, depth)), hBase) // the top of the chain
		})
		start := time.Now()
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: []report.ColumnID{"sam_account_name", "password_state", "policy_source"},
			scope: e.scopeNC(c), now: hBase.Add(24 * time.Hour)})
		took := time.Since(start)
		t.Logf("%d users, groups %d deep in a ring: %v", users, depth, took)
		if took > 20*time.Second { // the report statement timeout is 30 s
			t.Errorf("the users dataset took %v on a %d-deep ring, want well inside the 30 s statement timeout", took, depth)
		}
		if len(res.rows) != users {
			t.Fatalf("%d rows, want %d", len(res.rows), users)
		}
		for k, r := range res.rows {
			if got := cellKey(r["policy_source"]); !strings.Contains(got, "Deep") {
				t.Fatalf("%s policy_source = %s, want the PSO reached through 128 nested groups", k, got)
			}
		}
	})
}
