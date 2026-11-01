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
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// The declared budget is what reports.md §3.3 "As built (T-0961)" documents: change both together.
func Test_closure_budget_is_the_declared_one(t *testing.T) {
	if root, conn := inventory.ClosureBudget(); root != 250_000 || conn != 500_000 {
		t.Fatalf("closure budget = %d per group, %d per connection; reports.md §3.3 declares 250,000 and 500,000", root, conn)
	}
}

// Fan-out (security review of T-0961): one big group written into K groups must not grow the closure to
// K x N rows. With the budget lowered to 1,000 rows per group and 2,500 per connection, the 600-member
// group and three of the ten groups that contain it are expanded; the other seven get one marker row
// each, their counts read Unknown and group_members says so. A change to the big group stays fast, the
// outcome is the same when the groups are decided again, and room that frees up is used on the next refresh.
func Test_group_closure_fanout_is_bounded(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		const users, k, rootBudget, connBudget = 600, 10, 1000, 2500
		defer inventory.SetClosureBudget(rootBudget, connBudget)()
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		bigG := hGUID(2, 1)
		var members []string
		var batch []inventory.Observation
		for i := 1; i <= users; i++ {
			g := hGUID(1, i)
			batch = append(batch, hUser{guid: g, sam: fmt.Sprintf("u%05d", i), rid: uint32(10000 + i), uac: i64(uacNormal), read: 15}.obs())
			members = append(members, g)
		}
		if _, err := e.populate(t, c, hBase.Add(time.Hour), batch...); err != nil {
			t.Fatal(err)
		}
		if _, err := e.populate(t, c, hBase.Add(2*time.Hour), hGroup(bigG, "Big", 2001, members...)); err != nil {
			t.Fatal(err)
		}
		att := func(j int, with ...string) inventory.Observation {
			return hGroup(hGUID(3, j), fmt.Sprintf("att%02d", j), uint32(3000+j), with...)
		}
		var atts []inventory.Observation
		for j := 1; j <= k; j++ {
			atts = append(atts, att(j, bigG))
		}
		if _, err := e.populate(t, c, hBase.Add(3*time.Hour), atts...); err != nil {
			t.Fatalf("a group over the budget must not fail the sync: %v", err)
		}
		rows := e.count(t, `SELECT count(*) FROM public.inventory_group_members`)
		over := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE edge_kind = 'over_budget'`)
		// Big holds 600 rows; each expanded att holds Big plus its 600 users (601). The unconstrained closure is 600 + 10 x 601.
		if over != 7 || rows != 600+3*601+7 {
			t.Errorf("closure rows = %d, over-budget markers = %d, want %d and 7 (the unbounded closure is %d)", rows, over, 600+3*601+7, 600+k*601)
		}
		if rows > connBudget+k+1 {
			t.Errorf("%d closure rows exceed the connection budget %d (+ one marker per group)", rows, connBudget)
		}
		e.requireStoredDecisionIsFromScratch(t, c, "after the containers were added")
		wantOver := e.overBudgetGroups(t)

		// A one-member change to the big group: refreshed within a stated time, same decision.
		newcomer := hGUID(1, users+1)
		start := time.Now()
		if _, err := e.populate(t, c, hBase.Add(4*time.Hour), hUser{guid: newcomer, sam: "newcomer", rid: 20001, uac: i64(uacNormal), read: 15}.obs(),
			hGroup(bigG, "Big", 2001, append(members, newcomer)...)); err != nil {
			t.Fatal(err)
		}
		took := time.Since(start)
		t.Logf("one-member change to the big group with 10 containers: %v", took)
		if took > 5*time.Second {
			t.Errorf("a one-member change took %v at a %d-row budget, want under 5 s", took, connBudget)
		}
		e.requireStoredDecisionIsFromScratch(t, c, "after the one-member change")
		if got := e.overBudgetGroups(t); strings.Join(got, ",") != strings.Join(wantOver, ",") {
			t.Errorf("the groups left unexpanded changed with an unrelated member: %v, was %v", got, wantOver)
		}
		if got := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid`, bigG); got != users+1 {
			t.Errorf("Big holds %d rows, want %d", got, users+1)
		}

		// Datasets: expanded groups count, unexpanded ones are Unknown (never a wrong number) with a finding.
		now := hBase.Add(24 * time.Hour)
		groups := e.run(t, reg, hQuery{dataset: inventory.DatasetGroups, cols: []report.ColumnID{"sam_account_name", "direct_members", "effective_members", "has_members", "nesting_cut", "membership_listing"}, scope: e.scopeNC(c), now: now})
		unknown, known := 0, 0
		for j := 1; j <= k; j++ {
			row := groups.rows[strings.ToLower(hGUID(3, j))]
			if cellKey(row["effective_members"])[:1] == "u" {
				unknown++
				for _, col := range []report.ColumnID{"direct_members", "has_members", "nesting_cut"} {
					if cellKey(row[col])[:1] != "u" {
						t.Errorf("att%02d.%s = %s, want Unknown", j, col, cellKey(row[col]))
					}
				}
				continue
			}
			known++
			if got := cellStr(row, "effective_members"); got != fmt.Sprint(users+2) {
				t.Errorf("att%02d effective_members = %s, want %d", j, got, users+2)
			}
		}
		if unknown != 7 || known != 3 {
			t.Errorf("%d Unknown and %d counted container groups, want 7 and 3", unknown, known)
		}
		if got := cellStr(groups.rows[strings.ToLower(bigG)], "effective_members"); got != fmt.Sprint(users+1) {
			t.Errorf("Big effective_members = %s, want %d", got, users+1)
		}
		gm := e.run(t, reg, hQuery{dataset: inventory.DatasetGroupMembers, cols: gmCols, scope: e.scopeNC(c), now: now,
			where: report.Cmp{Column: "edge_kind", Op: report.OpEq, Value: report.EnumV("over_budget")}})
		if len(gm.rows) != 7 {
			t.Fatalf("%d over-budget rows in group_members, want 7", len(gm.rows))
		}
		for key, row := range gm.rows {
			g, m, _ := strings.Cut(key, "|")
			if g != m || !strings.HasPrefix(cellStr(row, "finding"), "Membership too large to list: the members of att") {
				t.Errorf("row %s finding = %q", key, cellStr(row, "finding"))
			}
		}

		// Three expanded containers lose their member: the room is used by the groups left out, three of the seven.
		var empty []inventory.Observation
		for _, j := range e.expandedAttackers(t, k) {
			empty = append(empty, att(j))
		}
		if _, err := e.populate(t, c, hBase.Add(5*time.Hour), empty...); err != nil {
			t.Fatal(err)
		}
		e.requireStoredDecisionIsFromScratch(t, c, "after three containers emptied")
		if got := len(e.overBudgetGroups(t)); got != 4 {
			t.Errorf("%d groups unexpanded after three containers emptied, want 4 (7 left out, 3 now fit)", got)
		}
		if rows := e.count(t, `SELECT count(*) FROM public.inventory_group_members`); rows > connBudget+k+1 {
			t.Errorf("%d closure rows exceed the connection budget %d", rows, connBudget)
		}
	})
}

func (e *env) strings(t *testing.T, sql string, args ...any) []string {
	t.Helper()
	var out []string
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *env) overBudgetGroups(t *testing.T) []string {
	t.Helper()
	return e.strings(t, `SELECT group_guid::text FROM public.inventory_group_members WHERE edge_kind = 'over_budget' ORDER BY 1`)
}

// expandedAttackers lists the container groups (1..k) that hold member rows.
func (e *env) expandedAttackers(t *testing.T, k int) []int {
	t.Helper()
	var out []int
	for j := 1; j <= k; j++ {
		if e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND edge_kind <> 'over_budget'`, hGUID(3, j)) > 0 {
			out = append(out, j)
		}
	}
	return out
}

// RP11 for the new finding: an over-budget group in scope shows a count of Unknown and a finding that names
// only itself, even though the members it would have listed are out of scope.
func rpOverBudget(t *testing.T, e *env, reg *reportsql.Registry, c inventory.ConnectionID, dataset report.DatasetID, cols []report.ColumnID, now, at time.Time) {
	t.Helper()
	defer inventory.SetClosureBudget(1, 100)()
	baseG, baseU := hGUID(2, 1), hGUID(1, 1)
	sentG, sentU := sentinelGUID(1), sentinelGUID(2)
	obs := []inventory.Observation{named(hUser{guid: baseU, sam: "base-user", rid: 1101, uac: i64(uacNormal), read: 15}.obs(), "base-user"),
		mu2(sentU, sentinel+"-user", 1201),
		named(hGroup(baseG, "base-group", 2001, baseU, sentU, sentG), "base-group"), hGroup(sentG, sentinel+"-group", 2002, sentU)}
	if _, err := e.populate(t, c, at, obs...); err != nil {
		t.Fatal(err)
	}
	if got := e.overBudgetGroups(t); len(got) != 1 || !strings.EqualFold(got[0], baseG) {
		t.Fatalf("over-budget groups = %v, want only the base group", got)
	}
	res := e.run(t, reg, hQuery{dataset: dataset, cols: cols, scope: scopeOf(c, baseG, baseU), now: now})
	switch dataset {
	case inventory.DatasetGroups:
		if len(res.rows) != 1 {
			t.Fatalf("rows = %d, want 1", len(res.rows))
		}
		checkNoLeaks(t, res, map[string]string{strings.ToLower(baseG): realDN("base-group")})
		row := res.rows[baseG]
		for _, col := range []report.ColumnID{"direct_members", "effective_members", "primary_group_members", "has_members", "nesting_cut"} {
			if cellKey(row[col])[:1] != "u" {
				t.Errorf("%s = %s, want Unknown", col, cellKey(row[col]))
			}
		}
	case inventory.DatasetGroupMembers:
		if len(res.rows) != 1 {
			t.Fatalf("rows = %d, want 1 (the finding of the group itself)", len(res.rows))
		}
		ownDN := map[string]string{strings.ToLower(baseG): realDN("base-group")}
		if l := leaksWhere(res, func(rowKey string, col report.ColumnID, v string) bool {
			return (col == "group_dn" || col == "member_dn") && v == strings.ToLower(ownDN[strings.ToLower(baseG)])
		}); len(l) > 0 {
			t.Errorf("the finding reveals objects outside the scope:\n  %s", strings.Join(l, "\n  "))
		}
		if got := cellStr(res.rows[strings.ToLower(baseG+"|"+baseG)], "finding"); got != "Membership too large to list: the members of base-group are not expanded" {
			t.Errorf("finding = %q", got)
		}
	}
}
