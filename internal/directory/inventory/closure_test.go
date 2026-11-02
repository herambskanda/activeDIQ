package inventory_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// closureRows reads the stored closure of one group as "member kind depth via" lines, sorted.
func (e *env) closureRows(t *testing.T, c inventory.ConnectionID, group string) []string {
	t.Helper()
	var out []string
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT member_guid::text, edge_kind, depth, via::text[] FROM public.inventory_group_members
			WHERE connection_id = $1::uuid AND group_guid = $2::uuid ORDER BY member_guid`, string(c), group)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m, k string
			var d int
			var via []string
			if err := rows.Scan(&m, &k, &d, &via); err != nil {
				return err
			}
			out = append(out, fmt.Sprintf("%s %s %d [%s]", m, k, d, strings.Join(via, ",")))
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("closure rows: %v", err)
	}
	return out
}

func wantRows(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	got, want = slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s:\n got:\n  %s\nwant:\n  %s", label, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// The closure holds each member once with its shortest path, the primary-group members, the cycle as a
// finding row, and it follows edge removals and a deleted intermediate group (spec §6.6, FR-15).
func Test_group_closure(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		c := e.adA
		e.hStructure(t, c)
		gA, gB, gC, gD := hGUID(2, 1), hGUID(2, 2), hGUID(2, 3), hGUID(2, 4)
		u1, u2, u3, u4 := hGUID(1, 1), hGUID(1, 2), hGUID(1, 3), hGUID(1, 4)
		at := hBase.Add(time.Hour)
		user := func(g, sam string, rid uint32, primary string) inventory.Observation {
			return hUser{guid: g, sam: sam, rid: rid, uac: i64(uacNormal), read: 15, primary: primary}.obs()
		}
		// A holds B and C and u1; B holds D and u2; C holds D (a diamond); D holds u3 and A (a cycle);
		// u4 has D as its primary group.
		obs := []inventory.Observation{
			user(u1, "u1", 1101, ""), user(u2, "u2", 1102, ""), user(u3, "u3", 1103, ""), user(u4, "u4", 1104, gD),
			hGroup(gA, "A", 2001, gB, gC, u1), hGroup(gB, "B", 2002, gD, u2), hGroup(gC, "C", 2003, gD), hGroup(gD, "D", 2004, u3, gA),
		}
		if _, err := e.populate(t, c, at, obs...); err != nil {
			t.Fatal(err)
		}
		wantRows(t, "A", e.closureRows(t, c, gA),
			gB+" direct 1 []", gC+" direct 1 []", gD+" nested 2 ["+gB+"]", u1+" direct 1 []", u2+" nested 2 ["+gB+"]",
			u3+" nested 3 ["+gB+","+gD+"]", u4+" nested 3 ["+gB+","+gD+"]", gA+" cycle 3 ["+gB+","+gD+"]")
		wantRows(t, "D", e.closureRows(t, c, gD),
			gA+" direct 1 []", gB+" nested 2 ["+gA+"]", gC+" nested 2 ["+gA+"]", gD+" cycle 3 ["+gA+","+gB+"]",
			u1+" nested 2 ["+gA+"]", u2+" nested 3 ["+gA+","+gB+"]", u3+" direct 1 []", u4+" primary_group 1 []")

		// C stops holding D: A still reaches D through B, C holds nothing.
		obs2 := []inventory.Observation{hGroup(gC, "C", 2003)}
		if _, err := e.populate(t, c, at.Add(time.Minute), obs2...); err != nil {
			t.Fatal(err)
		}
		wantRows(t, "C after removal", e.closureRows(t, c, gC))
		wantRows(t, "A after removal", e.closureRows(t, c, gA),
			gB+" direct 1 []", gC+" direct 1 []", gD+" nested 2 ["+gB+"]", u1+" direct 1 []", u2+" nested 2 ["+gB+"]",
			u3+" nested 3 ["+gB+","+gD+"]", u4+" nested 3 ["+gB+","+gD+"]", gA+" cycle 3 ["+gB+","+gD+"]")

		// D is deleted: no group reaches through it, and its own rows are gone.
		del := hGroup(gD, "D", 2004, u3, gA)
		del.State = inventory.ObjDeleted
		if _, err := e.populate(t, c, at.Add(2*time.Minute), del); err != nil {
			t.Fatal(err)
		}
		wantRows(t, "D deleted", e.closureRows(t, c, gD))
		wantRows(t, "A with D deleted", e.closureRows(t, c, gA),
			gB+" direct 1 []", gC+" direct 1 []", gD+" nested 2 ["+gB+"]", u1+" direct 1 []", u2+" nested 2 ["+gB+"]")
		wantRows(t, "B with D deleted", e.closureRows(t, c, gB), gD+" direct 1 []", u2+" direct 1 []")

		// u4 moves to another primary group: D's row for u4 is replaced.
		obs4 := []inventory.Observation{user(u4, "u4", 1104, gC)}
		if _, err := e.populate(t, c, at.Add(3*time.Minute), obs4...); err != nil {
			t.Fatal(err)
		}
		wantRows(t, "C primary", e.closureRows(t, c, gC), u4+" primary_group 1 []")
		wantRows(t, "A sees u4 via C", e.closureRows(t, c, gA),
			gB+" direct 1 []", gC+" direct 1 []", gD+" nested 2 ["+gB+"]", u1+" direct 1 []", u2+" nested 2 ["+gB+"]", u4+" nested 2 ["+gC+"]")
		if n := e.count(t, `SELECT count(*) FROM public.inventory_group_closure_dirty`); n != 0 {
			t.Errorf("%d groups still marked dirty after Populate", n)
		}
	})
}

// A group that contains itself is a cycle finding of depth 1.
func Test_group_closure_self_loop(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		c := e.adA
		e.hStructure(t, c)
		g := hGUID(2, 1)
		if _, err := e.populate(t, c, hBase.Add(time.Hour), hGroup(g, "Self", 2001, g)); err != nil {
			t.Fatal(err)
		}
		wantRows(t, "self", e.closureRows(t, c, g), g+" cycle 1 []")
	})
}

// A chain of groups deeper than the closure follows must not stop the sync: Populate succeeds, the walk
// stops at 128 levels, and the group_members dataset and the groups dataset say that members beyond are
// not listed. Whoever can build such a chain must not be able to freeze the inventory.
func Test_group_closure_deep_chain_is_a_finding_not_a_failure(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		const n = 130
		var chain []inventory.Observation
		for i := 1; i <= n; i++ {
			var members []string
			if i < n {
				members = []string{hGUID(3, i+1)}
			}
			chain = append(chain, hGroup(hGUID(3, i), fmt.Sprintf("N%d", i), uint32(3000+i), members...))
		}
		if _, err := e.populate(t, c, hBase.Add(2*time.Hour), chain...); err != nil {
			t.Fatalf("a %d-level chain must not fail the sync: %v", n, err)
		}
		if got := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid`, hGUID(3, 1)); got != 128 {
			t.Errorf("the head holds %d closure rows, want 128 (N2..N129)", got)
		}
		if got := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND cut`, hGUID(3, 1)); got != 1 {
			t.Errorf("the head has %d cut rows, want 1", got)
		}
		if got := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE cut`); got != 1 {
			t.Errorf("%d cut rows in all, want 1 (N2 reaches N130, which has no members: nothing hidden)", got)
		}
		if got := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND member_guid = $2::uuid`, hGUID(3, 1), hGUID(3, 130)); got != 0 {
			t.Errorf("the head lists the member at level 129")
		}
		now := hBase.Add(24 * time.Hour)
		gm := e.run(t, reg, hQuery{dataset: inventory.DatasetGroupMembers, cols: gmCols, scope: e.scopeNC(c), now: now})
		finding := cellStr(gm.rows[strings.ToLower(hGUID(3, 1)+"|"+hGUID(3, 129))], "finding")
		if want := "Nesting deeper than 128 levels: members of N129 and below are not listed"; finding != want {
			t.Errorf("finding = %q, want %q", finding, want)
		}
		groups := e.run(t, reg, hQuery{dataset: inventory.DatasetGroups, cols: []report.ColumnID{"sam_account_name", "nesting_cut"}, scope: e.scopeNC(c), now: now})
		for i, want := range map[int]string{1: "true", 2: "false", 129: "false"} {
			if got := cellStr(groups.rows[strings.ToLower(hGUID(3, i))], "nesting_cut"); got != want {
				t.Errorf("N%d nesting_cut = %q, want %q", i, got, want)
			}
		}
	})
}
