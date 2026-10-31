package inventory_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

var gmCols = []report.ColumnID{"group_name", "member_name", "member_kind", "edge_kind", "depth", "via_path", "finding", "member_enabled", "member_unresolved", "member_sid"}

func cellStr(r map[report.ColumnID]report.Cell, c report.ColumnID) string {
	s := cellKey(r[c])
	if i := strings.Index(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// fsp is a foreign security principal row: a member with no resolvable object.
func fsp(guid string, rid uint32) inventory.Observation {
	return inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(hDom), Kind: inventory.KindFSP, Class: "foreignSecurityPrincipal", State: inventory.ObjLive,
		Parent: inventory.GUID(hOU), Ancestry: []inventory.GUID{inventory.GUID(hOU), inventory.GUID(hDom)}, DN: "CN=fsp,OU=People,DC=example,DC=test", RDN: "CN=fsp", SID: hSID(rid)}
}

// The effective members of a group nested three levels deep with a cycle, a foreign security principal and a
// disabled member: each once, with its Via path, the cycle as a finding, and the principal unresolved
// (AC-20). The oracle is an independent walk over the model (the tokenGroups comparison needs the lab).
func Test_group_members_nested_cycle_fsp(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		gA, gB, gC := hGUID(2, 1), hGUID(2, 2), hGUID(2, 3)
		u1, u2, f := hGUID(1, 1), hGUID(1, 2), hGUID(5, 1)
		no := false
		dis := hUser{guid: u2, sam: "u2", rid: 1102, uac: i64(514), read: 15}.obs()
		dis.Enabled = &no
		direct := map[string][]string{gA: {gB, u1}, gB: {gC, u2}, gC: {gA, f}}
		obs := []inventory.Observation{hUser{guid: u1, sam: "u1", rid: 1101, uac: i64(uacNormal), read: 15}.obs(), dis, fsp(f, 9001),
			hGroup(gA, "A", 2001, direct[gA]...), hGroup(gB, "B", 2002, direct[gB]...), hGroup(gC, "C", 2003, direct[gC]...)}
		if _, err := e.populate(t, c, hBase.Add(time.Hour), obs...); err != nil {
			t.Fatal(err)
		}
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetGroupMembers, cols: gmCols, scope: e.scopeNC(c), now: hBase.Add(24 * time.Hour)})

		// oracle: every member reachable from each group, not counting a group as its own member unless it loops
		got := map[string]bool{}
		for k := range res.rows {
			got[k] = true
		}
		want := map[string]bool{}
		for _, g := range []string{gA, gB, gC} {
			seen, stack := map[string]bool{}, slices.Clone(direct[g])
			for len(stack) > 0 {
				m := stack[0]
				stack = stack[1:]
				if seen[m] {
					continue
				}
				seen[m] = true
				stack = append(stack, direct[m]...)
			}
			for m := range seen {
				want[strings.ToLower(g+"|"+m)] = true
			}
		}
		if !slices.Equal(sortedKeys(got), sortedKeys(want)) {
			t.Fatalf("effective members differ from the oracle:\n got  %v\n want %v", sortedKeys(got), sortedKeys(want))
		}
		if res.count != int64(len(want)) {
			t.Errorf("count = %d, want %d", res.count, len(want))
		}
		row := func(g, m string) map[report.ColumnID]report.Cell { return res.rows[strings.ToLower(g+"|"+m)] }
		for _, tc := range []struct{ g, m, col, want string }{
			{gA, u2, "via_path", "B"}, {gA, u2, "depth", "2"}, {gA, u2, "member_enabled", "false"}, {gA, u2, "edge_kind", "nested"},
			{gA, f, "via_path", "B → C"}, {gA, f, "member_name", "External principal (unresolved)"}, {gA, f, "member_unresolved", "true"},
			{gA, f, "member_sid", "S-1-5-21-1-2-3-9001"}, {gA, f, "member_kind", "fsp"},
			{gA, gA, "edge_kind", "cycle"}, {gA, gA, "finding", "Circular nesting: A → B → C → A"},
			{gB, gB, "finding", "Circular nesting: B → C → A → B"},
			{gA, u1, "edge_kind", "direct"}, {gA, u1, "via_path", ""}, {gA, gC, "via_path", "B"},
		} {
			if got := cellStr(row(tc.g, tc.m), report.ColumnID(tc.col)); got != tc.want && !(tc.want == "" && (got == "" || got == "<nil>")) {
				t.Errorf("(%s, %s).%s = %q, want %q", tc.g, tc.m, tc.col, got, tc.want)
			}
		}
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// A user whose primary group is not Domain Users shows it, and a group whose only members are
// primary-group users is not empty (AC-19). Ground truth is the model, not the dataset.
func Test_primary_group_user_and_group_without_member_values(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		gDU, gOnly, gEmpty, gOther := hGUID(2, 1), hGUID(2, 2), hGUID(2, 3), hGUID(2, 4)
		uA, uB, uC := hGUID(1, 1), hGUID(1, 2), hGUID(1, 3)
		mk := func(g, sam string, rid uint32, primary string) inventory.Observation {
			return hUser{guid: g, sam: sam, rid: rid, uac: i64(uacNormal), read: 15, primary: primary}.obs()
		}
		obs := []inventory.Observation{mk(uA, "alice", 1101, gOnly), mk(uB, "bob", 1102, gDU), mk(uC, "carol", 1103, gDU),
			hGroup(gDU, "Domain Users", 513), hGroup(gOnly, "Primary-only", 2002), hGroup(gEmpty, "Empty", 2003), hGroup(gOther, "Other", 2004, uB)}
		if _, err := e.populate(t, c, hBase.Add(time.Hour), obs...); err != nil {
			t.Fatal(err)
		}
		now := hBase.Add(24 * time.Hour)
		users := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: []report.ColumnID{"sam_account_name", "primary_group", "in_other_groups"}, scope: e.scopeNC(c), now: now})
		for g, want := range map[string][2]string{uA: {"Primary-only", "false"}, uB: {"Domain Users", "true"}, uC: {"Domain Users", "false"}} {
			r := users.rows[strings.ToLower(g)]
			if cellStr(r, "primary_group") != want[0] || cellStr(r, "in_other_groups") != want[1] {
				t.Errorf("%s: primary_group = %q, in_other_groups = %q, want %v", g, cellStr(r, "primary_group"), cellStr(r, "in_other_groups"), want)
			}
		}
		groups := e.run(t, reg, hQuery{dataset: inventory.DatasetGroups, cols: []report.ColumnID{"sam_account_name", "has_members", "direct_members", "effective_members", "primary_group_members"},
			scope: e.scopeNC(c), now: now})
		for g, want := range map[string][4]string{gOnly: {"true", "1", "1", "1"}, gEmpty: {"false", "0", "0", "0"}, gDU: {"true", "2", "2", "0"}, gOther: {"true", "1", "1", "0"}} {
			r := groups.rows[strings.ToLower(g)]
			got := [4]string{cellStr(r, "has_members"), cellStr(r, "direct_members"), cellStr(r, "effective_members"), cellStr(r, "primary_group_members")}
			if want[2] == "2" && g == gDU {
				want[3] = "2"
			}
			if got[0] != want[0] || got[1] != want[1] || got[2] != want[2] || got[3] != want[3] {
				t.Errorf("group %s: has/direct/effective/primary = %v, want %v", g, got, want)
			}
		}
	})
}

// Groups with 1,501 and 6,000 direct members count as many, with the measured times (AC-21).
func Test_group_member_counts_at_scale(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		const small, big = 1501, 6000
		var smallM, bigM []string
		var batch []inventory.Observation
		flush := func() {
			if len(batch) > 0 {
				if _, err := e.populate(t, c, hBase.Add(time.Hour), batch...); err != nil {
					t.Fatal(err)
				}
				batch = batch[:0]
			}
		}
		for i := 1; i <= big; i++ {
			g := hGUID(1, i)
			batch = append(batch, hUser{guid: g, sam: fmt.Sprintf("u%05d", i), rid: uint32(10000 + i), uac: i64(uacNormal), read: 15}.obs())
			if i <= small {
				smallM = append(smallM, g)
			}
			bigM = append(bigM, g)
			if len(batch) == 1000 {
				flush()
			}
		}
		flush()
		// Autovacuum would analyse the freshly loaded tables within minutes; the test database has no such
		// delay budget, and the app role may not ANALYZE tables it does not own. Without statistics the planner
		// believes the tables are empty and joins the closure to the objects with a nested loop over every row
		// (measured without: populate 40-45 s, the two counts 8-14 s; with: 6-7 s and 60-95 ms).
		if err := e.d.ExecOwner(context.Background(), "ANALYZE"); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := e.populate(t, c, hBase.Add(2*time.Hour), hGroup(hGUID(2, 1), "Small", 2001, smallM...), hGroup(hGUID(2, 2), "Big", 2002, bigM...)); err != nil {
			t.Fatal(err)
		}
		t.Logf("populate of the two groups (edges and closure refresh): %v", time.Since(start))
		truth := map[string]int{hGUID(2, 1): small, hGUID(2, 2): big}
		if err := e.d.ExecOwner(context.Background(), "ANALYZE"); err != nil {
			t.Fatal(err)
		}
		start = time.Now()
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetGroups, cols: []report.ColumnID{"direct_members", "effective_members"}, scope: e.scopeNC(c), now: hBase.Add(24 * time.Hour)})
		t.Logf("inventory.groups, both counts: %v", time.Since(start))
		for g, n := range truth {
			if d, ef := cellStr(res.rows[g], "direct_members"), cellStr(res.rows[g], "effective_members"); d != fmt.Sprint(n) || ef != fmt.Sprint(n) {
				t.Errorf("group %s: direct = %s, effective = %s, want %d", g, d, ef, n)
			}
			// ground truth straight from the links
			if got := e.count(t, `SELECT count(*) FROM public.links WHERE source_guid = $1::uuid AND link_attr = 'member' AND state = 'active'`, g); got != n {
				t.Errorf("links of %s = %d, want %d", g, got, n)
			}
		}
		start = time.Now()
		page := e.run(t, reg, hQuery{dataset: inventory.DatasetGroupMembers, cols: gmCols, scope: e.scopeNC(c), now: hBase.Add(24 * time.Hour), limit: 50,
			where: report.Cmp{Column: "group_name", Op: report.OpEq, Value: report.TextV("Big")}, sort: []report.SortKey{{Column: "member_name", Dir: report.Asc}}})
		t.Logf("first page of inventory.group_members for the 6,000-member group (%d rows, count %d): %v", len(page.rows), page.count, time.Since(start))
		if page.count != big || len(page.rows) != 50 {
			t.Errorf("group_members page: rows = %d, count = %d, want 50 and %d", len(page.rows), page.count, big)
		}
	})
}

func ouObs(guid, name, parent string, anc ...string) inventory.Observation {
	o := inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(hDom), Kind: inventory.KindOU, Class: "organizationalUnit", State: inventory.ObjLive,
		Parent: inventory.GUID(parent), DN: "OU=" + name + ",DC=example,DC=test", RDN: "OU=" + name}
	for _, a := range anc {
		o.Ancestry = append(o.Ancestry, inventory.GUID(a))
	}
	return o
}

func (e *env) under(o inventory.Observation, parent string, chain ...string) inventory.Observation {
	o.Parent = inventory.GUID(parent)
	o.Ancestry = nil
	for _, a := range chain {
		o.Ancestry = append(o.Ancestry, inventory.GUID(a))
	}
	return o
}

// subtree counts of an OU with objects partly out of scope count the in-scope objects only (AC-5).
func Test_ou_subtree_counts_in_scope_only(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		mixed, hidden := hGUID(6, 1), hGUID(6, 2)
		chainM := []string{mixed, hOU, hDom}
		chainH := []string{hidden, mixed, hOU, hDom}
		usr := func(g, sam string, rid uint32, parent string, chain []string) inventory.Observation {
			return e.under(hUser{guid: g, sam: sam, rid: rid, uac: i64(uacNormal), read: 15}.obs(), parent, chain...)
		}
		grp := e.under(hGroup(hGUID(2, 1), "in-group", 2001), mixed, chainM...)
		hiddenGrp := e.under(hGroup(hGUID(2, 2), "hidden-group", 2002), hidden, chainH...)
		obs := []inventory.Observation{
			ouObs(mixed, "Mixed", hOU, hOU, hDom), e.under(ouObs(hidden, "Hidden", mixed), mixed, chainM...),
			usr(hGUID(1, 1), "m1", 1101, mixed, chainM), usr(hGUID(1, 2), "m2", 1102, mixed, chainM),
			usr(hGUID(1, 3), "h1", 1103, hidden, chainH), usr(hGUID(1, 4), "h2", 1104, hidden, chainH), usr(hGUID(1, 5), "h3", 1105, hidden, chainH),
			grp, hiddenGrp,
		}
		if _, err := e.populate(t, c, hBase.Add(time.Hour), obs...); err != nil {
			t.Fatal(err)
		}
		cols := []report.ColumnID{"rdn", "subtree_objects", "subtree_users", "subtree_groups", "subtree_ous", "child_objects"}
		full := e.run(t, reg, hQuery{dataset: inventory.DatasetOUs, cols: cols, scope: e.scopeNC(c), now: hBase.Add(24 * time.Hour)})
		if got := fmt.Sprintf("%s %s %s", cellStr(full.rows[mixed], "subtree_users"), cellStr(full.rows[mixed], "subtree_objects"), cellStr(full.rows[mixed], "subtree_ous")); got != "5 8 1" {
			t.Fatalf("whole domain: users/objects/ous of Mixed = %s, want 5 8 1", got)
		}
		part := authztest.ReadScope(authz.ScopeGrant{
			Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: rpID(string(c)), Root: rpID(mixed)}},
			Exclude: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: rpID(string(c)), Root: rpID(hidden)}}})
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetOUs, cols: cols, scope: part, now: hBase.Add(24 * time.Hour)})
		if len(res.rows) != 1 {
			t.Fatalf("rows = %d, want only Mixed", len(res.rows))
		}
		r := res.rows[mixed]
		for col, want := range map[report.ColumnID]string{"subtree_users": "2", "subtree_groups": "1", "subtree_ous": "0", "subtree_objects": "3", "child_objects": "3"} {
			// child_objects: m1, m2, the group; the hidden OU is out of scope
			if got := cellStr(r, col); got != want {
				t.Errorf("Mixed.%s = %s, want %s", col, got, want)
			}
		}
	})
}
