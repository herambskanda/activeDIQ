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
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// RP11 (reports contract §3.3): a dataset run under a scope reveals no name, GUID or aggregate of an
// object outside it. One run per registered dataset; the subtest is named by the dataset ID, which the
// fitness job reads. This file covers the datasets of the inventory package (B3: users, computers; B6: groups, group members, OUs, contacts).

const sentinel = "SENTINEL"

// sentinelGUID is a GUID no in-scope cell may hold.
func sentinelGUID(i int) string { return hGUID(0xee, i) }

func columnIDs(ds report.Dataset) []report.ColumnID {
	var out []report.ColumnID
	for _, c := range ds.Columns {
		out = append(out, c.ID)
	}
	return out
}

func scopeOf(c inventory.ConnectionID, roots ...string) authz.ReadScope {
	var terms []authz.ScopeTerm
	for _, r := range roots {
		terms = append(terms, authz.ScopeTerm{Kind: authz.TermSubtree, Connection: rpID(string(c)), Root: rpID(r)})
	}
	return authztest.ReadScope(authz.ScopeGrant{Include: terms})
}

// parentOUs are the out-of-scope ancestors an in-scope object's own DN names. They carry the sentinel,
// so any cell that shows one is visible to leaks. Reports contract §3.3 "DN disclosure rule": the
// sentinel may appear only inside the dn cell of the row's own object.
const parentOUs = "OU=" + sentinel + "-OU-child,OU=" + sentinel + "-OU-parent,DC=example,DC=test"

// realDN is an in-scope object's own DN with its real, out-of-scope parents.
func realDN(name string) string { return "CN=" + name + "," + parentOUs }

// dnColumn is the one column that renders an object's own DN.
const dnColumn report.ColumnID = "dn"

// leaks lists the cells that hold a sentinel name or GUID. ownDN maps a lower-case row GUID to the DN
// of that object. The dn cell of a row is allowed to hold exactly that DN and nothing else; every other
// cell of every row, and the dn cell of any other value, must be free of the sentinel.
func leaks(res hResult, ownDN map[string]string) []string {
	return leaksWhere(res, func(rowKey string, col report.ColumnID, v string) bool {
		return col == dnColumn && v == strings.ToLower(ownDN[rowKey]) && v != ""
	})
}

// leaksWhere is leaks with the allowance as a function: allowed(rowKey, column, lower-cased text) says
// whether a text cell may hold the sentinel because it is the own DN of an object the row is about.
func leaksWhere(res hResult, allowed func(rowKey string, col report.ColumnID, v string) bool) []string {
	var out []string
	for k, row := range res.rows {
		if strings.HasPrefix(strings.ToLower(k), "ee000000-") {
			out = append(out, "row key "+k)
		}
		for col, cell := range row {
			v := strings.ToLower(string(cell.DigestValue()))
			if cell.Tag() == "s" && allowed(k, col, v) {
				continue
			}
			if strings.Contains(v, strings.ToLower(sentinel)) || strings.Contains(v, "ee000000-0000-4000") {
				out = append(out, fmt.Sprintf("%s.%s = %s", k, col, v))
			}
		}
	}
	return out
}

// checkNoLeaks fails on a leak and then proves the check itself: a copy of the result in which a second
// column (and a second row's dn) carries the parent OU name must be caught.
func checkNoLeaks(t *testing.T, res hResult, ownDN map[string]string) {
	t.Helper()
	if l := leaks(res, ownDN); len(l) > 0 {
		t.Errorf("the run reveals objects outside the scope:\n  %s", strings.Join(l, "\n  "))
	}
	if _, ok := res.rows[firstKey(res)][dnColumn]; !ok {
		t.Fatalf("the dn column is not in the run: the DN rule is untested")
	}
	for _, c := range []struct {
		name   string
		mutate func(rows map[string]map[report.ColumnID]report.Cell, k string)
	}{
		{"parent name in another column", func(r map[string]map[report.ColumnID]report.Cell, k string) {
			r[k]["ou_path"] = report.TextCell(parentOUs)
		}},
		{"parent name in the dn of a second column", func(r map[string]map[report.ColumnID]report.Cell, k string) {
			r[k]["parent_dn"] = r[k][dnColumn]
		}},
		{"another object's dn in the dn cell", func(r map[string]map[report.ColumnID]report.Cell, k string) {
			r[k][dnColumn] = report.TextCell(realDN("someone-else"))
		}},
	} {
		m := hResult{rows: map[string]map[report.ColumnID]report.Cell{}}
		for k, row := range res.rows {
			m.rows[k] = map[report.ColumnID]report.Cell{}
			for col, cell := range row {
				m.rows[k][col] = cell
			}
		}
		c.mutate(m.rows, firstKey(m))
		if len(leaks(m, ownDN)) == 0 {
			t.Errorf("mutation %q is not caught by RP11", c.name)
		}
	}
}

func firstKey(res hResult) string {
	var keys []string
	for k := range res.rows {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys[0]
}

func Test_dataset_reveals_nothing_outside_scope(t *testing.T) {
	for _, src := range inventory.Datasets() {
		t.Run(string(src.ID), func(t *testing.T) {
			storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
				e := setup(t, s)
				reg := e.registry(t)
				c := e.adA
				e.hStructure(t, c)
				now := hBase.Add(100 * 24 * time.Hour)
				at := now.Add(-time.Hour)
				cols := columnIDs(src)
				switch src.ID {
				case inventory.DatasetUsers:
					rpUsers(t, e, reg, c, cols, now, at)
				case inventory.DatasetComputers:
					rpComputers(t, e, reg, c, cols, now, at)
				case inventory.DatasetGroups:
					rpGroups(t, e, reg, c, cols, now, at)
				case inventory.DatasetGroupMembers:
					rpGroupMembers(t, e, reg, c, cols, now, at)
				case inventory.DatasetOUs:
					rpOUs(t, e, reg, c, cols, now, at)
				case inventory.DatasetContacts:
					rpContacts(t, e, reg, c, cols, now, at)
				default:
					t.Fatalf("no RP11 world for %s", src.ID)
				}
			})
		})
	}
}

func rpUsers(t *testing.T, e *env, reg *reportsql.Registry, c inventory.ConnectionID, cols []report.ColumnID, now, at time.Time) {
	base1, base2 := hGUID(1, 1), hGUID(1, 2)
	mk := func(guid, sam string, rid uint32, mod func(*hUser)) inventory.Observation {
		u := hUser{guid: guid, sam: sam, rid: rid, uac: i64(uacNormal), read: 15, pwdLastSet: now.Add(-20 * 24 * time.Hour), spn: new(bool)}
		if mod != nil {
			mod(&u)
		}
		o := u.obs()
		if !strings.HasPrefix(sam, sentinel) {
			o.DN = realDN(sam) // the real DN names the out-of-scope parent OUs (§3.3 DN disclosure rule)
			o.RDN = "CN=" + sam
		}
		o.DisplayName, o.UPN = sam+" Display", sam+"@example.test"
		return o
	}
	psoName := sentinel + "-PSO"
	obs := []inventory.Observation{
		mk(base1, "base-one", 1101, func(u *hUser) { u.primary = hGUID(2, 2) }),
		mk(base2, "base-two", 1102, nil),
		// out of scope: other users in the same OU, groups, the PSOs
		mk(sentinelGUID(1), sentinel+"-user-1", 1201, nil),
		mk(sentinelGUID(2), sentinel+"-user-2", 1202, func(u *hUser) { u.lockout = now.Add(-time.Minute) }),
		hGroup(hGUID(2, 1), sentinel+"-group-outer", 2001, hGUID(2, 2)),
		hGroup(hGUID(2, 2), sentinel+"-group-inner", 2002, base1, base2, sentinelGUID(1)),
		hPSOObj(sentinelGUID(10), psoName),
		hPSOObj(sentinelGUID(11), psoName+"-direct"),
	}
	if _, err := e.populate(t, c, at, obs...); err != nil {
		t.Fatal(err)
	}
	e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
		step := at.Add(time.Second)
		if err := pw.SetDomainPolicy(ctx, tx, c, inventory.GUID(hDom), inventory.DomainPolicy{MaxPwdAge: days(42), LockoutDuration: mins(30), PSOsReadAt: at}, step); err != nil {
			return err
		}
		for _, p := range []struct {
			guid   string
			prec   int64
			target string
		}{{sentinelGUID(10), 2, hGUID(2, 1)}, {sentinelGUID(11), 1, base2}} {
			if err := pw.SetPSO(ctx, tx, c, inventory.GUID(p.guid), inventory.GUID(hDom), inventory.PSO{Precedence: i64(p.prec), MaxPwdAge: days(10), LockoutDuration: mins(5)}, step); err != nil {
				return err
			}
			if err := pw.SetPSOApplies(ctx, tx, c, inventory.GUID(p.guid), inventory.GUID(p.target), step); err != nil {
				return err
			}
		}
		return nil
	})
	q := func(roots ...string) hResult {
		return e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: cols, scope: scopeOf(c, roots...), now: now})
	}
	res := q(base1, base2)
	if len(res.rows) != 2 || res.count != 2 {
		t.Fatalf("rows = %d, count = %d, want 2 and 2", len(res.rows), res.count)
	}
	checkNoLeaks(t, res, map[string]string{strings.ToLower(base1): realDN("base-one"), strings.ToLower(base2): realDN("base-two")})
	for g, name := range map[string]string{base1: "base-one", base2: "base-two"} {
		if got := cellKey(res.rows[strings.ToLower(g)][dnColumn]); got != "s:"+realDN(name) {
			t.Errorf("%s dn = %s, want its own real DN", g, got)
		}
	}
	// the policy still applies to the in-scope users, its identity does not show
	for g, want := range map[string]string{base1: "(policy outside your scope)", base2: "(policy outside your scope)"} {
		row := res.rows[strings.ToLower(g)]
		if got := cellKey(row["policy_source"]); got != "s:"+want {
			t.Errorf("%s policy_source = %s, want %s", g, got, want)
		}
		if got := cellKey(row["password_state"]); got != "e:expired" {
			t.Errorf("%s password_state = %s, want expired (the PSO's values apply)", g, got)
		}
	}

	// positive control: the same run with the PSOs in scope names them
	res = q(base1, base2, sentinelGUID(10), sentinelGUID(11))
	if len(res.rows) != 2 {
		t.Fatalf("rows with the PSOs in scope = %d, want 2", len(res.rows))
	}
	for g, want := range map[string]string{base1: psoName, base2: psoName + "-direct"} {
		if got := cellKey(res.rows[strings.ToLower(g)]["policy_source"]); got != "s:"+want {
			t.Errorf("%s policy_source with the PSO in scope = %s, want %s", g, got, want)
		}
	}
}

func rpComputers(t *testing.T, e *env, reg *reportsql.Registry, c inventory.ConnectionID, cols []report.ColumnID, now, at time.Time) {
	mk := func(guid, sam string, rid uint32) inventory.Observation {
		o := hUser{guid: guid, sam: sam, rid: rid, uac: i64(uacWks), read: 15, kind: inventory.KindComputer, class: "computer"}.obs()
		o.Attributes = map[string]any{"dNSHostName": strings.ToLower(sam) + ".example.test", "operatingSystem": "Windows Server 2022"}
		if !strings.HasPrefix(sam, sentinel) {
			o.DN, o.RDN = realDN(sam), "CN="+sam
		}
		return o
	}
	base := hGUID(4, 1)
	obs := []inventory.Observation{
		mk(base, "BASE-PC$", 3001),
		mk(sentinelGUID(1), sentinel+"-PC1$", 3002),
		mk(sentinelGUID(2), sentinel+"-PC2$", 3003),
		hGroup(hGUID(2, 1), sentinel+"-group", 2001, base, sentinelGUID(1)),
	}
	if _, err := e.populate(t, c, at, obs...); err != nil {
		t.Fatal(err)
	}
	res := e.run(t, reg, hQuery{dataset: inventory.DatasetComputers, cols: cols, scope: scopeOf(c, base), now: now})
	if len(res.rows) != 1 || res.count != 1 {
		t.Fatalf("rows = %d, count = %d, want 1 and 1", len(res.rows), res.count)
	}
	checkNoLeaks(t, res, map[string]string{strings.ToLower(base): realDN("BASE-PC$")})
	if got := cellKey(res.rows[strings.ToLower(base)][dnColumn]); got != "s:"+realDN("BASE-PC$") {
		t.Errorf("dn = %s, want its own real DN", got)
	}
	if got := cellKey(res.rows[strings.ToLower(base)]["dns_host_name"]); got != "s:base-pc$.example.test" {
		t.Errorf("dns_host_name = %s", got)
	}
}

// named gives an in-scope object its real DN (with the out-of-scope parent OUs, §3.3 DN disclosure rule)
// and an out-of-scope one a sentinel name.
func named(o inventory.Observation, name string) inventory.Observation {
	if !strings.HasPrefix(name, sentinel) {
		o.DN, o.RDN = realDN(name), "CN="+name
	}
	return o
}

// aggregate checks the Count columns of a row against the value computed from the model with the
// out-of-scope objects deleted.
func aggregate(t *testing.T, ds report.Dataset, row map[report.ColumnID]report.Cell, want map[report.ColumnID]string) {
	t.Helper()
	counts := 0
	for _, c := range ds.Columns {
		if !c.Count {
			continue
		}
		counts++
		w, ok := want[c.ID]
		if !ok {
			t.Errorf("no expected value for the aggregate column %s", c.ID)
			continue
		}
		if got := cellStr(row, c.ID); got != w {
			t.Errorf("%s.%s = %s, want %s (the count of in-scope objects)", ds.ID, c.ID, got, w)
		}
	}
	if counts != len(want) {
		t.Errorf("%s has %d aggregate columns, the test expects %d", ds.ID, counts, len(want))
	}
}

func dsOf(id report.DatasetID) report.Dataset {
	i := slices.IndexFunc(inventory.Datasets(), func(d report.Dataset) bool { return d.ID == id })
	return inventory.Datasets()[i]
}

func rpGroups(t *testing.T, e *env, reg *reportsql.Registry, c inventory.ConnectionID, cols []report.ColumnID, now, at time.Time) {
	baseG, baseU, baseU2 := hGUID(2, 1), hGUID(1, 1), hGUID(1, 2)
	sentG, sentU, sentU2, outside := sentinelGUID(1), sentinelGUID(2), sentinelGUID(3), hGUID(7, 1)
	mu := func(g, sam string, rid uint32) inventory.Observation {
		return named(hUser{guid: g, sam: sam, rid: rid, uac: i64(uacNormal), read: 15}.obs(), sam)
	}
	g1 := named(hGroup(baseG, "base-group", 2001, baseU, sentU, sentG, outside), "base-group")
	g1.Attributes = map[string]any{"managedBy": "CN=" + sentinel + "-manager,DC=example,DC=test"}
	gt := int32(-2147483646)
	g1.Facts.GroupType = &gt
	obs := []inventory.Observation{mu(baseU, "base-user", 1101), mu(baseU2, "base-user-2", 1102), mu(sentU, sentinel+"-user", 1201), mu(sentU2, sentinel+"-user-2", 1202),
		g1, hGroup(sentG, sentinel+"-group", 2002, sentU2, baseU2)}
	if _, err := e.populate(t, c, at, obs...); err != nil {
		t.Fatal(err)
	}
	res := e.run(t, reg, hQuery{dataset: inventory.DatasetGroups, cols: cols, scope: scopeOf(c, baseG, baseU, baseU2), now: now})
	if len(res.rows) != 1 || res.count != 1 {
		t.Fatalf("rows = %d, count = %d, want 1 and 1", len(res.rows), res.count)
	}
	checkNoLeaks(t, res, map[string]string{strings.ToLower(baseG): realDN("base-group")})
	row := res.rows[baseG]
	// direct: the base user only; effective adds base-user-2, who is reached through the out-of-scope group
	aggregate(t, dsOf(inventory.DatasetGroups), row, map[report.ColumnID]string{"direct_members": "1", "effective_members": "2", "primary_group_members": "0"})
	for col, want := range map[report.ColumnID]string{"managed_by": "(manager outside your scope)", "has_manager": "true", "group_type": "security", "group_scope": "global",
		"includes_members_outside_inventory": "true", "has_members": "true"} {
		if got := cellStr(row, col); got != want {
			t.Errorf("%s = %q, want %q", col, got, want)
		}
	}
}

func rpGroupMembers(t *testing.T, e *env, reg *reportsql.Registry, c inventory.ConnectionID, cols []report.ColumnID, now, at time.Time) {
	baseG, baseU := hGUID(2, 1), hGUID(1, 1)
	sentG, sentU := sentinelGUID(1), sentinelGUID(2)
	obs := []inventory.Observation{named(hUser{guid: baseU, sam: "base-user", rid: 1101, uac: i64(uacNormal), read: 15}.obs(), "base-user"),
		mu2(sentU, sentinel+"-user", 1201), named(hGroup(baseG, "base-group", 2001, sentG, sentU), "base-group"), hGroup(sentG, sentinel+"-group", 2002, baseU, baseG)}
	if _, err := e.populate(t, c, at, obs...); err != nil {
		t.Fatal(err)
	}
	res := e.run(t, reg, hQuery{dataset: inventory.DatasetGroupMembers, cols: cols, scope: scopeOf(c, baseG, baseU), now: now})
	// base-group holds base-user through the out-of-scope group, and itself again through the loop
	if len(res.rows) != 2 || res.count != 2 {
		t.Fatalf("rows = %d, count = %d, want 2 and 2 (the member and the cycle finding)", len(res.rows), res.count)
	}
	// A group_members row is about two objects, both in scope; group_dn and member_dn each render one of
	// them (§3.3 DN disclosure rule, applied to both own-object DN columns). Nothing else may.
	ownDN := map[string]string{strings.ToLower(baseG): realDN("base-group"), strings.ToLower(baseU): realDN("base-user")}
	gmAllowed := func(rowKey string, col report.ColumnID, v string) bool {
		g, m, _ := strings.Cut(rowKey, "|")
		switch col {
		case "group_dn":
			return v == strings.ToLower(ownDN[g])
		case "member_dn":
			return v == strings.ToLower(ownDN[m])
		}
		return false
	}
	if l := leaksWhere(res, gmAllowed); len(l) > 0 {
		t.Errorf("the run reveals objects outside the scope:\n  %s", strings.Join(l, "\n  "))
	}
	for _, c := range []struct {
		name string
		col  report.ColumnID
		val  string
	}{{"another object's DN in group_dn", "group_dn", realDN("someone-else")}, {"parent name in via_path", "via_path", parentOUs}, {"swapped DN in member_dn", "member_dn", realDN("base-group")}} {
		m := hResult{rows: map[string]map[report.ColumnID]report.Cell{}}
		for k, row := range res.rows {
			m.rows[k] = map[report.ColumnID]report.Cell{}
			for col, cell := range row {
				m.rows[k][col] = cell
			}
		}
		k := baseG + "|" + baseU
		m.rows[strings.ToLower(k)][c.col] = report.TextCell(c.val)
		if len(leaksWhere(m, gmAllowed)) == 0 {
			t.Errorf("mutation %q is not caught by RP11", c.name)
		}
	}
	for key, want := range map[string]string{baseG + "|" + baseU: "(group outside your scope)", baseG + "|" + baseG: "(group outside your scope)"} {
		row := res.rows[strings.ToLower(key)]
		if got := cellStr(row, "via_path"); got != want {
			t.Errorf("%s via_path = %q, want %q", key, got, want)
		}
	}
	if got := cellStr(res.rows[strings.ToLower(baseG+"|"+baseG)], "finding"); got != "Circular nesting: base-group → (group outside your scope) → base-group" {
		t.Errorf("finding = %q", got)
	}
	// positive control: with the hop in scope its name shows
	res = e.run(t, reg, hQuery{dataset: inventory.DatasetGroupMembers, cols: cols, scope: scopeOf(c, baseG, baseU, sentG), now: now})
	if got := cellStr(res.rows[strings.ToLower(baseG+"|"+baseU)], "via_path"); got != sentinel+"-group" {
		t.Errorf("via_path with the hop in scope = %q, want its name", got)
	}
}

func mu2(g, sam string, rid uint32) inventory.Observation {
	return hUser{guid: g, sam: sam, rid: rid, uac: i64(uacNormal), read: 15}.obs()
}

func rpOUs(t *testing.T, e *env, reg *reportsql.Registry, c inventory.ConnectionID, cols []report.ColumnID, now, at time.Time) {
	base, hidden := hGUID(6, 1), sentinelGUID(1)
	chainB := []string{base, hOU, hDom}
	chainH := []string{hidden, base, hOU, hDom}
	u := func(g, sam string, rid uint32, parent string, chain []string) inventory.Observation {
		return e.under(named(hUser{guid: g, sam: sam, rid: rid, uac: i64(uacNormal), read: 15}.obs(), sam), parent, chain...)
	}
	hiddenOU := e.under(ouObs(hidden, sentinel+"-ou", base), base, chainB...)
	obs := []inventory.Observation{named(ouObs(base, "base-ou", hOU, hOU, hDom), "base-ou"), hiddenOU,
		u(hGUID(1, 1), "base-user", 1101, base, chainB), u(sentinelGUID(2), sentinel+"-user", 1201, hidden, chainH), u(sentinelGUID(3), sentinel+"-user-2", 1202, hidden, chainH),
		e.under(hGroup(sentinelGUID(4), sentinel+"-group", 2001), hidden, chainH...)}
	obs[0].DN, obs[0].RDN = "OU=base-ou,"+parentOUs, "OU=base-ou"
	if _, err := e.populate(t, c, at, obs...); err != nil {
		t.Fatal(err)
	}
	scope := authztest.ReadScope(authz.ScopeGrant{
		Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: rpID(string(c)), Root: rpID(base)}},
		Exclude: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: rpID(string(c)), Root: rpID(hidden)}}})
	res := e.run(t, reg, hQuery{dataset: inventory.DatasetOUs, cols: cols, scope: scope, now: now})
	if len(res.rows) != 1 || res.count != 1 {
		t.Fatalf("rows = %d, count = %d, want 1 and 1", len(res.rows), res.count)
	}
	checkNoLeaks(t, res, map[string]string{strings.ToLower(base): "OU=base-ou," + parentOUs})
	aggregate(t, dsOf(inventory.DatasetOUs), res.rows[base], map[report.ColumnID]string{"subtree_objects": "1", "subtree_users": "1", "subtree_computers": "0",
		"subtree_groups": "0", "subtree_contacts": "0", "subtree_ous": "0", "child_objects": "1"})
}

func rpContacts(t *testing.T, e *env, reg *reportsql.Registry, c inventory.ConnectionID, cols []report.ColumnID, now, at time.Time) {
	mk := func(g, name string) inventory.Observation {
		return named(inventory.Observation{Object: inventory.GUID(g), NC: inventory.GUID(hDom), Kind: inventory.KindContact, Class: "contact", State: inventory.ObjLive,
			Parent: inventory.GUID(hOU), Ancestry: []inventory.GUID{inventory.GUID(hOU), inventory.GUID(hDom)}, DisplayName: name,
			Attributes: map[string]any{"mail": strings.ToLower(name) + "@example.test"}}, name)
	}
	base := hGUID(8, 1)
	if _, err := e.populate(t, c, at, mk(base, "base-contact"), mk(sentinelGUID(1), sentinel+"-contact")); err != nil {
		t.Fatal(err)
	}
	res := e.run(t, reg, hQuery{dataset: inventory.DatasetContacts, cols: cols, scope: scopeOf(c, base), now: now})
	if len(res.rows) != 1 || res.count != 1 {
		t.Fatalf("rows = %d, count = %d, want 1 and 1", len(res.rows), res.count)
	}
	checkNoLeaks(t, res, map[string]string{strings.ToLower(base): realDN("base-contact")})
	if got := cellStr(res.rows[base], "mail"); got != "base-contact@example.test" {
		t.Errorf("mail = %q", got)
	}
}
