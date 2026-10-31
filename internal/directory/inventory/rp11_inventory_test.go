package inventory_test

import (
	"context"
	"fmt"
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
// fitness job reads. This file covers the datasets of the inventory package (B3: users, computers).

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

// leaks lists the cells that hold a sentinel name or GUID.
func leaks(res hResult) []string {
	var out []string
	for k, row := range res.rows {
		if strings.HasPrefix(strings.ToLower(k), "ee000000-") {
			out = append(out, "row key "+k)
		}
		for col, cell := range row {
			v := strings.ToLower(string(cell.DigestValue()))
			if strings.Contains(v, strings.ToLower(sentinel)) || strings.Contains(v, "ee000000-0000-4000") {
				out = append(out, fmt.Sprintf("%s.%s = %s", k, col, v))
			}
		}
	}
	return out
}

func Test_dataset_reveals_nothing_outside_scope(t *testing.T) {
	for _, src := range inventory.Datasets() {
		t.Run(string(src.ID), func(t *testing.T) {
			for _, c := range src.Columns {
				if c.Count {
					t.Fatalf("column %s is an aggregate: this test must compare it with the out-of-scope objects deleted", c.ID)
				}
			}
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
			o.DN = "CN=" + sam + ",DC=example,DC=test" // an in-scope object's own DN does not name its parents
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
	if l := leaks(res); len(l) > 0 {
		t.Errorf("the run reveals objects outside the scope:\n  %s", strings.Join(l, "\n  "))
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
			o.DN, o.RDN = "CN="+sam+",DC=example,DC=test", "CN="+sam
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
	if l := leaks(res); len(l) > 0 {
		t.Errorf("the run reveals objects outside the scope:\n  %s", strings.Join(l, "\n  "))
	}
	if got := cellKey(res.rows[strings.ToLower(base)]["dns_host_name"]); got != "s:base-pc$.example.test" {
		t.Errorf("dns_host_name = %s", got)
	}
}
