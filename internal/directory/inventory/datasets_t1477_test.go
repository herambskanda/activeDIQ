package inventory_test

import (
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func Test_IsClusterSPN(t *testing.T) {
	for _, c := range []struct {
		spns []string
		want bool
	}{
		{[]string{"MSClusterVirtualServer/CL01"}, true},
		{[]string{"HOST/x", "msservercluster/cl01.example.test"}, true},
		{[]string{"MSServerClusterMgmtAPI/node1"}, false},
		{[]string{"host/cluster01", "MSSQLSvc/cluster-sql:1433"}, false},
		{[]string{"MSClusterVirtualServer"}, false},
		{nil, false},
	} {
		if got := inventory.IsClusterSPN(c.spns); got != c.want {
			t.Errorf("IsClusterSPN(%q) = %v, want %v", c.spns, got, c.want)
		}
	}
}

// T-1477 acceptance 1 and 2: manager GUID and name under scope, OU path from ancestry.
func Test_users_manager_and_ou_path(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		l2, l3 := hGUID(7, 2), hGUID(7, 3)
		ou := func(g, parent, name string, anc ...string) inventory.Observation {
			o := inventory.Observation{Object: inventory.GUID(g), NC: inventory.GUID(hDom), Kind: inventory.KindOU, Class: "organizationalUnit", State: inventory.ObjLive,
				Parent: inventory.GUID(parent), RDN: "OU=" + name}
			for _, a := range anc {
				o.Ancestry = append(o.Ancestry, inventory.GUID(a))
			}
			return o
		}
		mk := func(u hUser, parent string, anc []string, dn string, attrs map[string]any) inventory.Observation {
			u.uac, u.read = i64(uacNormal), 15
			o := u.obs()
			o.Parent, o.DN, o.Attributes = inventory.GUID(parent), dn, attrs
			o.Ancestry = nil
			for _, a := range anc {
				o.Ancestry = append(o.Ancestry, inventory.GUID(a))
			}
			return o
		}
		mIn, mOut := hGUID(1, 10), hGUID(1, 11)
		deep := []string{l3, l2, hOU, hDom}
		obs := []inventory.Observation{
			ou(l2, hOU, "Sales EMEA", hOU, hDom), ou(l3, l2, "Berlin", l2, hOU, hDom),
			mk(hUser{guid: mIn, sam: "boss", rid: 1200}, hOU, []string{hOU, hDom}, "CN=Boss\\, B,OU=People,DC=example,DC=test", nil),
			mk(hUser{guid: mOut, sam: "outsider", rid: 1201}, hDom, []string{hDom}, "CN=Outsider,DC=example,DC=test", nil),
			mk(hUser{guid: hGUID(1, 1), sam: "withmgr", rid: 1210}, l3, deep, "CN=withmgr,OU=Berlin,DC=example,DC=test",
				map[string]any{"manager": "cn=boss\\, b,OU=People,DC=example,DC=test"}),
			mk(hUser{guid: hGUID(1, 2), sam: "nomgr", rid: 1211}, hOU, []string{hOU, hDom}, "CN=nomgr,OU=People,DC=example,DC=test", nil),
			mk(hUser{guid: hGUID(1, 3), sam: "outmgr", rid: 1212}, hOU, []string{hOU, hDom}, "CN=outmgr,OU=People,DC=example,DC=test",
				map[string]any{"manager": "CN=Outsider,DC=example,DC=test"}),
			mk(hUser{guid: hGUID(1, 4), sam: "ghostmgr", rid: 1213}, hOU, []string{hOU, hDom}, "CN=ghostmgr,OU=People,DC=example,DC=test",
				map[string]any{"manager": "CN=Nobody,DC=example,DC=test"}),
			mk(hUser{guid: hGUID(1, 5), sam: "rootuser", rid: 1214}, hDom, []string{hDom}, "CN=rootuser,DC=example,DC=test", nil),
		}
		if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		cols := []report.ColumnID{"sam_account_name", "manager_guid", "manager", "has_manager", "ou_path"}
		run := func(sc report.DatasetID) hResult { return hResult{} }
		_ = run
		for _, tc := range []struct {
			name string
			res  hResult
			chk  func(rows map[string]map[report.ColumnID]report.Cell)
		}{
			{"ou scope", e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: cols, scope: e.scopeOU(e.adA), now: hBase}), func(r map[string]map[report.ColumnID]report.Cell) {
				if _, ok := r[strings.ToLower(hGUID(1, 5))]; ok {
					t.Error("root user is outside the OU scope")
				}
				w := r[strings.ToLower(hGUID(1, 1))]
				if got := cellStr(w, "manager"); got != "boss" && !strings.Contains(got, "boss") {
					t.Errorf("in-scope manager name = %q", got)
				}
				if got := cellStr(w, "manager_guid"); !strings.EqualFold(got, mIn) {
					t.Errorf("manager_guid = %q, want %q", got, mIn)
				}
				if got := cellStr(w, "ou_path"); got != "People/Sales EMEA/Berlin" {
					t.Errorf("ou_path = %q", got)
				}
				o := r[strings.ToLower(hGUID(1, 3))]
				if got := cellStr(o, "manager"); got != "(manager outside your scope)" {
					t.Errorf("out-of-scope manager name = %q", got)
				}
				if got := cellStr(o, "manager_guid"); !strings.EqualFold(got, mOut) {
					t.Errorf("out-of-scope manager_guid = %q, want %q", got, mOut)
				}
				if got := cellStr(r[strings.ToLower(hGUID(1, 2))], "has_manager"); got != "false" {
					t.Errorf("has_manager = %q", got)
				}
				if got := cellStr(r[strings.ToLower(hGUID(1, 4))], "manager"); got != "(manager not in inventory)" {
					t.Errorf("ghost manager = %q", got)
				}
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				for k, r := range tc.res.rows {
					for _, c := range cols {
						t.Logf("%s %s = %s", k, c, cellKey(r[c]))
					}
				}
				tc.chk(tc.res.rows)
			})
		}
		// whole-NC scope: the root user has an empty chain
		all := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: cols, scope: e.scopeNC(e.adA), now: hBase})
		if got := cellStr(all.rows[strings.ToLower(hGUID(1, 5))], "ou_path"); got != "" {
			t.Errorf("root user ou_path = %q, want empty", got)
		}
		if got := cellStr(all.rows[strings.ToLower(hGUID(1, 3))], "manager"); got != "outsider" {
			t.Errorf("manager with scope admitting it = %q", got)
		}
	})
}

// T-1477 acceptance 3: cluster virtual objects are told by the stored SPN class, a plain computer with a
// similar SPN is not, and an unread SPN is unknown (NULL), never "not a cluster".
func Test_computers_cluster_object(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		yes, no := true, false
		mk := func(i int, name string, spns []string, read bool) inventory.Observation {
			o := inventory.Observation{Object: inventory.GUID(hGUID(2, i)), NC: inventory.GUID(hDom), Kind: inventory.KindComputer, Class: "computer", State: inventory.ObjLive,
				Parent: inventory.GUID(hOU), Ancestry: []inventory.GUID{inventory.GUID(hOU), inventory.GUID(hDom)}, DN: "CN=" + name + ",OU=People,DC=example,DC=test",
				RDN: "CN=" + name, SID: hSID(uint32(3000 + i)), SAMAccountName: name + "$", UserAccountControl: i64(4096), InputsRead: 15}
			if read {
				c := inventory.IsClusterSPN(spns)
				o.HasSPN, o.ClusterSPN = &yes, &c
				if len(spns) == 0 {
					o.HasSPN = &no
				}
			}
			return o
		}
		if _, err := e.populate(t, e.adA, hBase,
			mk(1, "CL01", []string{"HOST/CL01", "MSClusterVirtualServer/CL01.example.test"}, true),
			mk(2, "CL02", []string{"msservercluster/CL02"}, true),
			mk(3, "NODE1", []string{"MSServerClusterMgmtAPI/NODE1", "TERMSRV/NODE1"}, true),
			mk(4, "cluster01", []string{"host/cluster01", "MSSQLSvc/cluster-sql:1433"}, true),
			mk(5, "UNREAD", nil, false)); err != nil {
			t.Fatal(err)
		}
		cols := []report.ColumnID{"name", "cluster_object", "ou_path"}
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetComputers, cols: cols, scope: e.scopeNC(e.adA), now: hBase})
		want := map[int]string{1: "true", 2: "true", 3: "false", 4: "false"}
		for i, w := range want {
			if got := cellStr(res.rows[strings.ToLower(hGUID(2, i))], "cluster_object"); got != w {
				t.Errorf("computer %d cluster_object = %q, want %q", i, got, w)
			}
		}
		if c := res.rows[strings.ToLower(hGUID(2, 5))]["cluster_object"]; c.Tag() == "bool" && cellStr(res.rows[strings.ToLower(hGUID(2, 5))], "cluster_object") == "false" {
			t.Errorf("unread SPN must not read as a plain computer: %s", cellKey(c))
		}
		// the exclusion the report applies: cluster_object = false keeps the plain computers only
		ex := e.run(t, reg, hQuery{dataset: inventory.DatasetComputers, cols: cols, scope: e.scopeNC(e.adA), now: hBase,
			where: report.Cmp{Column: "cluster_object", Op: report.OpEq, Value: report.BoolV(false)}})
		if len(ex.rows) != 2 {
			t.Errorf("excluding clusters left %d rows, want 2 (NODE1, cluster01)", len(ex.rows))
		}
	})
}
