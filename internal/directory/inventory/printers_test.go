package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

var printerCols = []report.ColumnID{"object_guid", "domain", "dn", "printer_name", "server_name", "unc_name", "share_name", "location",
	"description", "driver_name", "color", "duplex", "when_created", "observed_at"}

// printerWorld seeds two print servers in different containers (hOU and hSys), one printer with every
// attribute, one with none, and one on the second server. The comma and the accent are the nasty DN case.
func printerWorld(e *env, c inventory.ConnectionID) (obs []inventory.Observation, p1, p2, p3 string) {
	srv1, srv2 := hGUID(5, 1), hGUID(5, 2)
	p1, p2, p3 = hGUID(6, 1), hGUID(6, 2), hGUID(6, 3)
	comp := func(g, name, parent string) inventory.Observation {
		o := hUser{guid: g, sam: name + "$", rid: 3000, uac: i64(4096), read: 15, pwdLastSet: hBase, kind: inventory.KindComputer, class: "computer", parent: parent}.obs()
		if parent == hSys {
			o.DN, o.RDN = "CN="+name+",CN=System,DC=example,DC=test", "CN="+name
		} else {
			o.DN, o.RDN = "CN="+name+",OU=People,DC=example,DC=test", "CN="+name
		}
		return o
	}
	pq := func(g, rdn, srv string, srvDN string, parent string, anc []inventory.GUID, attrs map[string]any) inventory.Observation {
		return inventory.Observation{Object: inventory.GUID(g), NC: inventory.GUID(hDom), Kind: inventory.KindPrintQueue, Class: "printQueue",
			State: inventory.ObjLive, Parent: inventory.GUID(srv), Ancestry: anc, DN: "CN=" + rdn + "," + srvDN, RDN: "CN=" + rdn,
			WhenCreated: hBase.Add(-48 * time.Hour), Attributes: attrs}
	}
	s1, s2 := comp(srv1, "PRINT1", hOU), comp(srv2, "PRINT2", hSys)
	anc1 := []inventory.GUID{inventory.GUID(srv1), inventory.GUID(hOU), inventory.GUID(hDom)}
	anc2 := []inventory.GUID{inventory.GUID(srv2), inventory.GUID(hSys), inventory.GUID(hDom)}
	obs = []inventory.Observation{s1, s2,
		pq(p1, `PRINT1-Ünï\, Floor 2`, srv1, s1.DN, srv1, anc1, map[string]any{"printerName": "Ünï, Floor 2", "serverName": "print1.example.test",
			"uNCName": `\\print1.example.test\floor2`, "printShareName": "floor2", "location": "HQ/2/East", "description": "Colour laser",
			"driverName": "HP Universal", "printColor": true, "printDuplexSupported": false}),
		pq(p2, "PRINT1-bare", srv1, s1.DN, srv1, anc1, nil),
		pq(p3, "PRINT2-lab", srv2, s2.DN, srv2, anc2, map[string]any{"printerName": "lab", "serverName": "print2.example.test", "printColor": false}),
	}
	return
}

// T-1719 AC1: one row per printQueue, each column equals the synced attribute, an attribute that was not read
// is an empty cell, and the server's OU ancestry is in the dn.
func Test_printers_ground_truth(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		obs, p1, p2, p3 := printerWorld(e, e.adA)
		if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetPrinters, cols: printerCols, scope: e.scopeNC(e.adA), now: hBase.Add(time.Hour)})
		if len(res.rows) != 3 || res.count != 3 {
			t.Fatalf("rows = %d, count = %d, want 3 (the two servers are computers, not printers)", len(res.rows), res.count)
		}
		want := map[string]string{"printer_name": "Ünï, Floor 2", "server_name": "print1.example.test", "unc_name": `\\print1.example.test\floor2`,
			"share_name": "floor2", "location": "HQ/2/East", "description": "Colour laser", "driver_name": "HP Universal", "color": "true", "duplex": "false"}
		r := res.rows[p1]
		for c, w := range want {
			if got := cellStr(r, report.ColumnID(c)); got != w {
				t.Errorf("%s.%s = %q, want %q", p1, c, got, w)
			}
		}
		if got := cellStr(r, "dn"); !strings.HasSuffix(got, `,CN=PRINT1,OU=People,DC=example,DC=test`) || !strings.HasPrefix(got, `CN=PRINT1-Ünï\, Floor 2,`) {
			t.Errorf("dn = %q, want the queue under its server under the server's OU path", got)
		}
		if got := cellStr(res.rows[p3], "dn"); !strings.HasSuffix(got, `,CN=PRINT2,CN=System,DC=example,DC=test`) {
			t.Errorf("second server's printer dn = %q", got)
		}
		for _, c := range printerCols[3:12] {
			if got := cellStr(res.rows[p2], c); got != "" {
				t.Errorf("bare printer %s = %q, want an empty cell", c, got)
			}
		}
		if got := cellStr(res.rows[p3], "color"); got != "false" {
			t.Errorf("lab color = %q, want false (an explicit false is not an absent value)", got)
		}
		if got := cellStr(r, "domain"); !strings.EqualFold(got, hDom) {
			t.Errorf("domain = %q, want %s", got, hDom)
		}
		if cellKey(r["observed_at"]) == "" || cellKey(r["when_created"]) == "" || cellStr(r, "when_created") == "" {
			t.Errorf("created %q / observed %q", cellKey(r["when_created"]), cellKey(r["observed_at"]))
		}
		if cellStr(r, "observed_at") == "" {
			t.Errorf("no observed_at")
		}
	})
}

// T-1719 AC2: a printer is trimmed by its server's ancestry; a printer whose server is not in the inventory has
// an unknown ancestry and grants nothing, even to a scope that holds the whole naming context's OU.
func Test_printers_trimmed_by_server_ancestry(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		obs, p1, p2, _ := printerWorld(e, e.adA)
		orphan := hGUID(6, 9)
		obs = append(obs, inventory.Observation{Object: inventory.GUID(orphan), NC: inventory.GUID(hDom), Kind: inventory.KindPrintQueue, Class: "printQueue",
			State: inventory.ObjLive, Parent: inventory.GUID(hGUID(5, 99)), DN: "CN=orphan,CN=GONE,OU=People,DC=example,DC=test", RDN: "CN=orphan"})
		if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		q := func(scopeOU bool) hResult {
			sc := e.scopeNC(e.adA)
			if scopeOU {
				sc = e.scopeOU(e.adA)
			}
			return e.run(t, reg, hQuery{dataset: inventory.DatasetPrinters, cols: printerCols, scope: sc, now: hBase.Add(time.Hour)})
		}
		in := q(true)
		if len(in.rows) != 2 || in.rows[p1] == nil || in.rows[p2] == nil || in.rows[hGUID(6, 3)] != nil || in.rows[orphan] != nil {
			t.Errorf("OU scope sees %v, want the two printers of the server under the OU and nothing else", in.order)
		}
		if in.count != 2 {
			t.Errorf("OU scope count = %d, want 2 (the count is trimmed too)", in.count)
		}
		if all := q(false); all.rows[orphan] != nil {
			t.Errorf("a printer with an unknown ancestry is shown to the whole-NC scope")
		}
	})
}

// T-1719 AC3: a directory with no printQueue objects gives zero rows and a zero count; the as-of is the sync's.
func Test_printers_none_published(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		u := hUser{guid: hGUID(1, 1), sam: "alice", rid: 1100, uac: i64(uacNormal), read: 15, pwdLastSet: hBase}
		if _, err := e.populate(t, e.adA, hBase, u.obs()); err != nil {
			t.Fatal(err)
		}
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetPrinters, cols: printerCols, scope: e.scopeNC(e.adA), now: hBase.Add(time.Hour)})
		if len(res.rows) != 0 || res.count != 0 {
			t.Fatalf("rows = %d, count = %d, want none", len(res.rows), res.count)
		}
	})
}

// The dataset registers no secret and no binary column.
func Test_printers_columns_carry_no_secret(t *testing.T) {
	for _, d := range inventory.Datasets() {
		if d.ID != inventory.DatasetPrinters {
			continue
		}
		for _, c := range d.Columns {
			if j, ok := c.Source.(report.JSONAttr); ok && inventory.SecretKey(j.Key) {
				t.Errorf("column %s reads the secret key %s", c.ID, j.Key)
			}
		}
		return
	}
	t.Fatal("inventory.printers is not registered")
}

// T-1719: migration 0082 over a populated database. A printQueue stored as "other" before it is left alone (the
// resync reclassifies it), incremental cursors go to resync_required with no cookie, and the kind is accepted.
func Test_migration_0082_admits_printqueue_and_requires_a_resync(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		const mig = "0082_inventory_printqueue_kind.sql"
		e := setupFS(t, s, migrationsFS(t, func(n string) bool { return n < mig || strings.HasSuffix(n, clusterSPNMigSuffix) }))
		e.hStructure(t, e.adA)
		old := inventory.Observation{Object: inventory.GUID(hGUID(6, 1)), NC: inventory.GUID(hDom), Kind: inventory.KindOther, Class: "printQueue",
			State: inventory.ObjLive, Parent: inventory.GUID(hOU), Ancestry: []inventory.GUID{inventory.GUID(hOU), inventory.GUID(hDom)},
			DN: "CN=old,OU=People,DC=example,DC=test", RDN: "CN=old"}
		if _, err := e.populate(t, e.adA, hBase, old); err != nil {
			t.Fatal(err)
		}
		if err := e.exec(e.a, `INSERT INTO public.sync_cursors (tenant_id, connection_id, partition, state, lease_fencing_token, cookie, last_full_sync_at)
			SELECT tenant_id, id, $1, 'incremental', 1, '\x01', now() FROM public.connections WHERE id = $2::uuid`, hGUID(0xa1, 1), string(e.adA)); err != nil {
			t.Fatal(err)
		}
		before := e.ownerRun(t, e.a, `SELECT md5(string_agg(d::text, '|' ORDER BY object_guid)) FROM public.directory_objects d`)
		if err := e.d.Apply(context.Background(), migrationsFS(t, func(n string) bool { return n == mig })); err != nil {
			t.Fatal(err)
		}
		if got := e.ownerRun(t, e.a, `SELECT state || ':' || (cookie IS NULL)::text FROM public.sync_cursors`); fmt.Sprint(got) != "[resync_required:true]" {
			t.Errorf("cursor = %v", got)
		}
		if after := e.ownerRun(t, e.a, `SELECT md5(string_agg(d::text, '|' ORDER BY object_guid)) FROM public.directory_objects d`); after[0] != before[0] {
			t.Error("the migration changed inventory rows")
		}
		moved := old
		moved.Kind = inventory.KindPrintQueue
		if _, err := e.populate(t, e.adA, hBase.Add(time.Hour), moved); err != nil {
			t.Fatalf("a printqueue row after the migration: %v", err)
		}
	})
}
