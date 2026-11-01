package inventory_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// Security review 3 of T-0961, at the database level in a small form: a hub group holds w groups and k
// groups hold the hub. The refresh must succeed within a stated time, the stored decision must equal a
// from-scratch one after every refresh, the rows must stay within the connection budget, and the
// privileged group must be listed whatever the fan-out. The unit test (closure_budget_internal_test.go)
// measures the decision's work at 4,000 + 4,000 groups.
func Test_group_closure_hub_fan_is_bounded(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		const k, w, rootBudget, connBudget = 300, 300, 1000, 2500
		defer inventory.SetClosureBudget(rootBudget, connBudget)()
		e := setup(t, s)
		c := e.adA
		e.hStructure(t, c)
		hub, da := hGUID(2, 1), hGUID(2, 9)
		admins := []string{hGUID(1, 1), hGUID(1, 2), hGUID(1, 3)}
		var users []inventory.Observation
		for i, u := range admins {
			users = append(users, hUser{guid: u, sam: fmt.Sprintf("adm%d", i), rid: uint32(19000 + i), uac: i64(uacNormal), read: 15}.obs())
		}
		if _, err := e.populate(t, c, hBase.Add(time.Hour), users...); err != nil {
			t.Fatal(err)
		}
		var leaves []string
		var batch []inventory.Observation
		for i := 0; i < w; i++ {
			g := hGUID(3, i+1)
			leaves = append(leaves, g)
			batch = append(batch, hGroup(g, fmt.Sprintf("leaf%04d", i), uint32(30000+i)))
		}
		for i := 0; i < k; i++ {
			batch = append(batch, hGroup(hGUID(4, i+1), fmt.Sprintf("top%04d", i), uint32(40000+i), hub))
		}
		batch = append(batch, hGroup(hub, "Hub", 2001, leaves...), hGroup(da, "DomainAdmins", 512, admins...))
		start := time.Now()
		if _, err := e.populate(t, c, hBase.Add(2*time.Hour), batch...); err != nil {
			t.Fatalf("a hub fan must not fail the sync: %v", err)
		}
		t.Logf("%d + %d groups: populate %v", k, w, time.Since(start))
		e.requireStoredDecisionIsFromScratch(t, c, "after the fan was built")
		if rows := e.count(t, `SELECT count(*) FROM public.inventory_group_members`); rows > connBudget+k+w+2 {
			t.Errorf("%d closure rows exceed the connection budget %d (+ one marker per group)", rows, connBudget)
		}
		if marker, direct := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND edge_kind = 'over_budget'`, da),
			e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND edge_kind = 'direct'`, da); marker != 0 || direct != 3 {
			t.Errorf("Domain Admins: markers %d, direct rows %d; want 0 and 3", marker, direct)
		}
		if n := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND edge_kind = 'direct'`, hub); n != w {
			t.Errorf("hub lists %d members, want %d", n, w)
		}

		// One more group in the hub dirties every top group: a refresh within a stated time, same invariant.
		extra := hGUID(3, w+1)
		start = time.Now()
		if _, err := e.populate(t, c, hBase.Add(3*time.Hour), hGroup(extra, "leafX", 30999), hGroup(hub, "Hub", 2001, append(leaves, extra)...)); err != nil {
			t.Fatal(err)
		}
		took := time.Since(start)
		t.Logf("one change to the hub: %v", took)
		if took > 10*time.Second {
			t.Errorf("a one-group change to the hub took %v, want under 10 s", took)
		}
		e.requireStoredDecisionIsFromScratch(t, c, "after the hub changed")
		if n := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND edge_kind = 'direct'`, da); n != 3 {
			t.Errorf("Domain Admins lists %d members after the hub changed, want 3", n)
		}
	})
}
