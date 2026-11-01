package inventory_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// hBuiltinSID is S-1-5-32-<rid>, binary.
func hBuiltinSID(rid uint32) []byte {
	b := []byte{1, 2, 0, 0, 0, 0, 0, 5}
	for _, v := range []uint32{32, rid} {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}

// Test_live_groups_privileged_classification pins the SQL that decides which groups are the well-known
// privileged ones: domain RIDs 512, 516, 518, 519 and BUILTIN 544, 548-551 - and nothing near them.
func Test_live_groups_privileged_classification(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		c := e.adA
		e.hStructure(t, c)
		type g struct {
			name string
			obs  inventory.Observation
			want bool
		}
		var groups []g
		i := 0
		domain := func(rid uint32, want bool) {
			i++
			groups = append(groups, g{fmt.Sprintf("domain-%d", rid), hGroup(hGUID(5, i), fmt.Sprintf("d%d", rid), rid), want})
		}
		builtin := func(rid uint32, want bool) {
			i++
			o := hGroup(hGUID(5, i), fmt.Sprintf("b%d", rid), 1)
			o.SID = hBuiltinSID(rid)
			groups = append(groups, g{fmt.Sprintf("builtin-%d", rid), o, want})
		}
		for _, rid := range []uint32{512, 516, 518, 519} {
			domain(rid, true)
		}
		for _, rid := range []uint32{513, 520, 1512, 5120, 51, 5512} {
			domain(rid, false)
		}
		for _, rid := range []uint32{544, 548, 549, 550, 551} {
			builtin(rid, true)
		}
		for _, rid := range []uint32{545, 546, 547, 552, 5440} {
			builtin(rid, false)
		}
		var obs []inventory.Observation
		for _, x := range groups {
			obs = append(obs, x.obs)
		}
		if _, err := e.populate(t, c, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		var got map[string]bool
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
			got, err = inventory.LivePrivileged(ctx, tx, c)
			return
		}); err != nil {
			t.Fatal(err)
		}
		for _, x := range groups {
			guid := strings.ToLower(string(x.obs.Object))
			if got[guid] != x.want {
				t.Errorf("%s: privileged = %v, want %v", x.name, got[guid], x.want)
			}
		}
	})
}

// Test_group_closure_privileged_first_under_exhaustion: with the connection budget used up by 1-link
// filler groups that sort before the privileged group (smaller estimate and lower GUID), the RID-512 group
// is still listed, while an ordinary group of the same size (RID 5555, lower GUID than DA) is not. With
// privilege detection off, smallest-first alone would leave Domain Admins out.
func Test_group_closure_privileged_first_under_exhaustion(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		defer inventory.SetClosureBudget(100, 10)()
		e := setup(t, s)
		c := e.adA
		e.hStructure(t, c)
		da, ops := hGUID(2, 9), hGUID(2, 8)
		a1, a2, a3 := hGUID(1, 9001), hGUID(1, 9002), hGUID(1, 9003)
		var batch []inventory.Observation
		for k, u := range []string{a1, a2, a3} {
			batch = append(batch, hUser{guid: u, sam: fmt.Sprintf("adm%d", k), rid: uint32(19000 + k), uac: i64(uacNormal), read: 15}.obs())
		}
		batch = append(batch, hGroup(da, "DomainAdmins", 512, a1, a2, a3), hGroup(ops, "Ops", 5555, a1, a2, a3))
		for j := 1; j <= 12; j++ {
			batch = append(batch, hGroup(hGUID(1, j), fmt.Sprintf("fill%02d", j), uint32(4000+j), a1))
		}
		if _, err := e.populate(t, c, hBase, batch...); err != nil {
			t.Fatal(err)
		}
		e.requireStoredDecisionIsFromScratch(t, c, "exhausted budget")
		marker := func(g string) int {
			return e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND edge_kind = 'over_budget'`, g)
		}
		direct := func(g string) int {
			return e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND edge_kind = 'direct'`, g)
		}
		if marker(da) != 0 || direct(da) != 3 {
			t.Errorf("Domain Admins (RID 512): markers %d, direct rows %d; want 0 and 3", marker(da), direct(da))
		}
		if marker(ops) != 1 || direct(ops) != 0 {
			t.Errorf("ordinary group (RID 5555): markers %d, direct rows %d; want 1 and 0 (budget exhausted)", marker(ops), direct(ops))
		}
	})
}
