package inventory_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// requireStoredDecisionIsFromScratch is the invariant of the closure budget: the groups the table holds as
// over_budget are exactly the groups a fresh decision on the current links leaves out (history never matters),
// and every other live group is expanded or empty.
func (e *env) requireStoredDecisionIsFromScratch(t *testing.T, c inventory.ConnectionID, when string) {
	t.Helper()
	var admitted, over []string
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
		admitted, over, err = inventory.DecideClosure(ctx, tx, c)
		return
	}); err != nil {
		t.Fatal(err)
	}
	for i := range over {
		over[i] = strings.ToLower(over[i])
	}
	slices.Sort(over)
	got := e.overBudgetGroups(t)
	if !slices.Equal(got, over) {
		t.Errorf("%s: stored over-budget groups %v differ from a from-scratch decision %v", when, got, over)
	}
	for _, g := range admitted {
		if e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND edge_kind = 'over_budget'`, g) != 0 {
			t.Errorf("%s: %s is admitted by the decision but holds a marker", when, g)
		}
	}
}

// Security review of T-0961 (displacement): someone who fills the connection budget before joining a
// privileged group must not make that group's membership read "too large to list" at the moment they join.
// Run with a well-known privileged group (RID 512) and an ordinary small group (RID 5555): both are listed
// after the attacker joins, the stored decision equals a from-scratch one after every refresh, and a
// one-member change to the large group is still fast.
func Test_group_closure_no_displacement(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		defer inventory.SetClosureBudget(1000, 2500)()
		e := setup(t, s)
		c := e.adA
		e.hStructure(t, c)
		da, ops, big := hGUID(2, 9), hGUID(2, 8), hGUID(2, 1)
		var batch []inventory.Observation
		var members []string
		for i := 1; i <= 600; i++ {
			g := hGUID(1, i)
			batch = append(batch, hUser{guid: g, sam: fmt.Sprintf("u%05d", i), rid: uint32(10000 + i), uac: i64(uacNormal), read: 15}.obs())
			members = append(members, g)
		}
		admin1, admin2, attacker := hGUID(1, 9001), hGUID(1, 9002), hGUID(1, 9003)
		for i, g := range []string{admin1, admin2, attacker} {
			batch = append(batch, hUser{guid: g, sam: fmt.Sprintf("adm%d", i), rid: uint32(19000 + i), uac: i64(uacNormal), read: 15}.obs())
		}
		step := 0
		next := func(obs ...inventory.Observation) time.Duration {
			step++
			start := time.Now()
			if _, err := e.populate(t, c, hBase.Add(time.Duration(step)*time.Hour), obs...); err != nil {
				t.Fatal(err)
			}
			took := time.Since(start)
			e.requireStoredDecisionIsFromScratch(t, c, fmt.Sprintf("after step %d", step))
			return took
		}
		next(batch...)
		next(hGroup(da, "DomainAdmins", 512, admin1, admin2), hGroup(ops, "Ops", 5555, admin1, admin2), hGroup(big, "Big", 2001, members...))
		// The attacker nests Big into three groups they own and adds 120 one-member filler groups.
		var atk []inventory.Observation
		for j := 1; j <= 3; j++ {
			atk = append(atk, hGroup(hGUID(3, j), fmt.Sprintf("att%02d", j), uint32(3000+j), big))
		}
		next(atk...)
		var fill []inventory.Observation
		for j := 1; j <= 120; j++ {
			fill = append(fill, hGroup(hGUID(4, j), fmt.Sprintf("fill%03d", j), uint32(4000+j), attacker))
		}
		next(fill...)
		// Then they join the privileged group and the ordinary one.
		next(hGroup(da, "DomainAdmins", 512, admin1, admin2, attacker), hGroup(ops, "Ops", 5555, admin1, admin2, attacker))
		for _, g := range []string{da, ops} {
			if over := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND edge_kind = 'over_budget'`, g); over != 0 {
				t.Errorf("%s reads 'Membership too large to list' after a member joined", g)
			}
			if rows := e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE group_guid = $1::uuid AND edge_kind = 'direct'`, g); rows != 3 {
				t.Errorf("%s lists %d members, want 3", g, rows)
			}
		}
		if rows := e.count(t, `SELECT count(*) FROM public.inventory_group_members`); rows > 2500+200 {
			t.Errorf("%d closure rows exceed the connection budget plus markers", rows)
		}
		// A one-member change to the large group: fast, and the decision is still the from-scratch one.
		took := next(hUser{guid: hGUID(1, 601), sam: "newcomer", rid: 20001, uac: i64(uacNormal), read: 15}.obs(),
			hGroup(big, "Big", 2001, append(members, hGUID(1, 601))...))
		t.Logf("one-member change to the large group: %v", took)
		if took > 5*time.Second {
			t.Errorf("a one-member change took %v at a 2,500-row budget, want under 5 s", took)
		}
		// Privileged members leave: Domain Admins is emptied; still decided from the graph.
		next(hGroup(da, "DomainAdmins", 512))
	})
}
