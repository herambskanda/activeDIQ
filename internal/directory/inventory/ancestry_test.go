package inventory_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// forest builds AD observations whose chains follow their parents (nearest parent first), the way a
// connector reads them. The NC head is nc1 itself.
type forest struct{ chains map[string][]string }

func newForest() *forest { return &forest{chains: map[string][]string{nc1: nil}} }

var classes = map[inventory.Kind]string{inventory.KindOU: "organizationalUnit", inventory.KindUser: "user",
	inventory.KindGroup: "group", inventory.KindComputer: "computer"}

// at places g under parent with the parent's current chain in this forest.
func (f *forest) at(g string, k inventory.Kind, parent string) inventory.Observation {
	chain := append([]string{parent}, f.chains[parent]...)
	f.chains[g] = chain
	o := inventory.Observation{Object: inventory.GUID(g), NC: nc1, Kind: k, Class: classes[k], State: inventory.ObjLive,
		Parent: inventory.GUID(parent)}
	for _, c := range chain {
		o.Ancestry = append(o.Ancestry, inventory.GUID(c))
	}
	return o
}

func head() inventory.Observation {
	return inventory.Observation{Object: nc1, NC: nc1, Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive}
}

type row struct {
	Ancestry []string
	Complete bool
}

// rows reads every row of the connection as the tenant.
func (e *env) rows(t *testing.T, tid tenant.ID, c inventory.ConnectionID) map[string]row {
	t.Helper()
	out := map[string]row{}
	err := e.tx(t, tid, func(ctx context.Context, tx store.Tx) error {
		rs, err := tx.Query(ctx, `SELECT object_guid::text, ancestry::text[], ancestry_complete FROM public.directory_objects
			WHERE connection_id = $1::uuid`, string(c))
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var g string
			var r row
			if err := rs.Scan(&g, &r.Ancestry, &r.Complete); err != nil {
				return err
			}
			out[g] = r
		}
		return rs.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const (
	ouA   = "cccccccc-0000-4000-8000-00000000000a"
	ouB   = "cccccccc-0000-4000-8000-00000000000b"
	ouX   = "cccccccc-0000-4000-8000-0000000000e1"
	ouY   = "cccccccc-0000-4000-8000-0000000000e2"
	ouZ   = "cccccccc-0000-4000-8000-0000000000e3"
	uX    = "aaaaaaaa-0000-4000-8000-0000000000c1"
	gX    = "aaaaaaaa-0000-4000-8000-0000000000c2"
	cX    = "aaaaaaaa-0000-4000-8000-0000000000c3"
	uY    = "aaaaaaaa-0000-4000-8000-0000000000c4"
	gY    = "aaaaaaaa-0000-4000-8000-0000000000c5"
	cZ    = "aaaaaaaa-0000-4000-8000-0000000000c6"
	uZ    = "aaaaaaaa-0000-4000-8000-0000000000c7"
	noOne = "cccccccc-0000-4000-8000-0000000000ff" // a parent that is never synced
)

// subtree: X holds a user, a group, a computer and OU Y; Y holds a user, a group and OU Z; Z holds a
// computer and a user.
func (f *forest) subtree(parent string) []inventory.Observation {
	return []inventory.Observation{
		f.at(ouX, inventory.KindOU, parent),
		f.at(uX, inventory.KindUser, ouX), f.at(gX, inventory.KindGroup, ouX), f.at(cX, inventory.KindComputer, ouX),
		f.at(ouY, inventory.KindOU, ouX),
		f.at(uY, inventory.KindUser, ouY), f.at(gY, inventory.KindGroup, ouY),
		f.at(ouZ, inventory.KindOU, ouY),
		f.at(cZ, inventory.KindComputer, ouZ), f.at(uZ, inventory.KindUser, ouZ),
	}
}

var subtreeGUIDs = []string{ouX, uX, gX, cX, ouY, uY, gY, ouZ, cZ, uZ}

func wantRow(f *forest, g string) row { return row{Ancestry: f.chains[g], Complete: true} }

func TestMoveRewritesDescendantsAncestry(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		obs := []inventory.Observation{head(), f.at(ouA, inventory.KindOU, nc1), f.at(ouB, inventory.KindOU, ouA)}
		obs = append(obs, f.subtree(ouA)...)
		if _, err := e.populate(t, e.adA, t1, obs...); err != nil {
			t.Fatal(err)
		}
		before := e.rows(t, e.a, e.adA)
		for _, g := range subtreeGUIDs {
			if !reflect.DeepEqual(before[g], wantRow(f, g)) {
				t.Fatalf("before the move %s = %+v, want %+v", g, before[g], wantRow(f, g))
			}
		}
		t.Logf("before: uZ ancestry=%v complete=%v", before[uZ].Ancestry, before[uZ].Complete)

		// Move X from A to B, one level deeper: only X is observed; every descendant is rewritten.
		// Rebuilding the subtree in the forest gives the chains the directory would now hold.
		moved := f.subtree(ouB)[0]
		if _, err := e.populate(t, e.adA, t2, moved); err != nil {
			t.Fatal(err)
		}
		after := e.rows(t, e.a, e.adA)
		for _, g := range subtreeGUIDs {
			if !reflect.DeepEqual(after[g], wantRow(f, g)) {
				t.Errorf("after the move %s = %+v, want %+v", g, after[g], wantRow(f, g))
			}
		}
		t.Logf("after:  uZ ancestry=%v complete=%v", after[uZ].Ancestry, after[uZ].Complete)
		if got, want := after[uZ].Ancestry, []string{ouZ, ouY, ouX, ouB, ouA, nc1}; !reflect.DeepEqual(got, want) {
			t.Fatalf("uZ ancestry = %v, want %v", got, want)
		}
		// Rows outside the subtree are untouched.
		for _, g := range []string{nc1, ouA, ouB} {
			if !reflect.DeepEqual(after[g], before[g]) {
				t.Errorf("%s changed: %+v -> %+v", g, before[g], after[g])
			}
		}
	})
}

// A move out of one tree and back leaves the chain exactly as it started.
func TestMoveAndMoveBack(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		obs := []inventory.Observation{head(), f.at(ouA, inventory.KindOU, nc1), f.at(ouB, inventory.KindOU, nc1)}
		obs = append(obs, f.subtree(ouA)...)
		if _, err := e.populate(t, e.adA, t1, obs...); err != nil {
			t.Fatal(err)
		}
		before := e.rows(t, e.a, e.adA)
		g := newForest()
		g.chains = map[string][]string{nc1: nil, ouB: {nc1}, ouA: {nc1}}
		if _, err := e.populate(t, e.adA, t2, g.at(ouX, inventory.KindOU, ouB)); err != nil {
			t.Fatal(err)
		}
		if got := e.rows(t, e.a, e.adA)[uZ].Ancestry; !reflect.DeepEqual(got, []string{ouZ, ouY, ouX, ouB, nc1}) {
			t.Fatalf("uZ ancestry after the move = %v", got)
		}
		if _, err := e.populate(t, e.adA, t2.Add(1), g.at(ouX, inventory.KindOU, ouA)); err != nil {
			t.Fatal(err)
		}
		after := e.rows(t, e.a, e.adA)
		for k, v := range before {
			if !reflect.DeepEqual(after[k], v) {
				t.Errorf("%s: %+v -> %+v", k, v, after[k])
			}
		}
	})
}

// Acceptance 2: a move that fails part-way changes nothing. A trigger fails the rewrite at the deepest
// leaf, after the moved OU and the rows above it were already written in the transaction.
func TestMoveFailingPartWayRollsBack(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		obs := []inventory.Observation{head(), f.at(ouA, inventory.KindOU, nc1), f.at(ouB, inventory.KindOU, nc1)}
		obs = append(obs, f.subtree(ouA)...)
		if _, err := e.populate(t, e.adA, t1, obs...); err != nil {
			t.Fatal(err)
		}
		before := e.rows(t, e.a, e.adA)
		fault := fmt.Sprintf(`CREATE FUNCTION public.t0948_fault() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.object_guid = '%s' AND NEW.ancestry IS DISTINCT FROM OLD.ancestry THEN
					RAISE EXCEPTION 'injected fault' USING ERRCODE = 'AD500';
				END IF;
				RETURN NEW;
			END $$;
			CREATE TRIGGER t0948_fault BEFORE UPDATE ON public.directory_objects FOR EACH ROW EXECUTE FUNCTION public.t0948_fault()`, uZ)
		if err := e.d.ExecOwner(context.Background(), fault); err != nil {
			t.Fatal(err)
		}
		g := newForest()
		g.chains = map[string][]string{nc1: nil, ouB: {nc1}, ouA: {nc1}}
		_, err := e.populate(t, e.adA, t2, g.at(ouX, inventory.KindOU, ouB))
		if err == nil || !strings.Contains(err.Error(), "rewrite descendants") {
			t.Fatalf("move err = %v, want the descendant rewrite to fail", err)
		}
		after := e.rows(t, e.a, e.adA)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("a failed move changed rows:\nbefore %+v\nafter  %+v", before, after)
		}
		var parent string
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT parent_guid::text FROM public.directory_objects WHERE object_guid = $1::uuid`, ouX).Scan(&parent)
		}); err != nil || parent != ouA {
			t.Fatalf("moved OU parent = %q, %v; want %s", parent, err, ouA)
		}
	})
}

// A move that succeeds but whose transaction later rolls back changes nothing either.
func TestMoveRolledBackByCaller(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		obs := []inventory.Observation{head(), f.at(ouA, inventory.KindOU, nc1), f.at(ouB, inventory.KindOU, nc1)}
		obs = append(obs, f.subtree(ouA)...)
		if _, err := e.populate(t, e.adA, t1, obs...); err != nil {
			t.Fatal(err)
		}
		before := e.rows(t, e.a, e.adA)
		g := newForest()
		g.chains = map[string][]string{nc1: nil, ouB: {nc1}, ouA: {nc1}}
		boom := errors.New("boom")
		err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			if _, err := pop.Populate(ctx, tx, e.adA, t2, []inventory.Observation{g.at(ouX, inventory.KindOU, ouB)}); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
		if after := e.rows(t, e.a, e.adA); !reflect.DeepEqual(before, after) {
			t.Fatalf("a rolled-back move changed rows")
		}
	})
}

// Acceptance 3: a child whose parent is not synced is incomplete, in any order, and is repaired when
// the parent arrives, in the same call.
func TestIncompleteUntilParentArrives(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		// The head and OU X are not synced yet; everything under X is.
		a := f.at(ouA, inventory.KindOU, nc1)
		sub := f.subtree(ouA)
		xObs, rest := sub[0], sub[1:]
		if _, err := e.populate(t, e.adA, t1, rest...); err != nil {
			t.Fatal(err)
		}
		got := e.rows(t, e.a, e.adA)
		for _, g := range subtreeGUIDs[1:] {
			if got[g].Complete {
				t.Errorf("%s is complete before its parent chain is synced", g)
			}
			if !reflect.DeepEqual(got[g].Ancestry, f.chains[g]) {
				t.Errorf("%s chain = %v, want the observed %v", g, got[g].Ancestry, f.chains[g])
			}
		}
		// X arrives; its own parent A is still unknown, so X and everything below stay incomplete.
		if _, err := e.populate(t, e.adA, t1, xObs); err != nil {
			t.Fatal(err)
		}
		for g, r := range e.rows(t, e.a, e.adA) {
			if r.Complete {
				t.Errorf("%s complete while OU A is unsynced", g)
			}
		}
		// A arrives under the NC head: the whole subtree is repaired by that one call.
		if _, err := e.populate(t, e.adA, t1, a); err != nil {
			t.Fatal(err)
		}
		got = e.rows(t, e.a, e.adA)
		for _, g := range append([]string{ouA}, subtreeGUIDs...) {
			if !got[g].Complete {
				t.Errorf("%s still incomplete after its parents arrived", g)
			}
		}
	})
}

// The same repair within one batch, children listed before their parents.
func TestIncompleteRepairedWithinOneBatch(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		a := f.at(ouA, inventory.KindOU, nc1)
		sub := f.subtree(ouA)
		obs := []inventory.Observation{}
		for i := len(sub) - 1; i >= 0; i-- { // deepest first
			obs = append(obs, sub[i])
		}
		obs = append(obs, a, head())
		if _, err := e.populate(t, e.adA, t1, obs...); err != nil {
			t.Fatal(err)
		}
		for g, r := range e.rows(t, e.a, e.adA) {
			if !r.Complete {
				t.Errorf("%s incomplete after the whole batch", g)
			}
		}
	})
}

// Unknown or partial chains are never complete.
func TestAncestryCompleteness(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		a := f.at(ouA, inventory.KindOU, nc1)
		noChain := f.at(uX, inventory.KindUser, ouA)
		noChain.Ancestry = nil // parent known, chain not read
		partial := f.at(uY, inventory.KindUser, ouA)
		partial.Ancestry = partial.Ancestry[:1] // [A] without the NC head above it
		wrongParentFirst := f.at(uZ, inventory.KindUser, ouA)
		wrongParentFirst.Ancestry = []inventory.GUID{nc1, ouA}
		orphan := f.at(gX, inventory.KindGroup, noOne)
		if _, err := e.populate(t, e.adA, t1, head(), a, noChain, partial, wrongParentFirst, orphan); err != nil {
			t.Fatal(err)
		}
		got := e.rows(t, e.a, e.adA)
		for g, want := range map[string]bool{nc1: true, ouA: true, uX: false, uY: false, uZ: false, gX: false} {
			if got[g].Complete != want {
				t.Errorf("%s complete = %v, want %v", g, got[g].Complete, want)
			}
		}
		// A chain that holds the object itself, or repeats an ancestor, is refused.
		bad := f.at(cX, inventory.KindComputer, ouA)
		bad.Ancestry = append(bad.Ancestry, inventory.GUID(cX))
		dup := f.at(cZ, inventory.KindComputer, ouA)
		dup.Ancestry = append(dup.Ancestry, inventory.GUID(ouA))
		for _, o := range []inventory.Observation{bad, dup} {
			if _, err := e.populate(t, e.adA, t2, o); !errors.Is(err, inventory.ErrInvalid) {
				t.Errorf("cyclic chain err = %v, want ErrInvalid", err)
			}
		}
		// Entra objects carry no chain and are never complete.
		if _, err := e.populate(t, e.enA, t1, enUser(enG1, nil)); err != nil {
			t.Fatal(err)
		}
		if r := e.rows(t, e.a, e.enA)[enG1]; r.Complete {
			t.Errorf("an Entra row is complete: %+v", r)
		}
	})
}

// Moving under a parent whose chain is not complete makes the whole subtree incomplete, and it
// recovers when that parent is completed.
func TestMoveUnderIncompleteParent(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		obs := []inventory.Observation{head(), f.at(ouA, inventory.KindOU, nc1)}
		obs = append(obs, f.subtree(ouA)...)
		// B hangs under an unsynced parent: B is incomplete.
		b := f.at(ouB, inventory.KindOU, noOne)
		if _, err := e.populate(t, e.adA, t1, append(obs, b)...); err != nil {
			t.Fatal(err)
		}
		g := newForest()
		g.chains = map[string][]string{nc1: nil, ouB: f.chains[ouB]}
		if _, err := e.populate(t, e.adA, t2, g.at(ouX, inventory.KindOU, ouB)); err != nil {
			t.Fatal(err)
		}
		got := e.rows(t, e.a, e.adA)
		for _, k := range subtreeGUIDs {
			if got[k].Complete {
				t.Errorf("%s complete under an incomplete parent", k)
			}
		}
		// The missing parent arrives under the head. B's stored chain ([noOne]) is partial, so B and
		// the subtree stay incomplete until the pass that reads B again with the whole chain.
		np := f.at(noOne, inventory.KindOU, nc1)
		if _, err := e.populate(t, e.adA, t2.Add(1), np); err != nil {
			t.Fatal(err)
		}
		if got := e.rows(t, e.a, e.adA); got[ouB].Complete || got[ouX].Complete || !got[noOne].Complete {
			t.Fatalf("after the parent arrives: B %+v, X %+v, parent %+v", got[ouB], got[ouX], got[noOne])
		}
		if _, err := e.populate(t, e.adA, t2.Add(2), f.at(ouB, inventory.KindOU, noOne)); err != nil {
			t.Fatal(err)
		}
		got = e.rows(t, e.a, e.adA)
		if want := []string{noOne, nc1}; !reflect.DeepEqual(got[ouB].Ancestry, want) {
			t.Fatalf("B chain = %v", got[ouB].Ancestry)
		}
		if want := []string{ouZ, ouY, ouX, ouB, noOne, nc1}; !reflect.DeepEqual(got[uZ].Ancestry, want) {
			t.Fatalf("Z-level chain = %v", got[uZ].Ancestry)
		}
		for _, k := range append([]string{noOne}, subtreeGUIDs...) {
			if !got[k].Complete {
				t.Errorf("%s incomplete after B was read with its whole chain", k)
			}
		}
	})
}

// A deep tree: 100 nested OUs, a leaf at the bottom; moving the top under a 40-deep parent pushes the
// bottom past the 128-hop chain limit. Rows that still fit are rewritten; the rest are unknown, never stale.
func TestMoveDeepTree(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := newForest()
		obs := []inventory.Observation{head()}
		prev := nc1
		for i := 0; i < 40; i++ { // the new parent's branch: 40 deep
			g := guidN(1000 + i)
			obs = append(obs, f.at(g, inventory.KindOU, prev))
			prev = g
		}
		newParent := prev
		prev = nc1
		var deep []string
		for i := 0; i < 100; i++ { // the branch that moves: 100 deep
			g := guidN(2000 + i)
			obs = append(obs, f.at(g, inventory.KindOU, prev))
			deep = append(deep, g)
			prev = g
		}
		if _, err := e.populate(t, e.adA, t1, obs...); err != nil {
			t.Fatal(err)
		}
		for g, r := range e.rows(t, e.a, e.adA) {
			if !r.Complete {
				t.Fatalf("%s incomplete before the move", g)
			}
		}
		g := newForest()
		g.chains = map[string][]string{nc1: nil, newParent: f.chains[newParent]}
		// deep[0] is the top of the branch; it moves under newParent.
		if _, err := e.populate(t, e.adA, t2, g.at(deep[0], inventory.KindOU, newParent)); err != nil {
			t.Fatal(err)
		}
		got := e.rows(t, e.a, e.adA)
		// deep[i] has i branch members above it, then newParent (41 entries: itself, 39 above, the head).
		for i, d := range deep {
			want := i + 41
			if want > 128 {
				if got[d].Complete || len(got[d].Ancestry) != 0 {
					t.Errorf("deep[%d] = %+v, want an empty incomplete chain past the limit", i, got[d])
				}
				continue
			}
			if !got[d].Complete || len(got[d].Ancestry) != want {
				t.Errorf("deep[%d] complete=%v hops=%d, want complete with %d hops", i, got[d].Complete, len(got[d].Ancestry), want)
			}
		}
	})
}

// Acceptance 4: a move in one tenant leaves another tenant's rows alone, even with the same GUIDs, and
// another connection of the same tenant.
func TestMoveIsTenantScoped(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		build := func() ([]inventory.Observation, *forest) {
			f := newForest()
			obs := []inventory.Observation{head(), f.at(ouA, inventory.KindOU, nc1), f.at(ouB, inventory.KindOU, nc1)}
			return append(obs, f.subtree(ouA)...), f
		}
		obs, _ := build()
		for _, c := range []struct {
			tid tenant.ID
			c   inventory.ConnectionID
		}{{e.a, e.adA}, {e.b, e.adB}} {
			if err := e.tx(t, c.tid, func(ctx context.Context, tx store.Tx) error {
				_, err := pop.Populate(ctx, tx, c.c, t1, obs)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		// A second AD connection of tenant A with the same GUIDs.
		adA2 := e.conn(t, e.a, connection.KindADForest, connection.TransportLDAPS)
		if _, err := e.populate(t, adA2, t1, obs...); err != nil {
			t.Fatal(err)
		}
		otherB, otherA2 := e.rows(t, e.b, e.adB), e.rows(t, e.a, adA2)

		g := newForest()
		g.chains = map[string][]string{nc1: nil, ouB: {nc1}, ouA: {nc1}}
		if _, err := e.populate(t, e.adA, t2, g.at(ouX, inventory.KindOU, ouB)); err != nil {
			t.Fatal(err)
		}
		if got := e.rows(t, e.a, e.adA)[uZ].Ancestry; !reflect.DeepEqual(got, []string{ouZ, ouY, ouX, ouB, nc1}) {
			t.Fatalf("the moved tree = %v", got)
		}
		if !reflect.DeepEqual(otherB, e.rows(t, e.b, e.adB)) {
			t.Error("tenant B's rows changed")
		}
		if !reflect.DeepEqual(otherA2, e.rows(t, e.a, adA2)) {
			t.Error("tenant A's other connection changed")
		}
	})
}
