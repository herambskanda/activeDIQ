package sync_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// variant is a copy of a fake domain with the nodes drop names removed and the nodes in add appended: the
// directory some time after the one the inventory was read from.
func variant(d *fdom, drop func(fnode) bool, add ...fnode) *fdom {
	var ns []fnode
	for i := 0; i < d.count; i++ {
		if n := d.at(i); !drop(n) {
			ns = append(ns, n)
		}
	}
	ns = append(ns, add...)
	return &fdom{nc: d.nc, count: len(ns), sid: d.sid, at: func(i int) fnode { return ns[i] }}
}

func without(ids ...uint64) func(fnode) bool {
	set := map[uint64]bool{}
	for _, i := range ids {
		set[i] = true
	}
	return func(n fnode) bool { return set[n.n] }
}

// reconciling is a rig with the reconcile side wired: the real ingester, a fake that now serves later.
func (e *env) reconciling(t *testing.T, first *fakeConnector, ncs ...uint64) *rig {
	t.Helper()
	r := e.rig(t, first, ncs...)
	r.eng.Reconciler = dsync.NewIngester()
	return r
}

func (r *rig) reconcile(opts dsync.ReconcileOptions) (dsync.ReconcileReport, error) {
	return r.eng.Reconcile(context.Background(), r.e.a, connection.ID(r.e.conn), r.leases, opts)
}

// serve makes the rig read from a different (later) fake directory.
func (r *rig) serve(f *fakeConnector) {
	r.fake = f
	r.src.cc = f
}

func (e *env) states(t *testing.T) map[string]int {
	t.Helper()
	out := map[string]int{}
	err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT state, count(*) FROM public.directory_objects WHERE connection_id = $1::uuid GROUP BY state`, string(e.conn))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			var n int
			if err := rows.Scan(&s, &n); err != nil {
				return err
			}
			out[s] = n
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// usersOf lists n users of domain nc (build order, past the 10 fixed nodes).
func usersOf(f *forest, nc uint64, from, n int) []uint64 {
	var out []uint64
	for i := 0; i < n; i++ {
		out = append(out, nc+100+uint64(from+i))
	}
	return out
}

func TestMassDeleteShareIsTwentyPercent(t *testing.T) {
	if inventory.DefaultMassDeleteShare != 0.20 {
		t.Fatalf("DefaultMassDeleteShare = %v, want 0.20", inventory.DefaultMassDeleteShare)
	}
}

// TestReconcileRemovesTheDeleted is acceptance 1: 10 of the 1200 objects are gone from the directory; the
// reconcile deletes those 10 and leaves the other 1190 as they were (same rows, same observation time), and
// the live counts the reports read drop by 10. Their member edges go with them.
func TestReconcileRemovesTheDeleted(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		r := e.reconciling(t, newFake(fo.doms...), ncA, ncB)
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := e.states(t); got["live"] != 1200 {
			t.Fatalf("before: %v", got)
		}
		liveUsers := func() int {
			return e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid AND kind = 'user' AND state = 'live'`, string(e.conn))
		}
		usersBefore := liveUsers()
		// 7 members of the big group (and 7 primary-group edges), 3 users beyond it.
		gone := append(usersOf(fo, ncA, 0, 7), usersOf(fo, ncA, 610, 3)...)
		stamp := func() map[string]time.Time {
			m := map[string]time.Time{}
			err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
				rows, err := tx.Query(ctx, `SELECT object_guid::text, observed_at FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn))
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					var g string
					var at time.Time
					if err := rows.Scan(&g, &at); err != nil {
						return err
					}
					m[g] = at
				}
				return rows.Err()
			})
			if err != nil {
				t.Fatal(err)
			}
			return m
		}
		before := stamp()
		membersBefore := e.count(t, `SELECT count(*) FROM public.links WHERE connection_id = $1::uuid AND state = 'active'`, string(e.conn))

		r.serve(newFake(variant(fo.doms[0], without(gone...)), fo.doms[1]))
		rep, err := r.reconcile(dsync.ReconcileOptions{})
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if !rep.Completed || rep.Gone != 10 || rep.Purged != 0 || rep.Relocated != 0 || rep.Considered != 1198 {
			t.Fatalf("report = %+v", rep)
		}
		if len(rep.Listed) != 2 || rep.Listed[0].Objects != 640 || rep.Listed[1].Objects != 550 {
			t.Fatalf("listed = %+v", rep.Listed)
		}
		if got := e.states(t); got["live"] != 1190 || got["deleted"] != 10 || len(got) != 2 {
			t.Fatalf("after: %v", got)
		}
		if n := liveUsers(); n != usersBefore-10 {
			t.Fatalf("live users = %d, want %d", n, usersBefore-10)
		}
		after := stamp()
		dead := map[string]bool{}
		for _, g := range gone {
			dead[gtext(g)] = true
		}
		for g, at := range after {
			if dead[g] {
				if !at.After(before[g]) {
					t.Fatalf("a deleted row kept its observation time")
				}
				continue
			}
			if !at.Equal(before[g]) {
				t.Fatalf("object %s was touched by the reconcile", g)
			}
		}
		// 7 big-group members and 10 primary-group edges (every one of these users is in Domain Users).
		if want := membersBefore - 7 - 10; e.count(t, `SELECT count(*) FROM public.links WHERE connection_id = $1::uuid AND state = 'active'`, string(e.conn)) != want {
			t.Fatalf("active edges != %d", want)
		}
		if n := e.count(t, `SELECT count(*) FROM public.links l JOIN public.directory_objects o ON o.object_guid = l.target_guid AND o.connection_id = l.connection_id
			WHERE l.connection_id = $1::uuid AND l.state = 'active' AND o.state <> 'live'`, string(e.conn)); n != 0 {
			t.Fatalf("%d active edges end at a deleted object", n)
		}
		// Run again: nothing left to do, and no write.
		again, err := r.reconcile(dsync.ReconcileOptions{})
		if err != nil || again.Gone != 0 || again.Considered != 1188 {
			t.Fatalf("second reconcile = %+v, %v", again, err)
		}
	})
}

// TestReconcileKeepsAMoveAMove is acceptance 2: an object that left domain A and joined domain B between two
// cycles is one object. Reconciled before the destination domain is re-read, it is not deleted (the forest-wide
// diff finds it in B's listing) and is reported as relocated; once B is re-read it is one row in B.
func TestReconcileKeepsAMoveAMove(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		r := e.reconciling(t, newFake(fo.doms...), ncA, ncB)
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		mover := usersOf(fo, ncA, 200, 1)[0]
		moved := fo.nodes[mover]
		moved.parent = ncB
		moved.dn = fmt.Sprintf("CN=user200,OU=x,DC=d%d,DC=test", ncB)
		r.serve(newFake(variant(fo.doms[0], without(mover)), variant(fo.doms[1], without(), moved)))

		rep, err := r.reconcile(dsync.ReconcileOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Gone != 0 || rep.Relocated != 1 {
			t.Fatalf("before the destination is re-read: %+v", rep)
		}
		stored := func() (n int, nc, state string) {
			err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.directory_objects WHERE object_guid = $1::uuid`, gtext(mover)).Scan(&n); err != nil {
					return err
				}
				return tx.QueryRow(ctx, `SELECT nc_guid::text, state FROM public.directory_objects WHERE object_guid = $1::uuid`, gtext(mover)).Scan(&nc, &state)
			})
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		if n, nc, st := stored(); n != 1 || nc != gtext(ncA) || st != "live" {
			t.Fatalf("stored move = %d rows, nc %s, %s", n, nc, st)
		}

		// The destination domain is re-read (a resync), then reconciled: one row, in B, live.
		k := e.key(t, gtext(ncB))
		l, err := r.leases(context.Background(), mustLeaseName(t, k))
		if err != nil {
			t.Fatal(err)
		}
		if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := e.store.RequireResync(ctx, tx, k, l)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		rep, err = r.reconcile(dsync.ReconcileOptions{})
		if err != nil || rep.Gone != 0 || rep.Relocated != 0 {
			t.Fatalf("after the destination is re-read: %+v, %v", rep, err)
		}
		if n, nc, st := stored(); n != 1 || nc != gtext(ncB) || st != "live" {
			t.Fatalf("stored move = %d rows, nc %s, %s; want one live row in B", n, nc, st)
		}
	})
}

// TestReconcileNeverDeletesOnAnIncompleteListing is acceptance 3: a listing that is cut off, or fails, deletes
// nothing, writes nothing and is not complete, whichever domain it hit; the error carries no directory value.
func TestReconcileNeverDeletesOnAnIncompleteListing(t *testing.T) {
	for _, mode := range []string{"cut", "err"} {
		for _, which := range []uint64{ncA, ncB} {
			t.Run(fmt.Sprintf("%s/%x", mode, which), func(t *testing.T) {
				each(t, func(t *testing.T, e *env) {
					fo := twoDomains()
					r := e.reconciling(t, newFake(fo.doms...), ncA, ncB)
					if _, err := r.run(context.Background()); err != nil {
						t.Fatal(err)
					}
					// 5 objects are gone from each domain, so a listing that were trusted would delete 10.
					next := newFake(variant(fo.doms[0], without(usersOf(fo, ncA, 0, 5)...)), variant(fo.doms[1], without(usersOf(fo, ncB, 0, 5)...)))
					if mode == "cut" {
						next.listCut[gtext(which)] = 100
					} else {
						next.listErr[gtext(which)] = 100
					}
					r.serve(next)
					rep, err := r.reconcile(dsync.ReconcileOptions{})
					if err == nil || rep.Completed || rep.Gone != 0 {
						t.Fatalf("a broken listing was accepted: %+v, %v", rep, err)
					}
					var de *dsync.DomainError
					if !errors.As(err, &de) || de.Phase != "list" || de.NC != inventory.GUID(gtext(which)) {
						t.Fatalf("err = %v, want a list *DomainError for %x", err, which)
					}
					if mode == "cut" && !errors.Is(err, dsync.ErrIncomplete) {
						t.Fatalf("err = %v, want ErrIncomplete", err)
					}
					if mode == "err" && (!errors.Is(err, dsync.ErrConnector) || strings.Contains(err.Error(), leakSentinel)) {
						t.Fatalf("err = %q carries a directory value or is untyped", err)
					}
					if got := e.states(t); got["live"] != 1200 || len(got) != 1 {
						t.Fatalf("rows changed: %v", got)
					}
					if strings.Contains(r.logs.String(), leakSentinel) {
						t.Fatal("the log carries a directory value")
					}
					// The listing recovers: the same reconcile now deletes the 10.
					r.serve(newFake(variant(fo.doms[0], without(usersOf(fo, ncA, 0, 5)...)), variant(fo.doms[1], without(usersOf(fo, ncB, 0, 5)...))))
					rep, err = r.reconcile(dsync.ReconcileOptions{})
					if err != nil || !rep.Completed || rep.Gone != 10 {
						t.Fatalf("recovered reconcile = %+v, %v", rep, err)
					}
				})
			})
		}
	}
}

// TestReconcileRefusesAMassDelete is acceptance 4: an empty listing (100 %) and a listing that would remove 25 %
// delete nothing and fail with the typed cause; the inventory is unchanged and the pass is not complete; the
// next cycle proceeds. The share is configurable, and exactly that share is allowed.
func TestReconcileRefusesAMassDelete(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		r := e.reconciling(t, newFake(fo.doms...), ncA, ncB)
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		unchanged := func() {
			t.Helper()
			if got := e.states(t); got["live"] != 1200 || len(got) != 1 {
				t.Fatalf("inventory changed: %v", got)
			}
		}
		empty := func(d *fdom) *fdom {
			return &fdom{nc: d.nc, count: 0, sid: d.sid, at: func(int) fnode { return fnode{} }}
		}
		var quarter []uint64
		quarter = append(quarter, usersOf(fo, ncA, 0, 300)...) // 300 of 1198 considered: 25.04 %

		cases := []struct {
			name string
			fake *fakeConnector
			gone int
		}{
			{"100 percent: both listings empty", newFake(empty(fo.doms[0]), empty(fo.doms[1])), 1198},
			{"25 percent", newFake(variant(fo.doms[0], without(quarter...)), fo.doms[1]), 300},
		}
		for _, tc := range cases {
			r.serve(tc.fake)
			rep, err := r.reconcile(dsync.ReconcileOptions{})
			var md *inventory.MassDeleteError
			if !errors.Is(err, inventory.ErrMassDelete) || !errors.As(err, &md) || md.Gone != tc.gone || md.Considered != 1198 || md.Share != inventory.DefaultMassDeleteShare {
				t.Fatalf("%s: err = %v (%+v)", tc.name, err, md)
			}
			if rep.Completed || rep.Gone != 0 {
				t.Fatalf("%s: report = %+v", tc.name, rep)
			}
			unchanged()
		}
		if !strings.Contains(r.logs.String(), "mass_delete_refused") {
			t.Fatal("the refusal is not logged with its class")
		}
		// The next full cycle is not blocked (the finished domains are skipped, nothing errors).
		if _, err := r.run(context.Background()); err != nil {
			t.Fatalf("a full cycle after a refusal: %v", err)
		}
		// A larger share is the operator's explicit choice; 300 of 1198 passes at 30 % and not at 25 %.
		r.serve(cases[1].fake)
		if _, err := r.reconcile(dsync.ReconcileOptions{MaxDeleteShare: 0.25}); !errors.Is(err, inventory.ErrMassDelete) {
			t.Fatalf("25 %% limit: %v", err)
		}
		rep, err := r.reconcile(dsync.ReconcileOptions{MaxDeleteShare: 0.30})
		if err != nil || rep.Gone != 300 {
			t.Fatalf("30 %% limit: %+v, %v", rep, err)
		}
		if _, err := r.reconcile(dsync.ReconcileOptions{MaxDeleteShare: 1.5}); err == nil {
			t.Fatal("a share above 1 was accepted")
		}
	})
}

// groupForest is a small domain with nested groups: G has members u1, u2; H has members G and u3.
func groupForest() *fdom {
	const nc = ncA
	head := "DC=d1,DC=test"
	user := func(n uint64, rid uint32) fnode {
		return fnode{n: n, parent: nc, class: []string{"top", "person", "organizationalPerson", "user"}, sam: fmt.Sprintf("u%d", n), rid: rid, dn: fmt.Sprintf("CN=u%d,%s", n, head)}
	}
	ns := []fnode{
		{n: nc, class: []string{"top", "domain", "domainDNS"}, dn: head},
		user(nc+101, 1101), user(nc+102, 1102), user(nc+103, 1103),
		{n: nc + 20, parent: nc, class: []string{"top", "group"}, sam: "G", rid: 2001, members: []uint64{nc + 101, nc + 102}, dn: "CN=G," + head},
		{n: nc + 21, parent: nc, class: []string{"top", "group"}, sam: "H", rid: 2002, members: []uint64{nc + 20, nc + 103}, dn: "CN=H," + head},
	}
	return &fdom{nc: nc, count: len(ns), sid: 1, at: func(i int) fnode { return ns[i] }}
}

// TestReconcileRemovesADeletedGroupsEdges is acceptance 5: a deleted group that had members and was a member
// of another group loses every edge in the reconcile's transaction, the closure follows, and nobody's effective
// groups include it any more.
func TestReconcileRemovesADeletedGroupsEdges(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		d := groupForest()
		r := e.reconciling(t, newFake(d), ncA)
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		src := inventory.NewGroups(e.db)
		groupsOf := func(u uint64) []string {
			t.Helper()
			gs, err := src.GroupsOf(context.Background(), e.a, e.conn, inventory.GUID(gtext(u)))
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, g := range gs {
				out = append(out, string(g))
			}
			return out
		}
		g, h := gtext(ncA+20), gtext(ncA+21)
		if got := strings.Join(groupsOf(ncA+101), ","); got != g+","+h {
			t.Fatalf("before: effective groups of u1 = %q, want G and H", got)
		}
		closureRows := func(group string) int {
			return e.count(t, `SELECT count(*) FROM public.inventory_group_members WHERE connection_id = $1::uuid AND group_guid = $2::uuid`, string(e.conn), group)
		}
		if closureRows(g) != 2 || closureRows(h) != 4 {
			t.Fatalf("closure before: G=%d H=%d, want 2 and 4", closureRows(g), closureRows(h))
		}

		r.serve(newFake(variant(d, without(ncA+20))))
		rep, err := r.reconcile(dsync.ReconcileOptions{})
		if err != nil || rep.Gone != 1 || rep.EdgesRemoved != 3 { // G>u1, G>u2, H>G
			t.Fatalf("reconcile = %+v, %v", rep, err)
		}
		for _, u := range []uint64{ncA + 101, ncA + 102} {
			if got := groupsOf(u); len(got) != 0 {
				t.Fatalf("effective groups of a former member = %v, want none", got)
			}
		}
		if got := groupsOf(ncA + 103); len(got) != 1 || got[0] != h {
			t.Fatalf("effective groups of u3 = %v, want H only", got)
		}
		if n := e.count(t, `SELECT count(*) FROM public.links WHERE connection_id = $1::uuid AND state = 'active' AND (source_guid = $2::uuid OR target_guid = $2::uuid)`, string(e.conn), g); n != 0 {
			t.Fatalf("%d active edges still touch the deleted group", n)
		}
		if closureRows(g) != 0 || closureRows(h) != 1 {
			t.Fatalf("closure after: G=%d H=%d, want 0 and 1 (u3)", closureRows(g), closureRows(h))
		}
	})
}

// TestReconcilePurgesOldTombstones: with PurgeAfter set, a deleted object that is still absent and has not been
// observed that long becomes purged and leaves the search index; without it, nothing is purged.
func TestReconcilePurgesOldTombstones(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		r := e.reconciling(t, newFake(fo.doms...), ncA, ncB)
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		gone := usersOf(fo, ncA, 300, 4)
		r.serve(newFake(variant(fo.doms[0], without(gone...)), fo.doms[1]))
		if rep, err := r.reconcile(dsync.ReconcileOptions{}); err != nil || rep.Gone != 4 {
			t.Fatalf("%+v, %v", rep, err)
		}
		keys := func() int {
			return e.count(t, `SELECT count(*) FROM public.inventory_search_keys WHERE connection_id = $1::uuid AND object_guid = ANY($2::uuid[])`,
				string(e.conn), []string{gtext(gone[0]), gtext(gone[1]), gtext(gone[2]), gtext(gone[3])})
		}
		if keys() == 0 {
			t.Fatal("fixture: a deleted object has no search keys")
		}
		if rep, err := r.reconcile(dsync.ReconcileOptions{}); err != nil || rep.Purged != 0 {
			t.Fatalf("no PurgeAfter: %+v, %v", rep, err)
		}
		if rep, err := r.reconcile(dsync.ReconcileOptions{PurgeAfter: time.Hour}); err != nil || rep.Purged != 0 {
			t.Fatalf("a tombstone a moment old was purged: %+v, %v", rep, err)
		}
		rep, err := r.reconcile(dsync.ReconcileOptions{PurgeAfter: time.Nanosecond})
		if err != nil || rep.Purged != 4 || rep.Gone != 0 {
			t.Fatalf("PurgeAfter: %+v, %v", rep, err)
		}
		if got := e.states(t); got["purged"] != 4 || got["deleted"] != 0 || got["live"] != 1196 {
			t.Fatalf("states = %v", got)
		}
		if keys() != 0 {
			t.Fatal("a purged object is still in the search index")
		}
	})
}

// TestReconcileLeavesNewerRowsAlone: an object observed at or after the start of the listings is newer than
// them and is never removed on their account (an object created or changed while the listing ran).
func TestReconcileLeavesNewerRowsAlone(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		r := e.reconciling(t, newFake(fo.doms...), ncA, ncB)
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.serve(newFake(variant(fo.doms[0], without(usersOf(fo, ncA, 0, 5)...)), fo.doms[1]))
		past := time.Now().Add(-time.Hour)
		r.eng.Clock = func() time.Time { return past }
		rep, err := r.reconcile(dsync.ReconcileOptions{})
		if err != nil || rep.Gone != 0 || rep.Considered != 0 {
			t.Fatalf("%+v, %v", rep, err)
		}
		if got := e.states(t); got["live"] != 1200 || len(got) != 1 {
			t.Fatalf("states = %v", got)
		}
	})
}

// failAfter runs the real reconcile and then fails, as a store error after the writes would.
type failAfter struct{ inner dsync.Reconciler }

func (f failAfter) Reconcile(ctx context.Context, tx store.Tx, in inventory.Reconciliation) (inventory.Reconciled, error) {
	out, err := f.inner.Reconcile(ctx, tx, in)
	if err != nil {
		return out, err
	}
	return out, errors.New("injected failure after the writes")
}

// TestReconcileIsOneTransaction: a failure after the deletes were written leaves nothing of them behind.
func TestReconcileIsOneTransaction(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		d := groupForest()
		r := e.reconciling(t, newFake(d), ncA)
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.eng.Reconciler = failAfter{inner: dsync.NewIngester()}
		r.serve(newFake(variant(d, without(ncA+20))))
		edges := e.count(t, `SELECT count(*) FROM public.links WHERE connection_id = $1::uuid AND state = 'active'`, string(e.conn))
		rep, err := r.reconcile(dsync.ReconcileOptions{})
		if err == nil || rep.Completed || rep.Gone != 0 {
			t.Fatalf("%+v, %v", rep, err)
		}
		if got := e.states(t); got["live"] != 6 || len(got) != 1 {
			t.Fatalf("states after a failed reconcile = %v", got)
		}
		if n := e.count(t, `SELECT count(*) FROM public.links WHERE connection_id = $1::uuid AND state = 'active'`, string(e.conn)); n != edges {
			t.Fatalf("edges %d -> %d across a rolled-back reconcile", edges, n)
		}
	})
}

// TestReconcileRefusesBeforeReading: a connection that may not be read, a stale lease and a missing reconciler
// stop the reconcile before the connector is called.
func TestReconcileRefusesBeforeReading(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		f := newFake(twoDomains().doms...)
		r := e.reconciling(t, f, ncA)
		noCalls := func(what string) {
			t.Helper()
			if s, d := f.calls(); len(s) != 0 || d != 0 || r.src.calls != 0 {
				t.Fatalf("%s: the connector was called (%d searches, %d describes)", what, len(s), d)
			}
		}
		r.eng.Reconciler = nil
		if _, err := r.reconcile(dsync.ReconcileOptions{}); !errors.Is(err, dsync.ErrNotConfigured) {
			t.Fatalf("no reconciler: %v", err)
		}
		noCalls("no reconciler")
		r.eng.Reconciler = dsync.NewIngester()

		k := e.key(t, gtext(ncA))
		name := mustLeaseName(t, k)
		e.claim(t, k, jobs.Lease{Name: name, Holder: "newer", Token: 7})
		_, err := r.eng.Reconcile(context.Background(), e.a, connection.ID(e.conn), func(context.Context, string) (jobs.Lease, error) {
			return jobs.Lease{Name: name, Holder: "older", Token: 3}, nil
		}, dsync.ReconcileOptions{})
		if !errors.Is(err, dsync.ErrFenced) {
			t.Fatalf("stale lease: %v", err)
		}
		noCalls("stale lease")

		e.suspend(t, e.conn)
		_, err = r.reconcile(dsync.ReconcileOptions{})
		var rf *dsync.Refusal
		if !errors.Is(err, dsync.ErrRefused) || !errors.As(err, &rf) || rf.Reason != dsync.RefusedNotActive {
			t.Fatalf("suspended: %v", err)
		}
		noCalls("suspended")
	})
}
