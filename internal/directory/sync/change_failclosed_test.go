package sync_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/store"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The member edges in public.links are an authorization input (console grants through AD groups), so applying a
// feed is how a revocation takes effect. A change that cannot be applied in full must therefore never leave an
// edge active that it may have removed: the group stops granting, and the object is read (security review of
// T-1197, F1 and F2).

var t3 = t0.Add(3 * time.Hour)

// seedExtra stores users 40, 41, 42 and puts them in grpExtr.
func (e *env) seedExtra(t *testing.T, ap *dsync.Applier) {
	t.Helper()
	e.seed(t, ap)
	for i, n := range []uint64{40, 41, 42} {
		e.apply(t, ap, t0, newUser(n, fmt.Sprintf("m%d", n), "OU=Staff,"+root, staff, uint32(2000+i), 513))
	}
	e.apply(t, ap, t0, live(grpExtr, "", 0, cset("member", member(40), member(41), member(42))))
	if got := e.edges(t, grpExtr, "member"); !slices.Equal(got, texts_(40, 41, 42)) {
		t.Fatalf("seed members = %v", got)
	}
}

func (e *env) grants(t *testing.T, user uint64, group uint64) bool {
	t.Helper()
	gs, err := inventory.NewGroups(e.db).GroupsOf(context.Background(), e.a, e.conn, inventory.GUID(gtext(user)))
	if err != nil {
		t.Fatal(err)
	}
	return slices.Contains(gs, inventory.GUID(gtext(group)))
}

func (e *env) wantNeedsRead(t *testing.T, rep dsync.ApplyReport, objs ...uint64) {
	t.Helper()
	var want []inventory.GUID
	for _, s := range texts_(objs...) {
		want = append(want, inventory.GUID(s))
	}
	if !slices.Equal(rep.NeedsRead, want) {
		t.Fatalf("NeedsRead = %v, want %v (report %+v)", rep.NeedsRead, want, rep)
	}
}

var noGUID = dnv("CN=ext,"+root, nil)

// F1(i): a removal naming a member without a GUID cannot be applied, so the group grants nothing until it is
// read, and the read restores the members that remain.
func TestPatchUnresolvedRemovalFailsClosed(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seedExtra(t, ap)
		rep := e.apply(t, ap, t1, live(grpExtr, "", 0, cdel("member", noGUID), cset("displayName", txt("Extra group"))))
		if rep.MembersUnresolved != 1 || rep.Updated != 1 {
			t.Fatalf("report: %+v", rep)
		}
		e.wantNeedsRead(t, rep, grpExtr)
		if got := e.edges(t, grpExtr, "member"); len(got) != 0 {
			t.Fatalf("edges still active after an unresolved removal: %v", got)
		}
		for _, u := range []uint64{40, 41, 42} {
			if e.grants(t, u, grpExtr) {
				t.Errorf("user %d still reaches the group", u)
			}
		}
		// The rest of the change was applied.
		if got := e.row(t, grpExtr)["display_name"]; got != "Extra group" {
			t.Errorf("display_name = %v", got)
		}
		// A replay keeps it closed and reports it again.
		rep = e.apply(t, ap, t1, live(grpExtr, "", 0, cdel("member", noGUID)))
		e.wantNeedsRead(t, rep, grpExtr)
		if got := e.edges(t, grpExtr, "member"); len(got) != 0 {
			t.Fatalf("replay re-opened the group: %v", got)
		}
		// iii: the read names the members that remain (41 and 42; 40 was the one removed).
		e.apply(t, ap, t2, live(grpExtr, "", 0, cset("member", member(41), member(42))))
		if got := e.edges(t, grpExtr, "member"); !slices.Equal(got, texts_(41, 42)) {
			t.Fatalf("after the read: %v", got)
		}
		if e.grants(t, 40, grpExtr) || !e.grants(t, 41, grpExtr) || !e.grants(t, 42, grpExtr) {
			t.Errorf("after the read: 40=%v 41=%v 42=%v", e.grants(t, 40, grpExtr), e.grants(t, 41, grpExtr), e.grants(t, 42, grpExtr))
		}
	})
}

// F1(ii): a SET with one value that names no GUID cannot say which members to drop.
func TestPatchSetWithUnresolvedValueFailsClosed(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seedExtra(t, ap)
		rep := e.apply(t, ap, t1, live(grpExtr, "", 0, cset("member", member(41), noGUID)))
		e.wantNeedsRead(t, rep, grpExtr)
		if got := e.edges(t, grpExtr, "member"); len(got) != 0 {
			t.Fatalf("edges still active: %v", got)
		}
		if e.grants(t, 40, grpExtr) {
			t.Errorf("user 40 (not in the set) still reaches the group")
		}
		e.apply(t, ap, t2, live(grpExtr, "", 0, cset("member", member(41))))
		if got := e.edges(t, grpExtr, "member"); !slices.Equal(got, texts_(41)) {
			t.Fatalf("after the read: %v", got)
		}
	})
}

// An add that names no GUID only under-grants, so the group keeps what it had and is not re-read.
func TestPatchUnresolvedAddNeedsNoRead(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seedExtra(t, ap)
		rep := e.apply(t, ap, t1, live(grpExtr, "", 0, cadd("member", noGUID)))
		e.wantNeedsRead(t, rep)
		if rep.MembersUnresolved != 1 {
			t.Errorf("report: %+v", rep)
		}
		if got := e.edges(t, grpExtr, "member"); !slices.Equal(got, texts_(40, 41, 42)) {
			t.Fatalf("members = %v", got)
		}
	})
}

// F2: a change the mapper refuses is consumed with the cookie, so the object it named is read and a stored group
// stops granting. The out-of-bounds attribute here is a wrong-typed userAccountControl.
func TestPatchRefusedChangeIsReadNotLost(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seedExtra(t, ap)
		before := e.row(t, grpExtr)
		rep := e.apply(t, ap, t1, live(grpExtr, "", 0, cdel("member", member(40)), cset("userAccountControl", txt("512"))))
		if rep.Refused != 1 || rep.Updated != 0 {
			t.Fatalf("report: %+v", rep)
		}
		e.wantNeedsRead(t, rep, grpExtr)
		if got := e.edges(t, grpExtr, "member"); len(got) != 0 {
			t.Fatalf("edges still active after a refused change: %v", got)
		}
		if e.grants(t, 40, grpExtr) || e.grants(t, 41, grpExtr) {
			t.Errorf("the group still grants")
		}
		// Nothing of the refused change was written to the row.
		after := e.row(t, grpExtr)
		if after["observed_at"] != before["observed_at"] || after["user_account_control"] != before["user_account_control"] {
			t.Errorf("a refused change wrote the row: %v -> %v", before, after)
		}
		e.apply(t, ap, t2, live(grpExtr, "", 0, cset("member", member(41), member(42))))
		if got := e.edges(t, grpExtr, "member"); !slices.Equal(got, texts_(41, 42)) {
			t.Fatalf("after the read: %v", got)
		}
	})
}

// F2: a change for an object whose GUID parses but inventory has never seen is read too; one that has no GUID is
// a bare count.
func TestPatchRefusedChangeOfUnseenOrGuidlessObject(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seed(t, ap)
		rep := e.apply(t, ap, t1, live(70, "", 0, cset("userAccountControl", txt("512"))), &connectorv1.ObjectChange{State: connectorv1.ObjectState_OBJECT_STATE_LIVE})
		if rep.Refused != 2 {
			t.Fatalf("report: %+v", rep)
		}
		e.wantNeedsRead(t, rep, 70)
		var n int
		if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid AND object_guid = $2::uuid`, string(e.conn), gtext(70)).Scan(&n)
		}); err != nil || n != 0 {
			t.Fatalf("a half object was stored: %d, %v", n, err)
		}
	})
}

// F2 (patch.go): a member change for an object that is not a group is refused by the writer and read.
func TestPatchMemberChangeOfNonGroupIsReadNotLost(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seedExtra(t, ap)
		rep := e.apply(t, ap, t1, live(priya, "", 0, cadd("member", member(40))))
		if rep.Refused != 1 {
			t.Fatalf("report: %+v", rep)
		}
		e.wantNeedsRead(t, rep, priya)
	})
}

// F2 (patch.go, stored group): the change turns the stored group into a non-group and also carries a member
// removal. The writer refuses it, and because the row it holds is a group its edges end until the read.
func TestPatchMemberChangeOfStoredGroupBecomingNonGroupFailsClosed(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seedExtra(t, ap)
		rep := e.apply(t, ap, t1, live(grpExtr, "", 0, classes("top", "person", "organizationalPerson", "user"), cdel("member", member(40))))
		if rep.Refused != 1 || rep.Updated != 0 {
			t.Fatalf("report: %+v", rep)
		}
		e.wantNeedsRead(t, rep, grpExtr)
		if got := e.edges(t, grpExtr, "member"); len(got) != 0 {
			t.Fatalf("edges still active: %v", got)
		}
		for _, u := range []uint64{40, 41, 42} {
			if e.grants(t, u, grpExtr) {
				t.Errorf("user %d still reaches the group", u)
			}
		}
		e.apply(t, ap, t2, live(grpExtr, "", 0, cset("member", member(41), member(42))))
		if got := e.edges(t, grpExtr, "member"); !slices.Equal(got, texts_(41, 42)) {
			t.Fatalf("after the read: %v", got)
		}
		if e.grants(t, 40, grpExtr) || !e.grants(t, 41, grpExtr) || !e.grants(t, 42, grpExtr) {
			t.Errorf("after the read: 40=%v 41=%v 42=%v", e.grants(t, 40, grpExtr), e.grants(t, 41, grpExtr), e.grants(t, 42, grpExtr))
		}
	})
}

// A refused change older than the stored row is superseded by it: no read and no loss of edges.
func TestPatchRefusedChangeOlderThanRowIsStale(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seedExtra(t, ap)
		e.apply(t, ap, t2, live(grpExtr, "", 0, cset("description", txt("newer"))))
		rep := e.apply(t, ap, t1, live(grpExtr, "", 0, cdel("member", member(40)), cset("userAccountControl", txt("512"))))
		if rep.Stale != 1 || rep.Refused != 0 {
			t.Fatalf("report: %+v", rep)
		}
		e.wantNeedsRead(t, rep)
		if got := e.edges(t, grpExtr, "member"); !slices.Equal(got, texts_(40, 41, 42)) {
			t.Fatalf("members = %v", got)
		}
	})
}

// A refused change and a good change of the same object in one batch are applied in the order given.
func TestPatchRefusedThenGoodChangeOfOneObject(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seedExtra(t, ap)
		rep := e.apply(t, ap, t1,
			live(grpExtr, "", 0, cdel("member", member(40)), cset("userAccountControl", txt("512"))),
			live(grpExtr, "", 0, cset("member", member(41), member(42))))
		e.wantNeedsRead(t, rep, grpExtr)
		// The second change is a whole set and names the members; the group is still read for the first.
		if got := e.edges(t, grpExtr, "member"); !slices.Equal(got, texts_(41, 42)) {
			t.Fatalf("members = %v", got)
		}
	})
}

func TestPlanUnresolvedRemovalAndRefusalKeepTheObject(t *testing.T) {
	cm := changeMapper(t)
	p, err := cm.Plan(live(grpAll, "", 0, cdel("member", noGUID)))
	if err != nil || !p.Patch.Reread || p.MembersUnresolved != 1 {
		t.Errorf("unresolved removal: %+v %v", p, err)
	}
	p, err = cm.Plan(live(grpAll, "", 0, cset("member", member(40), noGUID)))
	if err != nil || !p.Patch.Reread || p.Patch.MembersComplete {
		t.Errorf("unresolved in a set: %+v %v", p, err)
	}
	p, err = cm.Plan(live(grpAll, "", 0, cadd("member", noGUID)))
	if err != nil || p.Patch.Reread {
		t.Errorf("unresolved add: %+v %v", p, err)
	}
	p, err = cm.Plan(live(grpAll, "", 0, cset("userAccountControl", txt("512"))))
	if err == nil || p.Patch.Object != inventory.GUID(gtext(grpAll)) {
		t.Errorf("a refused change must still name its object: %+v %v", p.Patch.Object, err)
	}
	p, err = cm.Plan(&connectorv1.ObjectChange{State: connectorv1.ObjectState_OBJECT_STATE_LIVE})
	if err == nil || p.Patch.Object != "" {
		t.Errorf("no guid: %+v %v", p.Patch.Object, err)
	}
}
