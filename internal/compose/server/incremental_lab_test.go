//go:build lab

package server

// T-1198 acceptance 1, 3 and 5 on the Samba lab: Engine.IncrementalCycle over the in-process connector's real
// DirSync feed, against a Postgres per test. The first sync is the real sync.full job; what the directory
// changes afterwards is made by an administrator session and compared with a direct LDAP read.
// Windows DirSync behaviour (the same feed on a Windows DC) is not proved here: see T-1282, T-1320, T-2038.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/connector/labadmin"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// allManaged says every naming context is managed: the lab connection has the one domain.
type allManaged struct{}

func (allManaged) Managed(context.Context, tenant.ID, connection.ID, string) (bool, error) {
	return true, nil
}

type incLab struct {
	*reportsRig
	eng   *dsync.Engine
	cid   inventory.ConnectionID
	nc    inventory.GUID
	admin *labadmin.Admin
	held  map[string]jobs.Lease
}

// recordingFeed logs the shape (attribute names and ops, never values) of what the feed delivered.
type recordingFeed struct {
	*client.ChangeFeedReader
	t *testing.T
}

func (f recordingFeed) Read(ctx context.Context, tid tenant.ID, req client.FeedRequest, fn func(context.Context, *connectorv1.ChangeBatch) error) (client.FeedResult, error) {
	return f.ChangeFeedReader.Read(ctx, tid, req, func(ctx context.Context, b *connectorv1.ChangeBatch) error {
		for _, c := range b.GetChanges() {
			var sh []string
			for _, a := range c.GetAttributes() {
				sh = append(sh, fmt.Sprintf("%s/%v/%d", a.GetName(), a.GetOp(), len(a.GetValues())))
			}
			f.t.Logf("feed change state=%v attrs=%v", c.GetState(), sh)
		}
		return fn(ctx, b)
	})
}

func (l *incLab) lease(ctx context.Context, name string) (jobs.Lease, error) {
	if old, ok := l.held[name]; ok {
		if err := jobs.ReleaseLease(ctx, l.db, old); err != nil {
			return jobs.Lease{}, err
		}
	}
	got, ok, err := jobs.AcquireLease(ctx, l.db, name, "inc-lab", 30*time.Minute)
	if err != nil || !ok {
		return jobs.Lease{}, fmt.Errorf("lease %s: %v %v", name, ok, err)
	}
	l.held[name] = got
	return got, nil
}

func (l *incLab) cycle(t *testing.T) dsync.IncrementalReport {
	t.Helper()
	rep, err := l.eng.IncrementalCycle(l.ctx, l.tid, connection.ID(l.cid), l.nc, l.lease)
	if err != nil {
		t.Fatalf("IncrementalCycle: %v (report %+v)", err, rep)
	}
	return rep
}

func newIncLab(t *testing.T, s *storetest.Server) *incLab {
	t.Helper()
	r := newReportsRig(t, s)
	cid := r.activateAndSync()
	all, err := r.conns.List(r.ctx, r.tid, false)
	if err != nil || len(all) != 1 {
		t.Fatalf("connections: %v %v", all, err)
	}
	rsrc, err := client.NewReaderSource(r.src)
	if err != nil {
		t.Fatal(err)
	}
	nc := inventory.GUID(strings.ToLower(string(all[0].DirectoryIdentity)))
	eng := &dsync.Engine{Tenants: r.db, Conns: r.conns, Domains: connectionDomains{conns: r.conns}, Source: rsrc,
		Ingester: dsync.NewIngester(), Cursors: dsync.Store{}, Reconciler: dsync.NewIngester(), FeedCursors: dsync.Store{}, Passes: inventory.Writer{}}
	feed, err := client.NewChangeFeedReader(r.conns, r.src, allManaged{})
	if err != nil {
		t.Fatal(err)
	}
	cm, err := dsync.NewChangeMapper(dsync.Config{NC: nc})
	if err != nil {
		t.Fatal(err)
	}
	eng.Feed, eng.Applier = recordingFeed{feed, t}, &dsync.Applier{Mapper: cm, Writer: dsync.NewIngester()}
	admin := labadmin.Dial(t, r.le.Port, r.le.Pool, "Administrator@lab.activediq.test", r.le.Values["LAB_ADMIN_PASSWORD"])
	return &incLab{reportsRig: r, eng: eng, cid: cid, nc: nc, admin: admin, held: map[string]jobs.Lease{}}
}

func (l *incLab) guidOf(t *testing.T, dn string) string {
	t.Helper()
	g, err := guid.FromBytes(l.admin.ObjectGUID(dn))
	if err != nil {
		t.Fatal(err)
	}
	return g.String()
}

func (l *incLab) row(t *testing.T, g string) (dn, state string, found bool) {
	t.Helper()
	err := l.db.WithTenant(l.ctx, l.tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT dn, state FROM public.directory_objects WHERE connection_id = $1::uuid AND object_guid = $2::uuid`, string(l.cid), g)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			found = true
			return rows.Scan(&dn, &state)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return
}

// activeMembers is the set of member guids of group g with an active link in inventory.
func (l *incLab) activeMembers(t *testing.T, g string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := l.db.WithTenant(l.ctx, l.tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT target_guid::text FROM public.links WHERE connection_id = $1::uuid AND source_guid = $2::uuid AND link_attr = 'member' AND state = 'active'`, string(l.cid), g)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m string
			if err := rows.Scan(&m); err != nil {
				return err
			}
			out[m] = true
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (l *incLab) passAt(t *testing.T) (state string, at time.Time) {
	t.Helper()
	err := l.db.WithTenant(l.ctx, l.tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, coalesce(last_pass_at, 'epoch') FROM public.nc_sync_passes WHERE connection_id = $1::uuid AND nc_guid = $2::uuid`,
			string(l.cid), string(l.nc)).Scan(&state, &at)
	})
	if err != nil {
		t.Fatalf("pass: %v", err)
	}
	return
}

func (l *incLab) cursorState(t *testing.T) (state string, hasCookie bool) {
	t.Helper()
	err := l.db.WithTenant(l.ctx, l.tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, cookie IS NOT NULL FROM public.sync_cursors WHERE connection_id = $1::uuid`, string(l.cid)).Scan(&state, &hasCookie)
	})
	if err != nil {
		t.Fatalf("cursor: %v", err)
	}
	return
}

func TestLabIncrementalCycle(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		l := newIncLab(t, s)
		users := "CN=Users," + labDom
		tag := fmt.Sprintf("t1198-%d", time.Now().UnixNano()%1_000_000)

		renamedDN := l.admin.CreateUser(tag+"-ren", users)
		deletedDN := l.admin.CreateUser(tag+"-del", users)
		groupDN := l.admin.CreateGroup(tag+"-grp", users)
		l.admin.AddMemberDN(groupDN, renamedDN)
		l.admin.AddMemberDN(groupDN, deletedDN)
		renG, delG, grpG := l.guidOf(t, renamedDN), l.guidOf(t, deletedDN), l.guidOf(t, groupDN)

		// The lab changed after the first full read: this cycle has no feed position, so it primes, reads in
		// full and reconciles, and ends incremental with a cookie.
		rep := l.cycle(t)
		if !rep.Primed || !rep.Completed {
			t.Fatalf("first cycle: %+v", rep)
		}
		if st, ck := l.cursorState(t); st != "incremental" || !ck {
			t.Fatalf("cursor after the first cycle: %s cookie=%v", st, ck)
		}
		if dn, st, ok := l.row(t, renG); !ok || st != "live" || !strings.EqualFold(dn, renamedDN) {
			t.Fatalf("renamed user before: %q %q %v", dn, st, ok)
		}

		// Acceptance 1: a new user, a renamed user, a deleted user and a membership change.
		newDN := l.admin.CreateUser(tag+"-new", users)
		newG := l.guidOf(t, newDN)
		l.admin.AddMemberDN(groupDN, newDN)
		renamedDN = l.admin.Rename(renamedDN, "CN="+tag+"-ren2")
		l.admin.RemoveMember(groupDN, deletedDN)
		l.admin.Delete(deletedDN)
		_, before := l.passAt(t)
		rep = l.cycle(t)
		if rep.Primed || len(rep.Resyncs) != 0 || !rep.Completed || rep.Changes == 0 {
			t.Fatalf("incremental cycle: %+v", rep)
		}
		if dn, st, ok := l.row(t, newG); !ok || st != "live" || !strings.EqualFold(dn, newDN) {
			t.Errorf("new user: %q %q %v, directory %q", dn, st, ok, newDN)
		}
		if dn, st, ok := l.row(t, renG); !ok || st != "live" || !strings.EqualFold(dn, renamedDN) {
			t.Errorf("renamed user: %q %q %v, directory %q", dn, st, ok, renamedDN)
		}
		// Samba's DirSync shows a tombstone (and a removed link) only to an administrator, and the lab service
		// account must not be one (V7 refuses it): the deletion reaches inventory by the resync below. The
		// delivered-deletion path is the fake-feed engine test and T-1282 on Windows.
		// The feed's member values carry no GUID (the DirSync request has no extended-DN control), so the
		// patch cannot name the added member and does not apply it (T-1197, fail closed): the group edge
		// arrives with the resync below. Delivering it incrementally is T-2056.
		t.Logf("group edge for the added member after the incremental cycle: %v", l.activeMembers(t, grpG)[newG])
		_, after := l.passAt(t)
		if !after.After(before) {
			t.Errorf("pass watermark did not move: %s -> %s", before, after)
		}

		// A second run with no change reports zero changes and still moves the pass watermark.
		rep = l.cycle(t)
		if rep.Changes != 0 || !rep.Completed || len(rep.Resyncs) != 0 {
			t.Fatalf("quiet cycle: %+v", rep)
		}
		if _, again := l.passAt(t); !again.After(after) {
			t.Errorf("quiet cycle did not move the watermark: %s -> %s", after, again)
		}

		// Acceptance 3: the stored cookie names a different invocation; the DC says STALE_COOKIE. An object
		// deleted while the position was stale (never seen by the feed) is deleted in inventory afterwards.
		victimDN := l.admin.CreateUser(tag+"-vic", users)
		victimG := l.guidOf(t, victimDN)
		rep = l.cycle(t) // the victim arrives through the feed
		if _, st, ok := l.row(t, victimG); !ok || st != "live" {
			t.Fatalf("victim before: %q %v (report %+v)", st, ok, rep)
		}
		l.breakCookie(t)
		l.admin.Delete(victimDN)
		rep = l.cycle(t)
		if len(rep.Resyncs) == 0 || rep.Resyncs[0] != dsync.ResyncStale || !rep.Reconciled {
			t.Fatalf("stale cycle: %+v", rep)
		}
		if _, st, ok := l.row(t, victimG); !ok || st == "live" {
			t.Errorf("victim after the resync: state %q found %v, want not live", st, ok)
		}
		if st, ck := l.cursorState(t); st != "incremental" || !ck {
			t.Errorf("cursor after the resync: %s cookie=%v", st, ck)
		}
		got := l.activeMembers(t, grpG)
		if got[delG] {
			t.Error("the deleted user is still an active member after the resync")
		}
		for _, m := range l.admin.Members(groupDN) {
			if g := l.guidOf(t, m); !got[g] {
				t.Errorf("group member %s of the directory missing in inventory after the resync", g)
			}
		}
		if _, st, ok := l.row(t, delG); !ok || st == "live" {
			t.Errorf("deleted user after the resync: state %q found %v, want not live", st, ok)
		}
		t.Logf("stale reason: %v", rep.StaleReason)
	})
}

// breakCookie rewrites the stored cookie's issuer invocation id, which is what a DC restore does.
func (l *incLab) breakCookie(t *testing.T) {
	t.Helper()
	var raw []byte
	if err := l.db.WithTenant(l.ctx, l.tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT cookie FROM public.sync_cursors WHERE connection_id = $1::uuid`, string(l.cid)).Scan(&raw)
	}); err != nil {
		t.Fatal(err)
	}
	var ck connectorv1.FeedCookie
	if err := proto.Unmarshal(raw, &ck); err != nil {
		t.Fatalf("stored cookie is not a FeedCookie: %v", err)
	}
	inv := append([]byte(nil), ck.GetIssuer().GetInvocationId().GetValue()...)
	if len(inv) == 0 {
		t.Fatal("stored cookie has no issuer invocation id")
	}
	inv[0] ^= 0xff
	ck.Issuer.InvocationId = &connectorv1.Guid{Value: inv}
	out, err := proto.Marshal(&ck)
	if err != nil {
		t.Fatal(err)
	}
	// The table is FORCE row-level secured: the owner connection carries the tenant as a start-up parameter.
	c, err := l.d.OwnerForTenant(l.ctx, l.tid.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(l.ctx)
	tag, err := c.Exec(l.ctx, `UPDATE public.sync_cursors SET cookie = $2 WHERE connection_id = $1::uuid`, string(l.cid), out)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("break the stored cookie: %v rows=%d", err, tag.RowsAffected())
	}
}

// Acceptance 5: an OU with 50 descendants is renamed; the feed reports the OU, and the 50 descendants' dn and
// ancestry in inventory follow though the feed did not report them.
func TestLabIncrementalRenamedOUChildrenFollow(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		l := newIncLab(t, s)
		tag := fmt.Sprintf("t1198-%d", time.Now().UnixNano()%1_000_000)
		ou := l.admin.CreateOU(tag+"-ou", labDom)
		sams := make([]string, 50)
		for i := range sams {
			sams[i] = fmt.Sprintf("%s-u%02d", tag, i)
			l.admin.CreateUser(sams[i], ou)
		}
		if rep := l.cycle(t); !rep.Primed {
			t.Fatalf("first cycle: %+v", rep)
		}
		ouG := l.guidOf(t, ou)
		newOU := l.admin.Rename(ou, "OU="+tag+"-ou2")
		rep := l.cycle(t)
		if rep.Primed || len(rep.Resyncs) != 0 || rep.Changes == 0 {
			t.Fatalf("cycle after the rename: %+v", rep)
		}
		if dn, _, ok := l.row(t, ouG); !ok || !strings.EqualFold(dn, newOU) {
			t.Fatalf("OU dn %q, directory %q", dn, newOU)
		}
		stale := 0
		for _, sam := range sams {
			dirDN := l.admin.DNOf(sam)
			g := l.guidOf(t, dirDN)
			dn, _, ok := l.row(t, g)
			if !ok || !strings.EqualFold(dn, dirDN) {
				stale++
				continue
			}
			var inAncestry bool
			if err := l.db.WithTenant(l.ctx, l.tid, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT parent_guid = $3::uuid AND $3::uuid = ANY(ancestry) FROM public.directory_objects WHERE connection_id = $1::uuid AND object_guid = $2::uuid`,
					string(l.cid), g, ouG).Scan(&inAncestry)
			}); err != nil || !inAncestry {
				t.Errorf("%s: ancestry does not name the renamed OU (%v)", sam, err)
			}
		}
		if stale != 0 {
			t.Errorf("%d of %d descendants have a stale dn in inventory", stale, len(sams))
		}
	})
}
