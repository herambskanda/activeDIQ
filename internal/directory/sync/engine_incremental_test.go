package sync_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The incremental cycle (T-1198) against the real database and ingester, with the fake connector for the full
// read and a scripted feed for the change feed. Directory behaviour (what DirSync really sends, a stale cookie
// from a real DC) is proved on Samba in engine_incremental_lab_test.go; Windows is T-1282.

// feedCall is one Read of the scripted feed: what it asked and how it answers.
type feedCall struct {
	// answer delivers batches through fn and returns what Read returns.
	answer func(ctx context.Context, fn func(context.Context, *connectorv1.ChangeBatch) error) (client.FeedResult, error)
}

type fakeFeed struct {
	script []feedCall
	reqs   []client.FeedRequest
}

func (f *fakeFeed) Read(ctx context.Context, _ tenant.ID, req client.FeedRequest, fn func(context.Context, *connectorv1.ChangeBatch) error) (client.FeedResult, error) {
	f.reqs = append(f.reqs, req)
	if len(f.script) == 0 {
		return client.FeedResult{}, errors.New("fakeFeed: unscripted Read")
	}
	c := f.script[0]
	f.script = f.script[1:]
	return c.answer(ctx, fn)
}

func fcookie(tag string) *connectorv1.FeedCookie {
	return &connectorv1.FeedCookie{ProviderState: []byte(tag), ProviderKind: connectorv1.ProviderKind_PROVIDER_KIND_AD, FormatVersion: 1,
		Issuer: &connectorv1.DcIdentity{DsaGuid: gid(0xd5a), InvocationId: gid(0x1d)}}
}

// delivers answers with the batches in order, the last with cycle_complete, cookie_after "<tag>.<n>".
func delivers(tag string, batches ...[]*connectorv1.ObjectChange) feedCall {
	return feedCall{answer: func(ctx context.Context, fn func(context.Context, *connectorv1.ChangeBatch) error) (client.FeedResult, error) {
		var res client.FeedResult
		if len(batches) == 0 {
			batches = [][]*connectorv1.ObjectChange{nil}
		}
		for i, ch := range batches {
			b := &connectorv1.ChangeBatch{Sequence: uint64(i + 1), Changes: ch, CookieAfter: fcookie(fmt.Sprintf("%s.%d", tag, i+1)), CycleComplete: i == len(batches)-1}
			if err := fn(ctx, b); err != nil {
				return res, fmt.Errorf("%w: %w", client.ErrFeedHandler, err)
			}
			res.Batches++
			res.Changes += len(ch)
			res.Cookie = b.CookieAfter
		}
		return res, nil
	}}
}

func fails(err error) feedCall {
	return feedCall{answer: func(context.Context, func(context.Context, *connectorv1.ChangeBatch) error) (client.FeedResult, error) {
		return client.FeedResult{}, err
	}}
}

// prime is a prime: one empty complete batch with the cookie "<tag>.1".
func prime(tag string) feedCall { return delivers(tag) }

type incRig struct {
	*rig
	feed *fakeFeed
	fo   *forest
	nc   inventory.GUID
}

func (e *env) incRig(t *testing.T, n int) *incRig {
	t.Helper()
	fo := newForest()
	fo.build(ncA, 1, n, n/2)
	r := e.rig(t, newFake(fo.doms...), ncA)
	ap := applier(t)
	cm, err := dsync.NewChangeMapper(dsync.Config{NC: inventory.GUID(gtext(ncA))})
	if err != nil {
		t.Fatal(err)
	}
	ap.Mapper = cm
	f := &fakeFeed{}
	r.eng.Feed, r.eng.Applier, r.eng.FeedCursors, r.eng.Passes = f, ap, dsync.Store{}, inventory.Writer{}
	r.eng.Reconciler = dsync.NewIngester()
	return &incRig{rig: r, feed: f, fo: fo, nc: inventory.GUID(gtext(ncA))}
}

func (r *incRig) cycle(t *testing.T) (dsync.IncrementalReport, error) {
	t.Helper()
	return r.eng.IncrementalCycle(context.Background(), r.e.a, connection.ID(r.e.conn), r.nc, r.leases)
}

func (r *incRig) mustCycle(t *testing.T) dsync.IncrementalReport {
	t.Helper()
	rep, err := r.cycle(t)
	if err != nil {
		t.Fatalf("IncrementalCycle: %v (report %+v)", err, rep)
	}
	return rep
}

func (r *incRig) cursor(t *testing.T) dsync.Cursor {
	return r.e.get(t, r.e.key(t, string(r.nc)))
}

// tagOf is the provider_state of the cookie a request resumed from, "" for a prime.
func tagOf(req client.FeedRequest) string { return string(req.Resume.GetProviderState()) }

func (r *incRig) passAt(t *testing.T) (state string, at string) {
	t.Helper()
	err := r.e.tx(r.e.a, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, coalesce(last_pass_at::text, '') FROM public.nc_sync_passes WHERE connection_id = $1::uuid AND nc_guid = $2::uuid`,
			string(r.e.conn), string(r.nc)).Scan(&state, &at)
	})
	if err != nil {
		t.Fatalf("pass: %v", err)
	}
	return
}

func (r *incRig) state(t *testing.T, obj uint64) string {
	t.Helper()
	var s string
	err := r.e.tx(r.e.a, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT state FROM public.directory_objects WHERE connection_id = $1::uuid AND object_guid = $2::uuid`, string(r.e.conn), gtext(obj)).Scan(&s)
	})
	if err != nil {
		return "absent"
	}
	return s
}

func (r *incRig) edge(t *testing.T, group, member uint64) bool {
	t.Helper()
	return r.e.count(t, `SELECT count(*) FROM public.links WHERE connection_id = $1::uuid AND link_attr = 'member' AND state = 'active'
		AND source_guid = $2::uuid AND target_guid = $3::uuid`, string(r.e.conn), gtext(group), gtext(member)) == 1
}

const (
	big      = ncA + 11
	userBase = ncA + 100
	newOne   = ncA + 9000
)

// TestIncrementalFirstSyncPrimesReadsThenResumes: a new partition is primed before the read, read in full, finished
// in one transaction with the prime's cookie, and the feed then replays from that cookie. A second, quiet cycle
// applies nothing and still moves the pass watermark.
func TestIncrementalFirstSyncPrimesReadsThenResumes(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		r := e.incRig(t, 40)
		oneUser := newUser(newOne, "new.one", "OU=L1,DC=x", ncA+1, 7001, domUsers)
		rename := live(userBase, "CN=renamed,OU=x,DC=d", ncA, cset("sAMAccountName", txt("renamed")))
		gone := tombstone(userBase+1, connectorv1.ObjectState_OBJECT_STATE_DELETED)
		grp := live(big, "CN=Big,OU=L2,DC=x", ncA+2, cadd("member", member(newOne)), cdel("member", member(userBase+2)))
		r.feed.script = []feedCall{prime("p"), delivers("c1", []*connectorv1.ObjectChange{oneUser, rename, gone, grp}), delivers("c2")}

		rep := r.mustCycle(t)
		if !rep.Primed || !rep.Completed || rep.Full == nil || !rep.Full.Completed || rep.Reconciled || len(rep.Resyncs) != 0 {
			t.Fatalf("first sync report = %+v", rep)
		}
		if got := []string{tagOf(r.feed.reqs[0]), tagOf(r.feed.reqs[1])}; got[0] != "" || got[1] != "p.1" {
			t.Fatalf("feed requests resumed from %q, want a prime then p.1", got)
		}
		if rep.Created != 1 || rep.Changes != 4 {
			t.Fatalf("applied = %+v", rep)
		}
		c := r.cursor(t)
		if c.State != dsync.StateIncremental || !c.HasCookie || c.IssuingDSA != gtext(0xd5a) {
			t.Fatalf("cursor = %v dsa %q", c, c.IssuingDSA)
		}
		if st := r.state(t, newOne); st != "live" {
			t.Fatalf("new user state %q", st)
		}
		if st := r.state(t, userBase+1); st != "deleted" {
			t.Fatalf("deleted user state %q", st)
		}
		if r.e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid AND object_guid = $2::uuid AND sam_account_name = 'renamed'`, string(e.conn), gtext(userBase)) != 1 {
			t.Fatal("rename not applied")
		}
		if !r.edge(t, big, newOne) || r.edge(t, big, userBase+2) {
			t.Fatal("membership change not applied")
		}
		if st, at := r.passAt(t); st != "ok" || at == "" {
			t.Fatalf("pass = %s %s", st, at)
		}
		_, before := r.passAt(t)

		rep = r.mustCycle(t)
		if rep.Primed || rep.Changes != 0 || !rep.Completed || tagOf(r.feed.reqs[2]) != "c1.1" {
			t.Fatalf("quiet cycle = %+v resumed from %q", rep, tagOf(r.feed.reqs[len(r.feed.reqs)-1]))
		}
		if _, after := r.passAt(t); after <= before {
			t.Fatalf("pass watermark did not move: %s -> %s", before, after)
		}
	})
}

// norm makes the dumps of two databases comparable: the tenant and connection ids differ between them.
func norm(e *env, d string) string {
	d = strings.ReplaceAll(d, e.a.String(), "TENANT")
	return strings.ReplaceAll(d, string(e.conn), "CONN")
}

// TestIncrementalCrashBetweenBatchesResumesFromTheStoredCookie is acceptance 2: the context ends after batch 1
// was committed; the next run resumes from batch 1's cookie, and the final inventory equals an uninterrupted run.
func TestIncrementalCrashBetweenBatchesResumesFromTheStoredCookie(t *testing.T) {
	batch1 := func() []*connectorv1.ObjectChange {
		return []*connectorv1.ObjectChange{newUser(newOne, "new.one", "OU=L1,DC=x", ncA+1, 7001, domUsers)}
	}
	batch2 := func() []*connectorv1.ObjectChange {
		return []*connectorv1.ObjectChange{tombstone(userBase+1, connectorv1.ObjectState_OBJECT_STATE_DELETED),
			live(big, "CN=Big,OU=L2,DC=x", ncA+2, cadd("member", member(newOne)))}
	}
	run := func(t *testing.T, e *env, crash bool) string {
		r := e.incRig(t, 40)
		if !crash {
			r.feed.script = []feedCall{prime("p"), delivers("c", batch1(), batch2())}
			r.mustCycle(t)
			return norm(e, e.dump(t, false))
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		dying := feedCall{answer: func(_ context.Context, fn func(context.Context, *connectorv1.ChangeBatch) error) (client.FeedResult, error) {
			if err := fn(ctx, &connectorv1.ChangeBatch{Sequence: 1, Changes: batch1(), CookieAfter: fcookie("c.1")}); err != nil {
				return client.FeedResult{}, err
			}
			cancel() // the process dies here
			err := fn(ctx, &connectorv1.ChangeBatch{Sequence: 2, Changes: batch2(), CookieAfter: fcookie("c.2"), CycleComplete: true})
			return client.FeedResult{}, fmt.Errorf("%w: %w", client.ErrFeedHandler, err)
		}}
		r.feed.script = []feedCall{prime("p"), dying}
		if _, err := r.eng.IncrementalCycle(ctx, e.a, connection.ID(e.conn), r.nc, r.leases); err == nil {
			t.Fatal("a cancelled cycle succeeded")
		}
		c := r.cursor(t)
		if c.State != dsync.StateIncremental || !c.HasCookie {
			t.Fatalf("cursor after the crash = %v", c)
		}
		if r.state(t, newOne) != "live" || r.state(t, userBase+1) == "deleted" {
			t.Fatal("batch 1 was not committed alone")
		}
		r.feed.script = []feedCall{delivers("c", batch2())}
		r.mustCycle(t)
		if got := tagOf(r.feed.reqs[len(r.feed.reqs)-1]); got != "c.1" {
			t.Fatalf("resumed from %q, want batch 1's cookie c.1", got)
		}
		return norm(e, e.dump(t, false))
	}
	var want, got string
	each(t, func(t *testing.T, e *env) { want = run(t, e, false) })
	each(t, func(t *testing.T, e *env) { got = run(t, e, true) })
	if want == "" || want != got {
		wl, gl := map[string]bool{}, map[string]bool{}
		for _, l := range strings.Split(want, "\n") {
			wl[l] = true
		}
		for _, l := range strings.Split(got, "\n") {
			gl[l] = true
		}
		var diff []string
		for l := range wl {
			if !gl[l] {
				diff = append(diff, "- "+l)
			}
		}
		for l := range gl {
			if !wl[l] {
				diff = append(diff, "+ "+l)
			}
		}
		sort.Strings(diff)
		t.Fatalf("a crashed and resumed run differs from an uninterrupted one:\n%s", strings.Join(diff[:min(len(diff), 20)], "\n"))
	}
}

// TestIncrementalStaleCookieResyncs is acceptance 3: for every reason of a stale cookie the partition goes to
// resync_required, re-primes, reads in full, reconciles (an object deleted while the cookie was stale is deleted in
// inventory), and ends incremental with a new cookie and a recorded pass.
func TestIncrementalStaleCookieResyncs(t *testing.T) {
	for _, reason := range []connectorv1.ResyncReason{
		connectorv1.ResyncReason_RESYNC_REASON_INVOCATION_ID_CHANGED, connectorv1.ResyncReason_RESYNC_REASON_USN_ROLLBACK,
		connectorv1.ResyncReason_RESYNC_REASON_ISSUER_MISMATCH, connectorv1.ResyncReason_RESYNC_REASON_COOKIE_TOO_OLD,
		connectorv1.ResyncReason_RESYNC_REASON_SERVER_REJECTED, connectorv1.ResyncReason_RESYNC_REASON_COOKIE_FORMAT_UNKNOWN,
		connectorv1.ResyncReason_RESYNC_REASON_DELTA_TOKEN_EXPIRED,
	} {
		t.Run(reason.String(), func(t *testing.T) {
			each(t, func(t *testing.T, e *env) {
				r := e.incRig(t, 40)
				r.feed.script = []feedCall{prime("p"), delivers("c")}
				r.mustCycle(t)
				if r.state(t, userBase+3) != "live" {
					t.Fatal("fixture")
				}
				// The user is deleted in the directory while the cookie is stale; the feed never says so.
				d := r.fo.doms[0]
				orig, victim := d.at, -1
				for i := 0; i < d.count; i++ {
					if orig(i).n == userBase+3 {
						victim = i
					}
				}
				d.count--
				d.at = func(i int) fnode {
					if i >= victim {
						return orig(i + 1)
					}
					return orig(i)
				}
				r.feed.script = []feedCall{fails(&client.StaleCookieError{Reason: reason}), prime("q"), delivers("d")}
				rep := r.mustCycle(t)
				if len(rep.Resyncs) != 1 || rep.Resyncs[0] != dsync.ResyncStale || rep.StaleReason != reason || !rep.Primed || !rep.Reconciled || rep.Reconcile.Gone != 1 {
					t.Fatalf("report = %+v", rep)
				}
				if r.state(t, userBase+3) != "deleted" {
					t.Fatalf("an object deleted during the stale period is %q", r.state(t, userBase+3))
				}
				c := r.cursor(t)
				if c.State != dsync.StateIncremental || !c.HasCookie {
					t.Fatalf("cursor = %v", c)
				}
				if got := tagOf(r.feed.reqs[len(r.feed.reqs)-1]); got != "q.1" {
					t.Fatalf("resumed from %q after the resync, want the new prime's q.1", got)
				}
				if st, _ := r.passAt(t); st != "ok" {
					t.Fatalf("pass state %s", st)
				}
			})
		})
	}
}

// TestIncrementalUnreachableDCRetriesTheSameDC is acceptance 4: the issuing DC is down: a retryable typed error,
// the state stays incremental, the cookie is untouched and nothing is primed or read.
func TestIncrementalUnreachableDCRetriesTheSameDC(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		r := e.incRig(t, 40)
		r.feed.script = []feedCall{prime("p"), delivers("c")}
		r.mustCycle(t)
		searches, _ := r.fake.calls()
		reqs := len(r.feed.reqs)
		for _, err := range []error{
			&client.UnreachableDCError{Retry: connectorv1.RetryAdvice_RETRY_ADVICE_SAME_DC_AFTER_BACKOFF},
			&client.ThrottledError{RetryAfter: 30e9},
			client.ErrFeedIncomplete,
		} {
			r.feed.script = []feedCall{fails(err)}
			rep, got := r.cycle(t)
			if !errors.Is(got, dsync.ErrRetryable) || !errors.Is(got, err) || rep.Completed || len(rep.Resyncs) != 0 {
				t.Fatalf("%v: err %v report %+v", err, got, rep)
			}
			var re *dsync.RetryableError
			if th, ok := err.(*client.ThrottledError); ok && (!errors.As(got, &re) || re.After != th.RetryAfter) {
				t.Fatalf("throttled advice lost: %v", got)
			}
			if c := r.cursor(t); c.State != dsync.StateIncremental || !c.HasCookie {
				t.Fatalf("cursor = %v", c)
			}
			if tagOf(r.feed.reqs[len(r.feed.reqs)-1]) != "c.1" {
				t.Fatal("did not resume from the stored cookie")
			}
		}
		if after, _ := r.fake.calls(); len(after) != len(searches) || len(r.feed.reqs) != reqs+3 {
			t.Fatalf("a retry re-primed or re-read: %d searches, %d feed calls", len(after), len(r.feed.reqs)-reqs)
		}
	})
}

// TestIncrementalUnusableCookie: a stored cookie that cannot be decoded, and one the reader refuses as
// malformed, resync instead of failing forever.
func TestIncrementalUnusableCookie(t *testing.T) {
	for _, mode := range []string{"garbage", "refused"} {
		t.Run(mode, func(t *testing.T) {
			each(t, func(t *testing.T, e *env) {
				r := e.incRig(t, 40)
				r.feed.script = []feedCall{prime("p"), delivers("c")}
				r.mustCycle(t)
				if mode == "garbage" {
					k := e.key(t, string(r.nc))
					l, err := r.leases(context.Background(), mustLeaseName(t, k))
					if err != nil {
						t.Fatal(err)
					}
					junk, _ := dsync.NewCookie([]byte{0xff, 0xff, 0xff, 0xff, 0xff})
					if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
						_, err := e.store.Advance(ctx, tx, k, l, dsync.Move{Cookie: junk})
						return err
					}); err != nil {
						t.Fatal(err)
					}
					r.feed.script = []feedCall{prime("q"), delivers("d")}
				} else {
					r.feed.script = []feedCall{fails(fmt.Errorf("%w: resume cookie", client.ErrFeedRequest)), prime("q"), delivers("d")}
				}
				rep := r.mustCycle(t)
				if len(rep.Resyncs) != 1 || rep.Resyncs[0] != dsync.ResyncBadCookie || !rep.Primed || !rep.Reconciled {
					t.Fatalf("report = %+v", rep)
				}
			})
		})
	}
}

// TestIncrementalSuspendedConnectionPausesAndResumesAsResync is acceptance 6.
func TestIncrementalSuspendedConnectionPausesAndResumesAsResync(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		r := e.incRig(t, 40)
		r.feed.script = []feedCall{prime("p"), delivers("c")}
		r.mustCycle(t)
		searches, _ := r.fake.calls()
		reqs := len(r.feed.reqs)

		e.suspend(t, e.conn)
		rep, err := r.cycle(t)
		if !errors.Is(err, dsync.ErrRefused) || !rep.Paused {
			t.Fatalf("suspended: err %v report %+v", err, rep)
		}
		if c := r.cursor(t); c.State != dsync.StatePaused {
			t.Fatalf("cursor = %v, want paused", c)
		}
		if st, _ := r.passAt(t); st != "paused" {
			t.Fatalf("pass state %q, want paused", st)
		}
		if after, _ := r.fake.calls(); len(after) != len(searches) || len(r.feed.reqs) != reqs {
			t.Fatal("a suspended connection was read")
		}

		if _, err := connection.NewRegistry(e.db).Transition(context.Background(), e.a, connection.ID(e.conn), connection.StateSuspended, connection.StateActive); err != nil {
			t.Fatal(err)
		}
		r.feed.script = []feedCall{prime("q"), delivers("d")}
		rep = r.mustCycle(t)
		if len(rep.Resyncs) != 1 || rep.Resyncs[0] != dsync.ResyncResumed || !rep.Reconciled || !rep.Primed {
			t.Fatalf("resumed cycle = %+v", rep)
		}
		if c := r.cursor(t); c.State != dsync.StateIncremental || !c.HasCookie {
			t.Fatalf("cursor = %v", c)
		}
	})
}

// TestIncrementalFailsClosedAndResyncsOnAnUnappliedChange: a membership removal that names no GUID cannot be
// applied; the group's edges are ended and the position is dropped in the same transaction, so a full read puts
// the group back right. The change is never lost with its cookie.
func TestIncrementalFailsClosedAndResyncsOnAnUnappliedChange(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		r := e.incRig(t, 40)
		r.feed.script = []feedCall{prime("p"), delivers("c")}
		r.mustCycle(t)
		if !r.edge(t, big, userBase+2) {
			t.Fatal("fixture: no member edge")
		}
		noGUID := &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Dn{Dn: &connectorv1.DnValue{DisplayDn: "CN=ghost,DC=x"}}}
		r.feed.script = []feedCall{delivers("d", []*connectorv1.ObjectChange{live(big, "CN=Big,OU=L2,DC=x", ncA+2, cdel("member", noGUID))}), prime("q"), delivers("e")}
		rep := r.mustCycle(t)
		if len(rep.Resyncs) != 1 || rep.Resyncs[0] != dsync.ResyncNeedsRead || !rep.Primed {
			t.Fatalf("report = %+v", rep)
		}
		if !r.edge(t, big, userBase+2) {
			t.Fatal("the full read did not restore the group's members")
		}
		if c := r.cursor(t); c.State != dsync.StateIncremental || !c.HasCookie {
			t.Fatalf("cursor = %v", c)
		}
	})
}

// TestIncrementalMovedOUChildrenFollow is acceptance 5: the feed reports the moved OU only, and every
// descendant's ancestry in inventory follows it.
func TestIncrementalMovedOUChildrenFollow(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		r := e.incRig(t, 300)
		r.feed.script = []feedCall{prime("p"), delivers("c")}
		r.mustCycle(t)
		moved := uint64(ncA + 3) // OU=L3, under L2; below it L4 and their users
		r.feed.script = []feedCall{delivers("d", []*connectorv1.ObjectChange{live(moved, "OU=L3,"+fmt.Sprintf("DC=d%d,DC=test", ncA), ncA, classes("top", "organizationalUnit"))})}
		rep := r.mustCycle(t)
		if rep.Changes != 1 {
			t.Fatalf("report = %+v", rep)
		}
		r.fo.parent[moved] = ncA
		below := 0
		for n := range r.fo.nodes {
			under := false
			for p := r.fo.parent[n]; p != 0; p = r.fo.parent[p] {
				if p == moved {
					under = true
				}
			}
			if !under {
				continue
			}
			below++
			var got []string
			if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT ancestry::text[] FROM public.directory_objects WHERE connection_id = $1::uuid AND object_guid = $2::uuid`, string(e.conn), gtext(n)).Scan(&got)
			}); err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, ",") != strings.Join(r.fo.chain(n), ",") {
				t.Fatalf("ancestry of %s = %v, want %v", gtext(n), got, r.fo.chain(n))
			}
		}
		// The descendants' dn is NOT asserted: T-0988's rewriteDescendantDNs is wired into Populate's move path only,
		// not into the patch path (inventory/patch.go settleChain), so a feed-reported OU move leaves the
		// children's dn stale. That gap is a follow-up ticket (see the T-1198 advance note).
		if below < 50 {
			t.Fatalf("only %d descendants below the moved OU", below)
		}
	})
}

// TestIncrementalNotConfigured: the cycle refuses to run with a port missing, and a naming context the connection
// does not manage is not read.
func TestIncrementalNotConfigured(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		r := e.incRig(t, 40)
		r.eng.Feed = nil
		if _, err := r.cycle(t); !errors.Is(err, dsync.ErrNotConfigured) {
			t.Fatalf("err = %v", err)
		}
		r.eng.Feed = r.feed
		r.nc = inventory.GUID(gtext(ncB))
		if _, err := r.cycle(t); !errors.Is(err, dsync.ErrNotDomainNC) {
			t.Fatalf("unmanaged NC: err = %v", err)
		}
	})
}
