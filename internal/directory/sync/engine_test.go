package sync_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	ncA        = 0xA001
	ncB        = 0xB001
	forestRoot = "aaaaaaaa-0000-4000-8000-0000000000f0"
	domUsers   = 513
)

// forest is the fake directory's ground truth.
type forest struct {
	doms   []*fdom
	nodes  map[uint64]fnode
	parent map[uint64]uint64
	// members maps a group to its member objects.
	members map[uint64][]uint64
	// pgusers are the users whose primary group is Domain Users, with that group per domain.
	primary map[uint64]uint64
	count   int
}

// build makes one domain: a head, an OU tree four deep, Domain Users, a big group and users spread over
// the tree, n objects in all. The slice is in build order (parents first); the fake streams it reversed, so
// children arrive before their parents.
func (f *forest) build(nc uint64, sid uint32, n, bigGroup int) *fdom {
	var ns []fnode
	add := func(x fnode) { ns = append(ns, x) }
	head := fmt.Sprintf("DC=d%d,DC=test", nc)
	add(fnode{n: nc, class: []string{"top", "domain", "domainDNS"}, dn: head})
	ous := []uint64{nc + 1, nc + 2, nc + 3, nc + 4}
	dn := head
	for i, o := range ous {
		dn = fmt.Sprintf("OU=L%d,%s", i+1, dn)
		p := nc
		if i > 0 {
			p = ous[i-1]
		}
		add(fnode{n: o, parent: p, class: []string{"top", "organizationalUnit"}, dn: dn})
	}
	du, big := nc+10, nc+11
	add(fnode{n: du, parent: ous[0], class: []string{"top", "group"}, sam: "Domain Users", rid: domUsers, dn: "CN=Domain Users," + fmt.Sprintf("OU=L1,%s", head)})
	var users []uint64
	parents := append([]uint64{nc}, ous...)
	for i := 0; len(ns)+1 < n; i++ {
		u := nc + 100 + uint64(i)
		p := parents[i%len(parents)]
		cn := fmt.Sprintf("user%d", i)
		switch {
		case i%50 == 0:
			cn = fmt.Sprintf(`Smith\, Jörg %d`, i) // a comma and a non-ASCII letter in the RDN
		case i%77 == 0:
			cn = fmt.Sprintf(`Ünï \+ #%d`, i)
		}
		add(fnode{n: u, parent: p, class: []string{"top", "person", "organizationalPerson", "user"}, sam: fmt.Sprintf("user%d", i),
			rid: uint32(1000 + i), pgid: domUsers, dn: fmt.Sprintf("CN=%s,OU=x,%s", cn, head)})
		users = append(users, u)
	}
	members := users[:min(bigGroup, len(users))]
	add(fnode{n: big, parent: ous[1], class: []string{"top", "group"}, sam: "Big", rid: 2000, members: members, dn: "CN=Big,OU=L2," + head})
	if len(ns) != n {
		panic(fmt.Sprintf("forest: built %d, want %d", len(ns), n))
	}
	for _, x := range ns {
		f.nodes[x.n] = x
		f.parent[x.n] = x.parent
		if len(x.members) > 0 {
			f.members[x.n] = x.members
		}
		if x.pgid != 0 {
			f.primary[x.n] = du
		}
	}
	f.count += n
	// Stream order: reversed, so every child precedes its parent.
	rev := make([]fnode, len(ns))
	for i, x := range ns {
		rev[len(ns)-1-i] = x
	}
	d := &fdom{nc: nc, count: n, sid: sid, at: func(i int) fnode { return rev[i] }}
	f.doms = append(f.doms, d)
	return d
}

func newForest() *forest {
	return &forest{nodes: map[uint64]fnode{}, parent: map[uint64]uint64{}, members: map[uint64][]uint64{}, primary: map[uint64]uint64{}}
}

// twoDomains is the 1200-object forest of the acceptance: 650 + 550 objects, a 600-member group, 4-deep OUs.
func twoDomains() *forest {
	f := newForest()
	f.build(ncA, 1, 650, 600)
	f.build(ncB, 2, 550, 40)
	return f
}

// chain is the ground-truth ancestry (nearest parent first) of an object.
func (f *forest) chain(n uint64) []string {
	var out []string
	for p := f.parent[n]; p != 0; p = f.parent[p] {
		out = append(out, gtext(p))
	}
	return out
}

// activate takes e.conn through the DM-10 lifecycle to active with a verified identity. It is idempotent.
func (e *env) activate(t *testing.T, id inventory.ConnectionID) {
	t.Helper()
	ctx := context.Background()
	reg := connection.NewRegistry(e.db)
	cid := connection.ID(id)
	if c, err := reg.Get(ctx, e.a, cid); err != nil || c.State != connection.StateDraft {
		return // already taken through the lifecycle (possibly suspended since)
	}
	if _, err := reg.Transition(ctx, e.a, cid, connection.StateDraft, connection.StateVerifying); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if _, err := reg.SetDirectoryIdentity(ctx, e.a, cid, connection.DirectoryIdentity(forestRoot)); err != nil {
		t.Fatalf("activate: %v", err)
	}
	err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		if _, err := (connection.Store{}).RecordVerification(ctx, tx, connection.NewVerification{
			ID: "00000000-0000-4000-b000-000000000001", ConnectionID: cid, CredentialID: cred, Kind: connection.KindManual,
			RequestedBy: "principal-test", StartedAt: time.Now(), CheckListVersion: 1, Verdict: connection.VerdictPass,
			Outcomes: map[connection.Check]connection.Outcome{"V5": connection.OutcomePass,
				connection.CheckV7OverPrivilege: connection.OutcomePass, connection.CheckV8ReadSufficient: connection.OutcomePass},
		}); err != nil {
			return err
		}
		_, err := (connection.Store{}).Activate(ctx, tx, cid)
		return err
	})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
}

// suspend moves an active connection to suspended through the registry.
func (e *env) suspend(t *testing.T, id inventory.ConnectionID) {
	t.Helper()
	if _, err := connection.NewRegistry(e.db).Transition(context.Background(), e.a, connection.ID(id), connection.StateActive, connection.StateSuspended); err != nil {
		t.Fatalf("suspend: %v", err)
	}
}

// ingestLog records what the engine handed the ingester and passes it to the real one.
type ingestLog struct {
	inner  dsync.Ingest
	cycles []cycleRec
}

type cycleRec struct {
	n      int
	more   bool
	passes []inventory.GUID
}

func (l *ingestLog) Ingest(ctx context.Context, tx store.Tx, c inventory.Cycle) (inventory.Ingested, error) {
	l.cycles = append(l.cycles, cycleRec{n: len(c.Observations), more: c.MoreBatches, passes: c.PassNCs})
	return l.inner.Ingest(ctx, tx, c)
}

func domainsOf(ncs ...uint64) []dsync.Domain {
	var out []dsync.Domain
	for _, n := range ncs {
		out = append(out, dsync.Domain{NC: inventory.GUID(gtext(n)), Kind: dsync.NCDomain})
	}
	return out
}

type connSource struct {
	cc    client.Reader
	calls int
}

func (s *connSource) Reader(context.Context, string) (client.Reader, error) {
	s.calls++
	return s.cc, nil
}

// rig is an Engine over the real database and ingester with a fake connector.
type rig struct {
	e      *env
	eng    *dsync.Engine
	fake   *fakeConnector
	src    *connSource
	ingest *ingestLog
	list   *managedDomains
	logs   *bytes.Buffer
	holder string
	held   map[string]jobs.Lease
}

type managedDomains struct{ list []dsync.Domain }

func (m *managedDomains) ManagedDomains(context.Context, tenant.ID, connection.ID) ([]dsync.Domain, error) {
	return m.list, nil
}

func (e *env) rig(t *testing.T, f *fakeConnector, ncs ...uint64) *rig {
	t.Helper()
	e.activate(t, e.conn)
	r := &rig{e: e, fake: f, src: &connSource{cc: f}, list: &managedDomains{list: domainsOf(ncs...)}, logs: &bytes.Buffer{}, holder: "engine", held: map[string]jobs.Lease{}}
	r.ingest = &ingestLog{inner: dsync.NewIngester()}
	r.eng = &dsync.Engine{Tenants: e.db, Conns: connection.NewRegistry(e.db), Domains: r.list, Source: r.src, Ingester: r.ingest,
		Cursors: dsync.Store{}, Log: slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	return r
}

// leases hands the engine a per-NC lease; a lease this rig took on an earlier run is released first (the
// job that owns the engine does that between runs), so every run gets a fresh, higher fencing token.
func (r *rig) leases(ctx context.Context, name string) (jobs.Lease, error) {
	if old, ok := r.held[name]; ok {
		if err := jobs.ReleaseLease(ctx, r.e.db, old); err != nil {
			return jobs.Lease{}, err
		}
	}
	l, ok, err := jobs.AcquireLease(ctx, r.e.db, name, r.holder, time.Minute)
	if err != nil || !ok {
		return jobs.Lease{}, fmt.Errorf("lease %s: %v %v", name, ok, err)
	}
	r.held[name] = l
	return l, nil
}

func (r *rig) run(ctx context.Context) (dsync.Report, error) {
	return r.eng.FullCycle(ctx, r.e.a, connection.ID(r.e.conn), r.leases)
}

func (e *env) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error { return tx.QueryRow(ctx, q, args...).Scan(&n) })
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// TestFullCycleStoresTheWholeForest is acceptance 1: 1200 objects of two domains, a 600-member group and OUs
// four deep, streamed children-first, end up in directory_objects exactly once with the right ancestry, the
// member edges equal the source, batches are bounded, and the pass is recorded per domain on its last batch only.
func TestFullCycleStoresTheWholeForest(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		r := e.rig(t, newFake(fo.doms...), ncA, ncB)
		rep, err := r.run(context.Background())
		if err != nil {
			t.Fatalf("FullCycle: %v", err)
		}
		if fo.count != 1200 {
			t.Fatalf("fixture has %d objects", fo.count)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn)); n != 1200 {
			t.Fatalf("rows = %d, want 1200", n)
		}
		if n := e.count(t, `SELECT count(DISTINCT object_guid) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn)); n != 1200 {
			t.Fatalf("distinct objects = %d", n)
		}

		// Ancestry and completeness against the ground truth.
		got := map[string][]string{}
		complete := 0
		err = e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.Query(ctx, `SELECT object_guid::text, ancestry::text[], ancestry_complete FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn))
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var g string
				var a []string
				var c bool
				if err := rows.Scan(&g, &a, &c); err != nil {
					return err
				}
				got[g] = a
				if c {
					complete++
				}
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		for n := range fo.nodes {
			want := fo.chain(n)
			if g := got[gtext(n)]; strings.Join(g, ",") != strings.Join(want, ",") {
				t.Fatalf("ancestry of %s = %v, want %v", gtext(n), g, want)
			}
		}
		if complete != 1200 {
			t.Fatalf("ancestry_complete rows = %d, want 1200", complete)
		}
		if got[gtext(ncA+4+100)] == nil && len(fo.chain(ncA+4+100)) == 0 {
			t.Fatal("fixture: no deep object")
		}

		// Member edges and primary-group edges equal the source.
		wantEdges := map[string]bool{}
		for g, ms := range fo.members {
			for _, m := range ms {
				wantEdges[gtext(g)+">"+gtext(m)] = true
			}
		}
		gotEdges := map[string]bool{}
		err = e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.Query(ctx, `SELECT source_guid::text, target_guid::text FROM public.links WHERE connection_id = $1::uuid AND link_attr = 'member' AND state = 'active'`, string(e.conn))
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var s, d string
				if err := rows.Scan(&s, &d); err != nil {
					return err
				}
				gotEdges[s+">"+d] = true
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(gotEdges) != len(wantEdges) || len(wantEdges) != 600+40 {
			t.Fatalf("member edges = %d, want %d (fixture %d)", len(gotEdges), len(wantEdges), 640)
		}
		for k := range wantEdges {
			if !gotEdges[k] {
				t.Fatalf("missing edge %s", k)
			}
		}
		if n := e.count(t, `SELECT count(*) FROM public.links WHERE connection_id = $1::uuid AND link_attr = 'primary_group' AND state = 'active'`, string(e.conn)); n != len(fo.primary) {
			t.Fatalf("primary-group edges = %d, want %d", n, len(fo.primary))
		}

		// Batches: bounded, MoreBatches on all but the last of each domain, passes on the last only.
		var passes []inventory.GUID
		perDomain := 0
		for i, c := range r.ingest.cycles {
			if c.n > inventory.IngestBatchSize {
				t.Fatalf("batch %d holds %d observations, over the ingest batch size", i, c.n)
			}
			perDomain++
			if c.more == (len(c.passes) > 0) {
				t.Fatalf("batch %d: more=%v passes=%v (passes belong on the last batch only)", i, c.more, c.passes)
			}
			if !c.more {
				passes = append(passes, c.passes...)
				perDomain = 0
			}
		}
		if len(passes) != 2 || passes[0] != inventory.GUID(gtext(ncA)) || passes[1] != inventory.GUID(gtext(ncB)) {
			t.Fatalf("passes = %v", passes)
		}
		if n := e.count(t, `SELECT count(*) FROM public.nc_sync_passes WHERE connection_id = $1::uuid AND last_pass_at IS NOT NULL`, string(e.conn)); n != 2 {
			t.Fatalf("recorded passes = %d, want 2", n)
		}
		for _, nc := range []uint64{ncA, ncB} {
			c := e.get(t, e.key(t, gtext(nc)))
			if c.State != dsync.StateIncremental || c.LastFullSync.IsZero() || c.HasCookie {
				t.Fatalf("cursor of %s = %+v, want incremental with a full-sync time and no cookie", gtext(nc), c)
			}
		}
		if len(rep.Domains) != 2 || !rep.Domains[0].Completed || !rep.Domains[1].Completed || rep.Domains[0].Entries != 650 || rep.Domains[1].Entries != 550 {
			t.Fatalf("report = %+v", rep.Domains)
		}
		if rep.Domains[0].AncestryUnresolved+rep.Domains[1].AncestryUnresolved != 0 {
			t.Fatalf("unresolved ancestry: %+v", rep.Domains)
		}
		if rep.Domains[0].Inserted+rep.Domains[1].Inserted != 1200 {
			t.Fatalf("inserted = %d", rep.Domains[0].Inserted+rep.Domains[1].Inserted)
		}
	})
}

// TestFullCycleIsIdempotent: a second run over an already complete forest reads nothing (both cursors are
// incremental), and a forced re-read through a resync adds no duplicate row.
func TestFullCycleIsIdempotent(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		f := newFake(fo.doms...)
		r := e.rig(t, f, ncA, ncB)
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		before, _ := f.calls()
		rep, err := r.run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		after, _ := f.calls()
		if len(after) != len(before) || !rep.Domains[0].Skipped || !rep.Domains[1].Skipped {
			t.Fatalf("a finished forest was read again: %d -> %d searches, %+v", len(before), len(after), rep.Domains)
		}
		// A resync re-reads: move A's cursor to resync_required, run again, still 1200 rows and 1 pass each.
		for _, nc := range []uint64{ncA} {
			k := e.key(t, gtext(nc))
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
		}
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn)); n != 1200 {
			t.Fatalf("rows after a re-read = %d", n)
		}
		if n := e.count(t, `SELECT count(*) FROM public.links WHERE connection_id = $1::uuid AND link_attr = 'member' AND state = 'active'`, string(e.conn)); n != 640 {
			t.Fatalf("member edges after a re-read = %d", n)
		}
	})
}

func mustLeaseName(t *testing.T, k dsync.Key) string {
	t.Helper()
	n, err := dsync.LeaseName(k)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestFullCycleSurvivesACutOffStream is acceptance 2: the second domain's stream is cut off (no completion
// marker) or fails with an error that carries a directory value. The first domain's pass stays, the second's
// pass and last_full_sync_at do not move, committed rows stay, the error is typed and value-free, and a
// second run finishes the job with no duplicate row.
func TestFullCycleSurvivesACutOffStream(t *testing.T) {
	for _, mode := range []string{"cut", "err"} {
		t.Run(mode, func(t *testing.T) {
			each(t, func(t *testing.T, e *env) {
				fo := twoDomains()
				f := newFake(fo.doms...)
				if mode == "cut" {
					f.cutAfter[gtext(ncB)] = 520
				} else {
					f.errAfter[gtext(ncB)] = 520
				}
				r := e.rig(t, f, ncA, ncB)
				rep, err := r.run(context.Background())
				if err == nil {
					t.Fatal("a cut stream was a success")
				}
				var de *dsync.DomainError
				if !errors.As(err, &de) || de.NC != inventory.GUID(gtext(ncB)) {
					t.Fatalf("err = %v, want a DomainError for domain B", err)
				}
				if mode == "cut" && !errors.Is(err, dsync.ErrIncomplete) || mode == "err" && !errors.Is(err, dsync.ErrConnector) {
					t.Fatalf("err = %v is not the typed cause", err)
				}
				if strings.Contains(err.Error(), "SENTINEL") || strings.Contains(r.logs.String(), "SENTINEL") {
					t.Fatalf("a directory value reached an error or the log: %v / %s", err, r.logs)
				}
				if !rep.Domains[0].Completed || rep.Domains[1].Completed {
					t.Fatalf("report = %+v", rep.Domains)
				}
				a, b := e.get(t, e.key(t, gtext(ncA))), e.get(t, e.key(t, gtext(ncB)))
				if a.State != dsync.StateIncremental || a.LastFullSync.IsZero() {
					t.Fatalf("A cursor = %+v", a)
				}
				if b.State != dsync.StateInitialSync || !b.LastFullSync.IsZero() {
					t.Fatalf("B cursor moved: %+v", b)
				}
				if n := e.count(t, `SELECT count(*) FROM public.nc_sync_passes WHERE connection_id = $1::uuid AND nc_guid = $2::uuid AND last_pass_at IS NOT NULL`, string(e.conn), gtext(ncA)); n != 1 {
					t.Fatalf("A's pass = %d, want recorded", n)
				}
				if n := e.count(t, `SELECT count(*) FROM public.nc_sync_passes WHERE connection_id = $1::uuid AND nc_guid = $2::uuid AND last_pass_at IS NOT NULL`, string(e.conn), gtext(ncB)); n != 0 {
					t.Fatalf("B's pass was recorded for a cut stream")
				}
				if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid AND nc_guid = $2::uuid`, string(e.conn), gtext(ncB)); n != 500 {
					t.Fatalf("B's committed rows = %d, want the first batch of 500 kept", n)
				}

				// The fault clears; a second run reads only B and finishes the job.
				delete(f.cutAfter, gtext(ncB))
				delete(f.errAfter, gtext(ncB))
				before, _ := f.calls()
				if _, err := r.run(context.Background()); err != nil {
					t.Fatalf("second run: %v", err)
				}
				after, _ := f.calls()
				for _, s := range after[len(before):] {
					if s.nc == gtext(ncA) {
						t.Fatalf("the finished domain A was read again")
					}
				}
				if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn)); n != 1200 {
					t.Fatalf("rows after the second run = %d, want 1200 with no duplicates", n)
				}
				if b := e.get(t, e.key(t, gtext(ncB))); b.State != dsync.StateIncremental || b.LastFullSync.IsZero() {
					t.Fatalf("B cursor after the second run = %+v", b)
				}
				if n := e.count(t, `SELECT count(*) FROM public.nc_sync_passes WHERE connection_id = $1::uuid AND last_pass_at IS NOT NULL`, string(e.conn)); n != 2 {
					t.Fatalf("passes after the second run = %d", n)
				}
			})
		})
	}
}

// TestFullCycleRefusesBeforeReading is acceptance 3: a draft, suspended or non-AD connection, and a lease
// whose token is behind the stored fencing token, read nothing from the connector.
func TestFullCycleRefusesBeforeReading(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		entra, err := connection.NewRegistry(e.db).Create(context.Background(), e.a,
			connection.New{Kind: connection.KindEntraTenant, DisplayName: "e", CredentialID: cred})
		if err != nil {
			t.Fatal(err)
		}
		draft, err := connection.NewRegistry(e.db).Create(context.Background(), e.a,
			connection.New{Kind: connection.KindADForest, DisplayName: "d", CredentialID: cred, Transport: connection.TransportLDAPS})
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name   string
			conn   inventory.ConnectionID
			state  string
			reason dsync.RefusalReason
		}{
			{"draft", inventory.ConnectionID(draft.ID), "", dsync.RefusedNotActive},
			{"suspended", e.conn, "suspended", dsync.RefusedNotActive},
			{"not AD", inventory.ConnectionID(entra.ID), "", dsync.RefusedNotAD},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f := newFake(twoDomains().doms...)
				r := e.rig(t, f, ncA)
				if tc.state == "suspended" {
					e.suspend(t, tc.conn)
				}
				_, err := r.eng.FullCycle(context.Background(), e.a, connection.ID(tc.conn), r.leases)
				var ref *dsync.Refusal
				if !errors.Is(err, dsync.ErrRefused) || !errors.As(err, &ref) || ref.Reason != tc.reason {
					t.Fatalf("err = %v, want a Refusal for %s", err, tc.reason)
				}
				if s, d := f.calls(); len(s) != 0 || d != 0 || r.src.calls != 0 {
					t.Fatalf("the connector was called: %d searches, %d describes, %d connects", len(s), d, r.src.calls)
				}
				if n := e.count(t, `SELECT count(*) FROM public.directory_objects`); n != 0 {
					t.Fatalf("%d rows written", n)
				}
			})
		}
	})
}

// TestFullCycleRefusesAStaleLease: a lease behind the stored token is ErrFenced and nothing is read.
func TestFullCycleRefusesAStaleLease(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		f := newFake(twoDomains().doms...)
		r := e.rig(t, f, ncA)
		k := e.key(t, gtext(ncA))
		name := mustLeaseName(t, k)
		e.claim(t, k, jobs.Lease{Name: name, Holder: "newer", Token: 7})
		r.eng.Cursors = dsync.Store{}
		_, err := r.eng.FullCycle(context.Background(), e.a, connection.ID(e.conn), func(context.Context, string) (jobs.Lease, error) {
			return jobs.Lease{Name: name, Holder: "older", Token: 3}, nil
		})
		var fe *dsync.FencedError
		if !errors.Is(err, dsync.ErrFenced) || !errors.As(err, &fe) {
			t.Fatalf("err = %v, want ErrFenced", err)
		}
		if s, d := f.calls(); len(s) != 0 || d != 0 || r.src.calls != 0 {
			t.Fatalf("the connector was called under a stale lease: %d searches, %d describes", len(s), d)
		}
	})
}

// TestFullCycleReadsOnlyManagedDomains is acceptance 4: with one domain excluded no search names its NC and
// nothing of it is stored; a configuration or schema NC is refused whether the managed list says so or the
// connector does, before any search.
func TestFullCycleReadsOnlyManagedDomains(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		f := newFake(fo.doms...)
		r := e.rig(t, f, ncA) // B is excluded
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		searches, _ := f.calls()
		if len(searches) != 2 {
			t.Fatalf("%d searches, want the pre-scan and the read of A", len(searches))
		}
		for _, s := range searches {
			if len(s.roots) != 1 || s.roots[0] != gtext(ncA) {
				t.Fatalf("a search was rooted at %v, only A is managed", s.roots)
			}
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE nc_guid = $1::uuid`, gtext(ncB)); n != 0 {
			t.Fatalf("%d rows of the excluded domain", n)
		}
		if n := e.count(t, `SELECT count(*) FROM public.sync_cursors WHERE partition = $1`, gtext(ncB)); n != 0 {
			t.Fatalf("a cursor exists for the excluded domain")
		}
	})
	t.Run("configuration and schema", func(t *testing.T) {
		each(t, func(t *testing.T, e *env) {
			const cfg, sch = "cccccccc-0000-4000-8000-000000000001", "cccccccc-0000-4000-8000-000000000002"
			f := newFake(twoDomains().doms...)
			f.extraNCs[cfg] = connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_CONFIGURATION
			f.extraNCs[sch] = connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_SCHEMA
			r := e.rig(t, f, ncA)
			for name, list := range map[string][]dsync.Domain{
				"labelled configuration":   {{NC: cfg, Kind: dsync.NCConfiguration}},
				"labelled schema":          {{NC: sch, Kind: dsync.NCSchema}},
				"mislabelled as domain":    {{NC: cfg, Kind: dsync.NCDomain}, {NC: sch, Kind: dsync.NCDomain}},
				"a domain among them":      {{NC: inventory.GUID(gtext(ncA)), Kind: dsync.NCDomain}, {NC: sch, Kind: dsync.NCDomain}},
				"unknown to the connector": {{NC: "dddddddd-0000-4000-8000-0000000000ff", Kind: dsync.NCDomain}},
			} {
				r.list.list = list
				_, err := r.run(context.Background())
				if !errors.Is(err, dsync.ErrNotDomainNC) {
					t.Fatalf("%s: err = %v, want ErrNotDomainNC", name, err)
				}
				if s, _ := f.calls(); len(s) != 0 {
					t.Fatalf("%s: a search was sent", name)
				}
				if n := e.count(t, `SELECT count(*) FROM public.directory_objects`); n != 0 {
					t.Fatalf("%s: rows were written", name)
				}
			}
		})
	})
}

// TestFullCycleSkipsMalformedEntries is acceptance 5: 3 malformed entries among 500 are counted and skipped
// without aborting the batch, the report says so, and no directory value is logged or returned.
func TestFullCycleSkipsMalformedEntries(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		f := newForest()
		d := f.build(ncA, 1, 500, 5)
		bad := 0
		inner := d.at
		d.at = func(i int) fnode {
			x := inner(i)
			if x.rid >= 1000 && x.rid < 1003 { // three users
				x.badUAC = true
				x.dn = strings.Replace(x.dn, "CN=", "CN=BADUSER-SECRET-", 1)
				bad++
			}
			return x
		}
		r := e.rig(t, newFake(d), ncA)
		rep, err := r.run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		dr := rep.Domains[0]
		if dr.Entries != 500 || dr.Refused != 3 || dr.Mapped != 497 || dr.RefusedBy[dsync.RefusalKey{Attr: "userAccountControl", Code: dsync.CodeType}] != 3 {
			t.Fatalf("report = %+v", dr)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn)); n != 497 {
			t.Fatalf("rows = %d, want 497", n)
		}
		// T-1250: the refused objects are named by GUID and reason, not only counted.
		if len(dr.RefusedEntries) != 3 || dr.RefusedOmitted != 0 {
			t.Fatalf("refused entries = %+v", dr.RefusedEntries)
		}
		seen := map[inventory.GUID]bool{}
		for _, re := range dr.RefusedEntries {
			if re.Object == "" || seen[re.Object] || re.Attr != "userAccountControl" || re.Code != dsync.CodeType {
				t.Fatalf("refused entry = %+v", re)
			}
			seen[re.Object] = true
		}
		out := r.logs.String()
		for _, leak := range []string{"BADUSER-SECRET", "not-a-number", "user0", "DC=d"} {
			if strings.Contains(out, leak) {
				t.Fatalf("the log carries a directory value %q:\n%s", leak, out)
			}
		}
		if !strings.Contains(out, "refused_object.2") || !strings.Contains(out, "userAccountControl.type") ||
			!strings.Contains(out, `"refused":3`) || !strings.Contains(out, "refused.userAccountControl.type") {
			t.Fatalf("the log does not carry the refusal counts:\n%s", out)
		}
	})
}

// TestFullCycleHonoursTheSearchLimits is the request half of acceptance 6: every ScopedSearch stays under the
// contract's limits, asks for the closed attribute list, and the read is pinned to the DC the pre-scan used.
func TestFullCycleHonoursTheSearchLimits(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		f := newFake(twoDomains().doms...)
		f.maxPage = 777
		r := e.rig(t, f, ncA, ncB)
		if _, err := r.run(context.Background()); err != nil {
			t.Fatal(err)
		}
		searches, describes := f.calls()
		if len(searches) != 4 || describes != 1 {
			t.Fatalf("%d searches, %d describes", len(searches), describes)
		}
		closed := dsync.Attributes()
		sort.Strings(closed)
		for _, s := range searches {
			if len(s.roots) < 1 || len(s.roots) > 64 || len(s.attrs) < 1 || len(s.attrs) > 64 {
				t.Fatalf("request over the limits: %d roots, %d attributes", len(s.roots), len(s.attrs))
			}
			if s.pageSize == 0 || s.pageSize > 777 {
				t.Fatalf("page size %d, want the connector's limit 777 at most", s.pageSize)
			}
			if s.depth != connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE || s.filter.GetPresent() != "objectClass" {
				t.Fatalf("depth/filter = %v / %v", s.depth, s.filter)
			}
			for _, a := range s.attrs {
				if a == "*" || a == "+" || strings.EqualFold(a, "nTSecurityDescriptor") {
					t.Fatalf("attribute %q requested", a)
				}
			}
			if s.prescan {
				if s.pin != "" {
					t.Fatal("the pre-scan is pinned")
				}
				continue
			}
			got := append([]string(nil), s.attrs...)
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(closed, ",") {
				t.Fatalf("main pass attributes = %v, want the closed list", got)
			}
			if s.pin != gtext(f.dsa) {
				t.Fatalf("main pass pin = %q, want the pre-scan DC %q", s.pin, gtext(f.dsa))
			}
		}
	})
}

// TestFullCycleStopsWhenSuspendedMidRead: a suspension (or removal) that lands while a domain is being read
// stops the cycle at the next batch, with or without the partition cursors having been paused. Rows
// committed before the stop stay; no pass or cursor moves; nothing more is searched, and the second domain
// is never read. The stop is a typed refusal, not a per-domain failure.
func TestFullCycleStopsWhenSuspendedMidRead(t *testing.T) {
	pause := func(t *testing.T, e *env) {
		t.Helper()
		err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := dsync.Store{}.PauseConnection(ctx, tx, e.conn)
			return err
		})
		if err != nil {
			t.Fatalf("pause: %v", err)
		}
	}
	cases := []struct {
		name string
		// at is true when the stop should land: searches issued so far, batches committed so far.
		at     func(searches, committed int) bool
		stop   func(t *testing.T, e *env)
		want   error
		reason dsync.RefusalReason
		rows   int
		state  dsync.State
	}{
		{"suspended and paused", func(_, c int) bool { return c == 1 }, func(t *testing.T, e *env) { e.suspend(t, e.conn); pause(t, e) },
			dsync.ErrRefused, dsync.RefusedNotActive, 500, dsync.StatePaused},
		{"suspended, cursors not paused", func(_, c int) bool { return c == 1 }, func(t *testing.T, e *env) { e.suspend(t, e.conn) },
			dsync.ErrRefused, dsync.RefusedNotActive, 500, dsync.StateInitialSync},
		{"decommissioning", func(_, c int) bool { return c == 1 }, func(t *testing.T, e *env) {
			if _, err := connection.NewRegistry(e.db).Transition(context.Background(), e.a, connection.ID(e.conn), connection.StateActive, connection.StateDecommissioning); err != nil {
				t.Fatalf("decommission: %v", err)
			}
		}, dsync.ErrRefused, dsync.RefusedRetired, 500, dsync.StateInitialSync},
		{"cursors paused only", func(_, c int) bool { return c == 1 }, pause, dsync.ErrPaused, "", 500, dsync.StatePaused},
		{"suspended during the pre-scan", func(s, c int) bool { return s == 1 && c == 0 }, func(t *testing.T, e *env) { e.suspend(t, e.conn) },
			dsync.ErrRefused, dsync.RefusedNotActive, 0, dsync.StateInitialSync},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			each(t, func(t *testing.T, e *env) {
				f := newForest()
				f.build(ncA, 1, 1600, 50)
				f.build(ncB, 2, 300, 10)
				fk := newFake(f.doms...)
				r := e.rig(t, fk, ncA, ncB)
				stopped, searchesAtStop := false, 0
				fk.onBatch = func() {
					s, _ := fk.calls()
					if stopped || !tc.at(len(s), len(r.ingest.cycles)) {
						return
					}
					stopped, searchesAtStop = true, len(s)
					tc.stop(t, e)
				}
				rep, err := r.run(context.Background())
				if !stopped {
					t.Fatal("the stop never landed")
				}
				var de *dsync.DomainError
				if !errors.Is(err, tc.want) || errors.As(err, &de) {
					t.Fatalf("err = %v, want %v and not a DomainError", err, tc.want)
				}
				var ref *dsync.Refusal
				if tc.want == dsync.ErrRefused && (!errors.As(err, &ref) || ref.Reason != tc.reason) {
					t.Fatalf("err = %v, want the %s refusal", err, tc.reason)
				}
				if s, _ := fk.calls(); len(s) != searchesAtStop {
					t.Fatalf("%d searches after the stop", len(s)-searchesAtStop)
				}
				for _, s := range func() []searchRec { s, _ := fk.calls(); return s }() {
					if s.nc == gtext(ncB) {
						t.Fatal("the second domain was searched after the stop")
					}
				}
				if len(rep.Domains) != 2 || rep.Domains[0].Completed || rep.Domains[1].Completed {
					t.Fatalf("report = %+v", rep.Domains)
				}
				if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn)); n != tc.rows {
					t.Fatalf("rows = %d, want %d (what was committed before the stop)", n, tc.rows)
				}
				if n := e.count(t, `SELECT count(*) FROM public.nc_sync_passes WHERE connection_id = $1::uuid AND last_pass_at IS NOT NULL`, string(e.conn)); n != 0 {
					t.Fatalf("%d passes recorded after a stop", n)
				}
				for _, nc := range []uint64{ncA, ncB} {
					if c := e.get(t, e.key(t, gtext(nc))); c.State != tc.state || !c.LastFullSync.IsZero() {
						t.Fatalf("cursor %x = %+v, want %s and no full sync", nc, c, tc.state)
					}
				}
			})
		})
	}
}

type failingIngest struct{ err error }

func (f failingIngest) Ingest(context.Context, store.Tx, inventory.Cycle) (inventory.Ingested, error) {
	return inventory.Ingested{}, f.err
}

// TestFullCycleLogsOnlyAFixedClass: a store error that repeats a bound value (as a PgError message can)
// reaches the caller but never the log.
func TestFullCycleLogsOnlyAFixedClass(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		r := e.rig(t, newFake(twoDomains().doms...), ncA)
		r.eng.Ingester = failingIngest{err: errors.New("invalid input syntax for type uuid: \"" + leakSentinel + "\"")}
		_, err := r.run(context.Background())
		if err == nil {
			t.Fatal("a failing ingest was a success")
		}
		out := r.logs.String()
		if strings.Contains(out, "SENTINEL") || strings.Contains(out, "invalid input") {
			t.Fatalf("a database error text reached the log:\n%s", out)
		}
		if !strings.Contains(out, `"error_phase":"store"`) || !strings.Contains(out, `"error_class":"other"`) {
			t.Fatalf("the log carries no fixed error class:\n%s", out)
		}
	})
}
