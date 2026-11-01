package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const (
	ncA = "bbbbbbbb-0000-4000-8000-0000000000a1"
	ncB = "bbbbbbbb-0000-4000-8000-0000000000a2"
	ncC = "bbbbbbbb-0000-4000-8000-0000000000a3"
)

func ncOID(t *testing.T, s string) authz.ObjectID {
	t.Helper()
	id, err := authz.ParseObjectID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) pass(t *testing.T, c inventory.ConnectionID, nc string, at time.Time) error {
	t.Helper()
	return e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error { return w.RecordPass(ctx, tx, c, inventory.GUID(nc), at) })
}

func (e *env) mark(t *testing.T, c inventory.ConnectionID, nc string, s inventory.PassState) {
	t.Helper()
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error { return w.MarkNC(ctx, tx, c, inventory.GUID(nc), s) }); err != nil {
		t.Fatal(err)
	}
}

func (e *env) fresh(t *testing.T, now time.Time, threshold time.Duration, cs ...inventory.ConnectionID) inventory.FreshnessResult {
	t.Helper()
	r, err := e.r.Freshness(context.Background(), e.a, inventory.FreshnessQuery{Connections: cs, Now: now, Threshold: threshold})
	if err != nil {
		t.Fatalf("Freshness: %v", err)
	}
	return r
}

// suspend takes an AD connection through the DM-10 lifecycle to suspended.
func (e *env) suspend(t *testing.T, c inventory.ConnectionID) {
	t.Helper()
	ctx := context.Background()
	reg := connection.NewRegistry(e.db)
	id := connection.ID(c)
	if _, err := reg.Transition(ctx, e.a, id, connection.StateDraft, connection.StateVerifying); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.SetDirectoryIdentity(ctx, e.a, id, connection.DirectoryIdentity("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")); err != nil {
		t.Fatal(err)
	}
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		if _, err := (connection.Store{}).RecordVerification(ctx, tx, connection.NewVerification{
			ID: "00000000-0000-4000-b000-000000000001", ConnectionID: id, CredentialID: cred, Kind: connection.KindManual,
			RequestedBy: "principal-test", StartedAt: time.Now(), CheckListVersion: 1, Verdict: connection.VerdictPass,
			Outcomes: map[connection.Check]connection.Outcome{"V5": connection.OutcomePass,
				connection.CheckV7OverPrivilege: connection.OutcomePass, connection.CheckV8ReadSufficient: connection.OutcomePass},
		}); err != nil {
			return err
		}
		_, err := (connection.Store{}).Activate(ctx, tx, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Transition(ctx, e.a, id, connection.StateActive, connection.StateSuspended); err != nil {
		t.Fatal(err)
	}
}

// AC-09: a quiet domain, no changes for 24 hours, successful passes: the watermark is the last pass and
// the state is not stale.
func TestFreshnessQuietDomainIsNotStale(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		now := t1.Add(24 * time.Hour)
		// The last (and only) change was observed 24 hours ago; passes ran since, finding nothing.
		if _, err := e.populate(t, e.adA, t1, adUser(usr1, nc1)); err != nil {
			t.Fatal(err)
		}
		for _, at := range []time.Time{t1.Add(8 * time.Hour), t1.Add(16 * time.Hour), now.Add(-5 * time.Minute)} {
			if err := e.pass(t, e.adA, nc1, at); err != nil {
				t.Fatal(err)
			}
		}
		r := e.fresh(t, now, 0, e.adA)
		want := now.Add(-5 * time.Minute)
		if r.Label.State != report.FreshnessSynced || !r.Label.AsOf.Equal(want) || len(r.Label.Stale) != 0 || len(r.Label.NotSynced) != 0 {
			t.Fatalf("label %+v, want synced as of %s", r.Label, want)
		}
		if n, ok := r.Names[e.adA]; !ok || n != "c" || len(r.Names) != 1 {
			t.Fatalf("connection names %v, want the display name of the one covered connection", r.Names)
		}
		if len(r.Watermarks) != 1 || r.Watermarks[0].State != report.NCOK || !r.Watermarks[0].LastPassAt.Equal(want) ||
			r.Watermarks[0].NC != ncOID(t, nc1) || r.Threshold != inventory.DefaultStalenessThreshold {
			t.Fatalf("watermarks %+v", r.Watermarks)
		}
		// The same directory with no pass since the change is stale by age, not by quiet.
		later := now.Add(2 * time.Hour)
		if r := e.fresh(t, later, 0, e.adA); r.Label.State != report.FreshnessStale || r.Label.Stale[0].Age != 2*time.Hour+5*time.Minute {
			t.Fatalf("2 h without a pass: %+v", r.Label)
		}
		// A threshold set by the caller is honoured and reported.
		if r := e.fresh(t, later, 3*time.Hour, e.adA); r.Label.State != report.FreshnessSynced || r.Threshold != 3*time.Hour {
			t.Fatalf("3 h threshold: %+v", r)
		}
	})
}

// AC-10: resync_required and paused (the NC's own, or the connection's suspension) are stale with age and
// cause, and the other NCs are still reported.
func TestFreshnessResyncAndPausedAreStaleAndOthersStillReported(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		now := t1.Add(10 * time.Hour)
		okAt, rsAt, pzAt := now.Add(-3*time.Minute), now.Add(-3*time.Hour), now.Add(-90*time.Minute)
		for nc, at := range map[string]time.Time{ncA: okAt, ncB: rsAt, ncC: pzAt} {
			if err := e.pass(t, e.adA, nc, at); err != nil {
				t.Fatal(err)
			}
		}
		e.mark(t, e.adA, ncB, inventory.PassResyncRequired)
		e.mark(t, e.adA, ncC, inventory.PassPaused)

		r := e.fresh(t, now, 0, e.adA)
		if len(r.Watermarks) != 3 {
			t.Fatalf("all three NCs are reported: %+v", r.Watermarks)
		}
		got := map[authz.ObjectID]report.NCWatermark{}
		for _, m := range r.Watermarks {
			got[m.NC] = m
		}
		for nc, want := range map[string]struct {
			st report.NCState
			at time.Time
		}{ncA: {report.NCOK, okAt}, ncB: {report.NCResyncRequired, rsAt}, ncC: {report.NCPaused, pzAt}} {
			if m := got[ncOID(t, nc)]; m.State != want.st || !m.LastPassAt.Equal(want.at) {
				t.Errorf("%s: %+v, want %v at %s (the pass time survives the state)", nc, m, want.st, want.at)
			}
		}
		l := r.Label
		if l.State != report.FreshnessStale || len(l.Stale) != 2 || !l.AsOf.Equal(rsAt) {
			t.Fatalf("label %+v", l)
		}
		if s0, s1 := l.Stale[0], l.Stale[1]; s0.State != report.NCResyncRequired || s0.Age != 3*time.Hour || s0.NC != ncOID(t, ncB) ||
			s1.State != report.NCPaused || s1.Age != 90*time.Minute || s1.NC != ncOID(t, ncC) {
			t.Fatalf("stale causes %+v", l.Stale)
		}

		// A pass completes the resync: the cause clears.
		if err := e.pass(t, e.adA, ncB, now.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		if r := e.fresh(t, now, 0, e.adA); len(r.Label.Stale) != 1 || r.Label.Stale[0].NC != ncOID(t, ncC) {
			t.Fatalf("after the pass: %+v", r.Label)
		}
	})
}

// A suspended connection reads as paused without any write to inventory, and a recent pass does not hide it.
func TestFreshnessSuspendedConnectionIsPaused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		now := t1.Add(time.Hour)
		if err := e.pass(t, e.adA, nc1, now.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		e.suspend(t, e.adA)
		r := e.fresh(t, now, 0, e.adA)
		if r.Label.State != report.FreshnessStale || len(r.Label.Stale) != 1 || r.Label.Stale[0].State != report.NCPaused || r.Label.Stale[0].Age != time.Minute {
			t.Fatalf("suspended: %+v", r.Label)
		}
	})
}

// AC-11: a connection that never completed a first sync is skipped and not in the oldest watermark.
func TestFreshnessNeverSyncedIsSkipped(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		now := t1.Add(time.Hour)
		synced := now.Add(-10 * time.Minute)
		if err := e.pass(t, e.adA, nc1, synced); err != nil {
			t.Fatal(err)
		}
		fresh := e.conn(t, e.a, connection.KindADForest, connection.TransportLDAPS) // no row at all
		half := e.conn(t, e.a, connection.KindADForest, connection.TransportLDAPS)  // marked before its first pass
		e.mark(t, half, ncA, inventory.PassResyncRequired)

		r := e.fresh(t, now, 0, e.adA, fresh, half)
		l := r.Label
		if l.State != report.FreshnessSynced || !l.AsOf.Equal(synced) || len(l.Stale) != 0 {
			t.Fatalf("the others still decide the label: %+v", l)
		}
		if len(l.NotSynced) != 2 || !(l.NotSynced[0] == ncOID(t, string(fresh)) && l.NotSynced[1] == ncOID(t, string(half)) ||
			l.NotSynced[1] == ncOID(t, string(fresh)) && l.NotSynced[0] == ncOID(t, string(half))) {
			t.Fatalf("skipped %+v", l.NotSynced)
		}
		for _, m := range r.Watermarks {
			if (m.Connection == ncOID(t, string(fresh)) || m.Connection == ncOID(t, string(half))) && (m.State != report.NCNeverSynced || !m.LastPassAt.IsZero()) {
				t.Errorf("never-synced watermark %+v", m)
			}
		}
		// Only never-synced connections: not synced yet, and no as-of is invented.
		if l := e.fresh(t, now, 0, fresh).Label; l.State != report.FreshnessNotSyncedYet || !l.AsOf.IsZero() {
			t.Fatalf("only skipped: %+v", l)
		}
	})
}

// AC-08: several covered NCs, as_of is the oldest covered watermark, whichever connection holds it.
func TestFreshnessAsOfIsTheOldestCoveredWatermark(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		now := t1.Add(time.Hour)
		other := e.conn(t, e.a, connection.KindADForest, connection.TransportLDAPS)
		at := map[string]time.Time{ncA: now.Add(-5 * time.Minute), ncB: now.Add(-40 * time.Minute), ncC: now.Add(-20 * time.Minute)}
		for nc, a := range at {
			if err := e.pass(t, e.adA, nc, a); err != nil {
				t.Fatal(err)
			}
		}
		if err := e.pass(t, other, ncA, now.Add(-30*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if r := e.fresh(t, now, 0, e.adA, other); r.Label.State != report.FreshnessSynced || !r.Label.AsOf.Equal(at[ncB]) || len(r.Watermarks) != 4 {
			t.Fatalf("%+v", r)
		}
		// Only the covered connections count: the older NC of adA does not reach a read of `other`.
		if r := e.fresh(t, now, 0, other); !r.Label.AsOf.Equal(now.Add(-30 * time.Minute)) {
			t.Fatalf("scoped to one connection: %+v", r.Label)
		}
	})
}

func TestRecordPassIsMonotonicAndValidated(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		at := t1
		if err := e.pass(t, e.adA, nc1, at); err != nil {
			t.Fatal(err)
		}
		if err := e.pass(t, e.adA, nc1, at.Add(-time.Second)); !errors.Is(err, inventory.ErrStale) {
			t.Fatalf("older pass: %v, want ErrStale", err)
		}
		if err := e.pass(t, e.adA, nc1, at); err != nil { // a repeat of the same pass is idempotent
			t.Fatalf("same pass: %v", err)
		}
		if r := e.fresh(t, at.Add(time.Minute), 0, e.adA); !r.Label.AsOf.Equal(at) {
			t.Fatalf("the watermark did not move back: %+v", r.Label)
		}
		if err := e.pass(t, e.adA, nc1, time.Now().Add(time.Hour)); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatalf("future pass: %v", err)
		}
		for name, fn := range map[string]func(ctx context.Context, tx store.Tx) error{
			"zero as-of": func(ctx context.Context, tx store.Tx) error { return w.RecordPass(ctx, tx, e.adA, nc1, time.Time{}) },
			"bad NC":     func(ctx context.Context, tx store.Tx) error { return w.RecordPass(ctx, tx, e.adA, "nope", at) },
			"zero NC": func(ctx context.Context, tx store.Tx) error {
				return w.RecordPass(ctx, tx, e.adA, "00000000-0000-0000-0000-000000000000", at)
			},
			"upper-case NC": func(ctx context.Context, tx store.Tx) error {
				return w.RecordPass(ctx, tx, e.adA, "BBBBBBBB-0000-4000-8000-000000000001", at)
			},
			"mark ok":   func(ctx context.Context, tx store.Tx) error { return w.MarkNC(ctx, tx, e.adA, nc1, "ok") },
			"mark junk": func(ctx context.Context, tx store.Tx) error { return w.MarkNC(ctx, tx, e.adA, nc1, "x") },
		} {
			if err := e.tx(t, e.a, fn); !errors.Is(err, inventory.ErrInvalid) {
				t.Errorf("%s: %v, want ErrInvalid", name, err)
			}
		}
		// Another tenant's connection is not ours to write.
		err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error { return w.RecordPass(ctx, tx, e.adB, nc1, at) })
		if !errors.Is(err, inventory.ErrUnknownConnection) {
			t.Fatalf("foreign connection: %v", err)
		}
		// The database holds the line whichever writer holds the pen.
		if err := e.exec(e.a, `UPDATE public.nc_sync_passes SET last_pass_at = last_pass_at - interval '1 hour'`); err == nil {
			t.Fatal("the guard trigger let last_pass_at move back")
		}
		if err := e.exec(e.a, `UPDATE public.nc_sync_passes SET last_pass_at = NULL, state = 'paused'`); err == nil {
			t.Fatal("the guard trigger let last_pass_at be cleared")
		}
		if err := e.exec(e.a, `INSERT INTO public.nc_sync_passes (tenant_id, connection_id, nc_guid, state)
			VALUES (current_setting('app.tenant_id')::uuid, $1::uuid, $2::uuid, 'ok')`, string(e.adA), ncA); err == nil {
			t.Fatal("state ok without a pass time was accepted")
		}
	})
}

func TestFreshnessFailsClosed(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		now := t1
		for name, q := range map[string]inventory.FreshnessQuery{
			"no connections": {Now: now},
			"no now":         {Connections: []inventory.ConnectionID{e.adA}},
			"negative":       {Connections: []inventory.ConnectionID{e.adA}, Now: now, Threshold: -1},
			"bad id":         {Connections: []inventory.ConnectionID{"x"}, Now: now},
		} {
			if _, err := e.r.Freshness(ctx, e.a, q); !errors.Is(err, inventory.ErrInvalid) {
				t.Errorf("%s: %v, want ErrInvalid", name, err)
			}
		}
		// A connection that is not the tenant's is never dropped from a freshness claim.
		if _, err := e.r.Freshness(ctx, e.a, inventory.FreshnessQuery{Connections: []inventory.ConnectionID{e.adA, e.adB}, Now: now}); !errors.Is(err, inventory.ErrUnknownConnection) {
			t.Errorf("foreign connection: %v", err)
		}
		if _, err := e.r.Freshness(ctx, e.a, inventory.FreshnessQuery{Connections: make([]inventory.ConnectionID, inventory.MaxFreshnessConnections+1), Now: now}); !errors.Is(err, inventory.ErrTooMany) {
			t.Errorf("too many: %v", err)
		}
		// Duplicates are one connection, not two reports of it.
		if r := e.fresh(t, now, 0, e.adA, e.adA); len(r.Watermarks) != 1 {
			t.Errorf("duplicate connection: %+v", r.Watermarks)
		}
		// Tenant isolation: B sees none of A's watermarks.
		if err := e.pass(t, e.adA, nc1, now); err != nil {
			t.Fatal(err)
		}
		r, err := e.r.Freshness(ctx, e.b, inventory.FreshnessQuery{Connections: []inventory.ConnectionID{e.adB}, Now: now})
		if err != nil || r.Label.State != report.FreshnessNotSyncedYet {
			t.Fatalf("tenant B: %+v %v", r, err)
		}
	})
}

// Ingest records the pass on the last batch only, for a quiet cycle as well, and a failed cycle records none.
func TestIngestRecordsPassOnLastBatchOnly(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ing := inventory.Ingester{Classifier: stubClassifier{at: t1}}
		run := func(c inventory.Cycle) error {
			return e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error { _, err := ing.Ingest(ctx, tx, c); return err })
		}
		cyc := inventory.Cycle{Connection: e.adA, Observed: t1, Now: t1, PassNCs: []inventory.GUID{nc1}}
		first := cyc
		first.Observations, first.MoreBatches = []inventory.Observation{adUser(usr1, nc1)}, true
		if err := run(first); err != nil {
			t.Fatal(err)
		}
		if n := e.count(t, `SELECT count(*) FROM public.nc_sync_passes`); n != 0 {
			t.Fatalf("a pass was recorded before the last batch: %d", n)
		}
		last := cyc
		last.Observations = []inventory.Observation{adUser(usr2, nc1)}
		if err := run(last); err != nil {
			t.Fatal(err)
		}
		if r := e.fresh(t, t1.Add(time.Minute), 0, e.adA); !r.Label.AsOf.Equal(t1) || r.Label.State != report.FreshnessSynced {
			t.Fatalf("after the cycle: %+v", r.Label)
		}
		// A quiet cycle (no observations) is still a pass.
		quiet := inventory.Cycle{Connection: e.adA, Observed: t1.Add(30 * time.Minute), Now: t1.Add(30 * time.Minute), PassNCs: []inventory.GUID{nc1}}
		if err := run(quiet); err != nil {
			t.Fatal(err)
		}
		if r := e.fresh(t, t1.Add(31*time.Minute), 0, e.adA); !r.Label.AsOf.Equal(t1.Add(30 * time.Minute)) {
			t.Fatalf("after a quiet cycle: %+v", r.Label)
		}
		// A cycle that fails rolls its pass back with its rows.
		bad := inventory.Cycle{Connection: e.adA, Observed: t1.Add(time.Hour), Now: t1.Add(time.Hour), PassNCs: []inventory.GUID{"nope"}}
		if err := run(bad); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatalf("bad pass NC: %v", err)
		}
		if r := e.fresh(t, t1.Add(2*time.Hour), 0, e.adA); !r.Label.AsOf.Equal(t1.Add(30 * time.Minute)) {
			t.Fatalf("rolled back: %+v", r.Label)
		}
	})
}
