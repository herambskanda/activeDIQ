package sync_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	gosync "sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/jobs/jobstest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// jrig is one node's sync.full: its own job registry, holder and log over the shared database.
type jrig struct {
	e    *env
	reg  *jobs.Registry
	jobs *dsync.Jobs
	logs *bytes.Buffer
}

func (e *env) jobRig(t *testing.T, eng dsync.Cycler, holder string, ttl time.Duration) *jrig {
	t.Helper()
	logs := &bytes.Buffer{}
	reg := jobs.NewRegistry()
	j, err := dsync.RegisterJobs(reg, dsync.JobConfig{DB: e.db, Cycle: eng, Passes: inventory.Writer{}, Holder: holder, LeaseTTL: ttl,
		Log: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatalf("RegisterJobs: %v", err)
	}
	return &jrig{e: e, reg: reg, jobs: j, logs: logs}
}

func (j *jrig) enqueue(t *testing.T) jobs.Enqueued {
	t.Helper()
	var out jobs.Enqueued
	err := j.e.tx(j.e.a, func(ctx context.Context, tx store.Tx) error {
		var err error
		out, err = j.jobs.Enqueue(ctx, tx, j.e.a, connection.ID(j.e.conn))
		return err
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	return out
}

// exec claims one queued job and runs it to its recorded outcome.
func (j *jrig) exec(t *testing.T) (jobs.Result, error) {
	t.Helper()
	cl, err := jobs.Claim(context.Background(), j.e.db, j.reg.Leases(), 1)
	if err != nil || len(cl) != 1 {
		t.Fatalf("claim: %v %v", cl, err)
	}
	return jobs.NewRunner(j.e.db, j.reg).Execute(context.Background(), cl[0])
}

func (e *env) jobStrings(t *testing.T, q string, args ...any) []string {
	t.Helper()
	out, err := e.d.OwnerStrings(context.Background(), q, args...)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return out
}

// query is e.d.OwnerStrings in the shape jobstest wants.
func (e *env) query(sql string, args ...any) ([]string, error) {
	return e.d.OwnerStrings(context.Background(), sql, args...)
}

func (e *env) freshness(t *testing.T) inventory.FreshnessResult {
	t.Helper()
	res, err := inventory.NewReader(e.db, nil).Freshness(context.Background(), e.a, inventory.FreshnessQuery{
		Connections: []inventory.ConnectionID{e.conn}, Now: time.Now()})
	if err != nil {
		t.Fatalf("Freshness: %v", err)
	}
	return res
}

// TestSyncFullJobFillsInventory: the job reads the connection under its leases, the inventory is filled, the
// freshness read reports the data's age, the leases are given up, and a second enqueue while one is queued
// is a duplicate.
func TestSyncFullJobFillsInventory(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		r := e.rig(t, newFake(fo.doms...), ncA, ncB)
		jr := e.jobRig(t, r.eng, "node-1", time.Minute)

		before := e.freshness(t)
		if before.Label.State != report.FreshnessNotSyncedYet {
			t.Fatalf("before the first read the label is %v", before.Label.State)
		}
		if first := jr.enqueue(t); first.Duplicate {
			t.Fatal("first enqueue was a duplicate")
		}
		if again := jr.enqueue(t); !again.Duplicate {
			t.Fatal("a second enqueue for the same connection must be a duplicate")
		}
		res, err := jr.exec(t)
		if err != nil || res != jobs.Completed {
			t.Fatalf("exec: %v %v\n%s", res, err, jr.logs)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn)); n != fo.count {
			t.Fatalf("rows = %d, want %d", n, fo.count)
		}
		after := e.freshness(t)
		if after.Label.State != report.FreshnessSynced || after.Label.AsOf.IsZero() {
			t.Fatalf("after the read the label is %+v", after.Label)
		}
		if len(after.Watermarks) != 2 {
			t.Fatalf("watermarks = %d, want one per domain NC", len(after.Watermarks))
		}
		live := e.jobStrings(t, `SELECT name FROM public.platform_leases WHERE name LIKE 'sync.cursor.%' AND expires_at > now()`)
		if len(live) != 0 {
			t.Fatalf("leases still held after the job: %v", live)
		}
		// The next enqueue after completion is allowed (the cadence), and finds the domains done.
		if again := jr.enqueue(t); again.Duplicate {
			t.Fatal("an enqueue after completion must be accepted")
		}
		if res, err := jr.exec(t); err != nil || res != jobs.Completed {
			t.Fatalf("second exec: %v %v", res, err)
		}
	})
}

// TestSyncFullTwoNodesOneReader is acceptance 3: with two nodes enqueuing for the same connection, exactly
// one holds each NC lease; the other exits as lease held and reads nothing from the directory.
func TestSyncFullTwoNodesOneReader(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		fa := newFake(fo.doms...)
		fb := newFake(fo.doms...)
		ra := e.rig(t, fa, ncA, ncB)
		engB := *ra.eng
		engB.Source = &connSource{cc: fb}
		a := e.jobRig(t, ra.eng, "node-a", time.Minute)
		b := e.jobRig(t, &engB, "node-b", time.Minute)

		// Node A blocks inside its first batch, holding the leases.
		started, release := make(chan struct{}), make(chan struct{})
		var once gosync.Once
		fa.onBatch = func() {
			once.Do(func() { close(started) })
			<-release
		}
		a.enqueue(t)
		jobstest.MakeDueUnderKey(t, e.d.ExecOwner, dsync.JobFull, "node-a") // node A's row; the unique key is free again
		type out struct {
			res jobs.Result
			err error
		}
		done := make(chan out, 1)
		go func() { r, err := a.exec(t); done <- out{r, err} }()
		<-started

		// Node B enqueues for the same connection and runs while A reads.
		if b.enqueue(t).Duplicate {
			t.Fatal("B's job should be queued (A's row has its own key)")
		}
		res, err := b.exec(t)
		if err != nil || res != jobs.Completed {
			t.Fatalf("B exec: %v %v\n%s", res, err, b.logs)
		}
		if s, d := fb.calls(); len(s) != 0 || d != 0 {
			t.Fatalf("node B touched the directory: %d searches, %d describes", len(s), d)
		}
		if !bytes.Contains(b.logs.Bytes(), []byte("lease held by another node")) {
			t.Fatalf("B did not log the held lease:\n%s", b.logs)
		}
		holders := e.jobStrings(t, `SELECT holder FROM public.platform_leases WHERE name LIKE 'sync.cursor.%' AND expires_at > now() GROUP BY holder`)
		if len(holders) != 1 || holders[0] != "node-a" {
			t.Fatalf("lease holders = %v, want only node-a", holders)
		}
		close(release)
		o := <-done
		if o.err != nil || o.res != jobs.Completed {
			t.Fatalf("A exec: %v %v", o.res, o.err)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn)); n != fo.count {
			t.Fatalf("rows = %d, want %d", n, fo.count)
		}
	})
}

// TestSyncFullTakeoverAfterExpiry: a holder that dies without releasing blocks the others only until its
// lease expires; the next holder then reads under a higher fencing token.
func TestSyncFullTakeoverAfterExpiry(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		fb := newFake(fo.doms...)
		r := e.rig(t, fb, ncA, ncB)
		b := e.jobRig(t, r.eng, "node-b", 2*time.Second)

		// The dead node held both leases and never renewed or released them.
		dead := map[string]int64{}
		for _, nc := range []uint64{ncA, ncB} {
			k := e.key(t, gtext(nc))
			l := e.leaseFor(t, k, "node-dead", 600*time.Millisecond)
			dead[l.Name] = l.Token
		}
		b.enqueue(t)
		res, err := b.exec(t)
		if err != nil || res != jobs.Completed {
			t.Fatalf("exec while the dead holder's lease is live: %v %v", res, err)
		}
		if s, d := fb.calls(); len(s) != 0 || d != 0 {
			t.Fatalf("read while the lease was held: %d searches", len(s))
		}
		time.Sleep(700 * time.Millisecond)
		b.enqueue(t)
		res, err = b.exec(t)
		if err != nil || res != jobs.Completed {
			t.Fatalf("exec after expiry: %v %v\n%s", res, err, b.logs)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn)); n != fo.count {
			t.Fatalf("rows = %d, want %d", n, fo.count)
		}
		for _, nc := range []uint64{ncA, ncB} {
			k := e.key(t, gtext(nc))
			name, _ := dsync.LeaseName(k)
			var cur dsync.Cursor
			if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
				var err error
				cur, err = e.store.Get(ctx, tx, k)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if cur.FencingToken <= dead[name] {
				t.Fatalf("cursor token %d did not rise above the dead holder's %d", cur.FencingToken, dead[name])
			}
		}
	})
}

// TestSyncFullRenewsAndAbortsOnLoss: a lease is renewed while the run works (it outlives its TTL), and a
// lease that is lost mid-run aborts the run with the lease_lost code instead of writing on.
func TestSyncFullRenewsAndAbortsOnLoss(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		f := newFake(fo.doms...)
		r := e.rig(t, f, ncA)
		j := e.jobRig(t, r.eng, "node-1", 600*time.Millisecond)

		// A read longer than the TTL: the renewal keeps the lease.
		var once gosync.Once
		f.onBatch = func() { once.Do(func() { time.Sleep(1500 * time.Millisecond) }) }
		j.enqueue(t)
		res, err := j.exec(t)
		if err != nil || res != jobs.Completed {
			t.Fatalf("a read longer than the lease TTL must complete: %v %v\n%s", res, err, j.logs)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(e.conn)); n != 650 {
			t.Fatalf("rows = %d, want 650", n)
		}
	})
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		f := newFake(fo.doms...)
		r := e.rig(t, f, ncA)
		j := e.jobRig(t, r.eng, "node-1", 600*time.Millisecond)

		// The lease is taken from under the run (its row expires, as after a stalled node): the next renewal
		// is ErrLeaseLost and the run stops.
		var once gosync.Once
		f.onBatch = func() {
			once.Do(func() {
				if err := e.d.ExecOwner(context.Background(), `UPDATE public.platform_leases SET expires_at = now() - interval '1 second' WHERE name LIKE 'sync.cursor.%'`); err != nil {
					t.Error(err)
				}
				time.Sleep(900 * time.Millisecond)
			})
		}
		j.enqueue(t)
		res, err := j.exec(t)
		if err != nil || res != jobs.Retried {
			t.Fatalf("a lost lease must fail the run for a retry: %v %v\n%s", res, err, j.logs)
		}
		codes, _ := jobstest.QueuedErrorCodes(e.query, dsync.JobFull, 1)
		if len(codes) != 1 || codes[0] != dsync.CodeLeaseLost {
			t.Fatalf("error code = %v, want %s", codes, dsync.CodeLeaseLost)
		}
		if n := e.count(t, `SELECT count(*) FROM public.nc_sync_passes WHERE connection_id = $1::uuid AND last_pass_at IS NOT NULL`, string(e.conn)); n != 0 {
			t.Fatalf("a pass was recorded by a run that lost its lease")
		}
	})
}

// faultConn is a connector whose ScopedSearch fails with a status that carries a directory value in its message.
type faultConn struct {
	*fakeConnector
	code codes.Code
}

func (f faultConn) ScopedSearch(context.Context, *connectorv1.ScopedSearchRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[connectorv1.ScopedSearchResponse], error) {
	return nil, status.Error(f.code, "failed: "+leakSentinel)
}

func (e *env) requireResync(t *testing.T, nc uint64) {
	t.Helper()
	k := e.key(t, gtext(nc))
	l := e.leaseFor(t, k, "setup", time.Minute)
	if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		_, err := e.store.RequireResync(ctx, tx, k, l)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	name, _ := dsync.LeaseName(k)
	if err := jobs.ReleaseLease(context.Background(), e.db, l); err != nil {
		t.Fatalf("release %s: %v", name, err)
	}
}

// TestSyncFullFaults is acceptance 4: an unreachable connector and a stale-cookie-class error fail the run
// into the platform backoff, record no pass, show the cause in freshness, leak nothing, and heal on the next run.
func TestSyncFullFaults(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		f := newFake(fo.doms...)
		r := e.rig(t, f, ncA)
		j := e.jobRig(t, r.eng, "node-1", time.Minute)

		// Unreachable: retried, no pass, no rows beyond what committed, nothing leaked.
		r.eng.Source = &connSource{cc: faultConn{f, codes.Unavailable}}
		j.enqueue(t)
		res, err := j.exec(t)
		if err != nil || res != jobs.Retried {
			t.Fatalf("unreachable: %v %v", res, err)
		}
		cs, _ := jobstest.QueuedErrorCodes(e.query, dsync.JobFull, 1)
		if len(cs) != 1 || cs[0] != dsync.CodeUnreachable {
			t.Fatalf("code = %v, want %s", cs, dsync.CodeUnreachable)
		}
		if n := e.count(t, `SELECT count(*) FROM public.nc_sync_passes WHERE connection_id = $1::uuid AND last_pass_at IS NOT NULL`, string(e.conn)); n != 0 {
			t.Fatal("a pass was recorded for a failed run")
		}
		if got := e.freshness(t).Label.State; got != report.FreshnessNotSyncedYet {
			t.Fatalf("label after a failed first read = %v, want not synced yet", got)
		}

		// The connector heals: the retry completes the read.
		r.eng.Source = &connSource{cc: f}
		jobstest.MakeDue(t, e.d.ExecOwner, dsync.JobFull)
		if res, err := j.exec(t); err != nil || res != jobs.Completed {
			t.Fatalf("retry: %v %v\n%s", res, err, j.logs)
		}
		if got := e.freshness(t).Label.State; got != report.FreshnessSynced {
			t.Fatalf("label after the retry = %v", got)
		}

		// Stale-cookie class on a connection that was synced before: the cursor needs a resync, the connector
		// says the position is unusable (FAILED_PRECONDITION), and the freshness label shows that cause.
		e.requireResync(t, ncA)
		r.eng.Source = &connSource{cc: faultConn{f, codes.FailedPrecondition}}
		j.enqueue(t)
		res, err = j.exec(t)
		if err != nil || res != jobs.Retried {
			t.Fatalf("stale cookie: %v %v", res, err)
		}
		cs, _ = jobstest.QueuedErrorCodes(e.query, dsync.JobFull, 1)
		if len(cs) != 1 || cs[0] != dsync.CodeStaleCookie {
			t.Fatalf("code = %v, want %s", cs, dsync.CodeStaleCookie)
		}
		fr := e.freshness(t)
		if fr.Label.State != report.FreshnessStale || len(fr.Label.Stale) != 1 || fr.Label.Stale[0].State != report.NCResyncRequired {
			t.Fatalf("freshness label does not show the stale cause: %+v", fr.Label)
		}

		for _, b := range [][]byte{j.logs.Bytes(), r.logs.Bytes()} {
			if bytes.Contains(b, []byte(leakSentinel)) {
				t.Fatalf("a directory value reached the log:\n%s", b)
			}
		}
		stored := e.jobStrings(t, `SELECT coalesce(error_code, '') FROM public.jobs WHERE kind = $1`, dsync.JobFull)
		for _, s := range stored {
			if bytes.Contains([]byte(s), []byte(leakSentinel)) {
				t.Fatalf("a directory value reached the job row: %q", s)
			}
		}

		// The resync completes when the connector is back: the stale cause clears.
		r.eng.Source = &connSource{cc: f}
		jobstest.MakeDue(t, e.d.ExecOwner, dsync.JobFull)
		if res, err := j.exec(t); err != nil || res != jobs.Completed {
			t.Fatalf("resync: %v %v\n%s", res, err, j.logs)
		}
		if got := e.freshness(t).Label.State; got != report.FreshnessSynced {
			t.Fatalf("label after the resync = %v", got)
		}
	})
}

// TestSyncFullRefusesAndRightsFailuresDoNotRetry: a connection that is not active is discarded without a
// connector call, and a rights refusal from the connector is not retried (a permissions error must not
// become a retry storm against a DC).
func TestSyncFullRefusesAndRightsFailuresDoNotRetry(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		fo := twoDomains()
		f := newFake(fo.doms...)
		r := e.rig(t, f, ncA)
		j := e.jobRig(t, r.eng, "node-1", time.Minute)

		r.eng.Source = &connSource{cc: faultConn{f, codes.PermissionDenied}}
		j.enqueue(t)
		if res, err := j.exec(t); err != nil || res != jobs.Discarded {
			t.Fatalf("a rights refusal must be discarded, not retried: %v %v", res, err)
		}
		codes := e.jobStrings(t, `SELECT coalesce(error_code, '') FROM public.jobs WHERE kind = $1 AND state = 'discarded'`, dsync.JobFull)
		if len(codes) != 1 || codes[0] != dsync.CodeInsufficient {
			t.Fatalf("code = %v", codes)
		}

		e.suspend(t, e.conn)
		r.eng.Source = &connSource{cc: f}
		s0, d0 := f.calls() // the rights-refusal run above described the directory already
		j.enqueue(t)
		if res, err := j.exec(t); err != nil || res != jobs.Discarded {
			t.Fatalf("a suspended connection must be discarded: %v %v", res, err)
		}
		if s, d := f.calls(); len(s) != len(s0) || d != d0 {
			t.Fatalf("a suspended connection was read: %d searches, %d describes", len(s)-len(s0), d-d0)
		}
	})
}

func TestRegisterJobsNeedsItsPorts(t *testing.T) {
	_, err := dsync.RegisterJobs(jobs.NewRegistry(), dsync.JobConfig{})
	if !errors.Is(err, dsync.ErrNotConfigured) {
		t.Fatalf("RegisterJobs with nothing: %v", err)
	}
}
