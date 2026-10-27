package audit_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/jobs/jobstest"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// worker is one audit-job worker: its own registry, runner and lease holder, sharing the database.
type worker struct {
	j   *audit.Jobs
	run *jobs.Runner
	reg *jobs.Registry
}

type fakeSink struct {
	mu      sync.Mutex
	got     []audit.Record
	calls   int
	failAt  map[int]bool // 1-based call numbers that fail
	failAll bool
}

func (s *fakeSink) Deliver(_ context.Context, _ tenant.ID, b []audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failAll || s.failAt[s.calls] {
		return errors.New("sink down")
	}
	s.got = append(s.got, b...)
	return nil
}

func (r *rig) worker(holder string, sink audit.ForwardSink, mut func(*audit.JobsConfig)) *worker {
	r.t.Helper()
	reg := jobs.NewRegistry()
	cfg := audit.JobsConfig{DB: r.db, Checkpointer: r.cp, Registry: reg, Holder: holder,
		CheckpointEvents: 1, CheckpointMaxAge: time.Hour, CheckpointTick: 20 * time.Millisecond, ForwardTick: 20 * time.Millisecond}
	if sink != nil {
		cfg.Sinks = func(_ tenant.ID, id string) (audit.ForwardSink, bool) { return sink, id == "siem" }
	}
	if mut != nil {
		mut(&cfg)
	}
	j, err := audit.RegisterJobs(cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return &worker{j: j, run: jobs.NewRunner(r.db, reg), reg: reg}
}

func (r *rig) claim(w *worker, kind string) []jobs.Claimed {
	r.t.Helper()
	var kinds []jobs.KindLease
	for _, k := range w.reg.TenantLeases() {
		if k.Kind == kind {
			kinds = append(kinds, k)
		}
	}
	cs, err := jobs.Claim(context.Background(), r.db, kinds, 10)
	if err != nil {
		r.t.Fatal(err)
	}
	return cs
}

// runDue makes every queued job of the kind runnable now, claims and executes one.
func (r *rig) runDue(w *worker, kind string) jobs.Result {
	r.t.Helper()
	// A job runs in a later interval bucket than the one that queued it; the cadence relies on that.
	time.Sleep(25 * time.Millisecond)
	jobstest.MakeDue(r.t, r.d.ExecOwner, kind)
	cs := r.claim(w, kind)
	if len(cs) == 0 {
		r.t.Fatalf("no %s job to run", kind)
	}
	res, err := w.run.Execute(context.Background(), cs[0])
	if err != nil {
		r.t.Fatal(err)
	}
	return res
}

func (r *rig) schedule(w *worker, f func(ctx context.Context, tx store.Tx) error) {
	r.t.Helper()
	if err := r.db.WithTenant(context.Background(), r.id, f); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) checkpointCount() int {
	r.t.Helper()
	v, err := r.adminStrings(`SELECT count(*)::text FROM audit_checkpoint WHERE tenant_id = $1::uuid`, r.id.String())
	if err != nil {
		r.t.Fatal(err)
	}
	var n int
	fmt.Sscan(v[0], &n)
	return n
}

func (r *rig) verifyChain() {
	r.t.Helper()
	b := r.export(r.id)
	if res := chain.Verify(b, r.pin(r.id)); res.Status != chain.OK {
		r.t.Fatalf("chain does not verify: %+v", res)
	}
	var prev uint64
	for _, c := range b.Checkpoints {
		if c.PrevSeq != prev {
			r.t.Fatalf("checkpoint %d names predecessor %d; want %d: the checkpoint chain forked or has a gap", c.Seq, c.PrevSeq, prev)
		}
		prev = c.Seq
	}
}

// Acceptance 1: two workers fire together, the lease and the signer lock leave exactly one checkpoint.
func TestCheckpointJobSignsOncePerIntervalWithTwoWorkers(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		w1, w2 := r.worker("w1", nil, nil), r.worker("w2", nil, nil)
		r.schedule(w1, func(ctx context.Context, tx store.Tx) error { return w1.j.ScheduleCheckpoint(ctx, tx, r.id) })
		r.append(r.id, "e1", "e2", "e3")
		cs := r.claim(w1, audit.JobCheckpoint)
		if len(cs) != 1 {
			t.Fatalf("claimed %d checkpoint jobs; want 1", len(cs))
		}
		var wg sync.WaitGroup
		for _, w := range []*worker{w1, w2} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := w.run.Execute(context.Background(), cs[0]); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if n := r.checkpointCount(); n != 1 {
			t.Fatalf("checkpoints = %d; want exactly 1", n)
		}
		// The next interval's run is queued, and with nothing new it signs nothing.
		if res := r.runDue(w2, audit.JobCheckpoint); res != jobs.Completed {
			t.Fatalf("next run = %s", res)
		}
		if n := r.checkpointCount(); n != 1 {
			t.Fatalf("checkpoints after an idle interval = %d; want 1", n)
		}
		r.verifyChain()
	})
}

func TestCheckpointCadenceSignsOnEventCountOrAge(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		w := r.worker("w1", nil, func(c *audit.JobsConfig) { c.CheckpointEvents = 3; c.CheckpointMaxAge = time.Hour })
		r.schedule(w, func(ctx context.Context, tx store.Tx) error { return w.j.ScheduleCheckpoint(ctx, tx, r.id) })
		r.append(r.id, "e1")
		r.runDue(w, audit.JobCheckpoint) // first checkpoint: nothing before it
		if n := r.checkpointCount(); n != 1 {
			t.Fatalf("first checkpoint missing: %d", n)
		}
		r.append(r.id, "e2")
		r.runDue(w, audit.JobCheckpoint)
		if n := r.checkpointCount(); n != 1 {
			t.Fatalf("1 new event signed early: %d checkpoints", n)
		}
		r.append(r.id, "e3", "e4")
		r.runDue(w, audit.JobCheckpoint)
		if n := r.checkpointCount(); n != 2 {
			t.Fatalf("3 new events not signed: %d checkpoints", n)
		}
		// Age: one new event, and the last checkpoint is old enough.
		r.append(r.id, "e5")
		if err := r.admin(`UPDATE audit_checkpoint SET signed_at = now() - interval '2 hours' WHERE tenant_id = $1::uuid`, r.id.String()); err != nil {
			t.Fatal(err)
		}
		r.runDue(w, audit.JobCheckpoint)
		if n := r.checkpointCount(); n != 3 {
			t.Fatalf("an old checkpoint with one new event was not renewed: %d", n)
		}
	})
}

// Acceptance 2: a holder that died with the lease blocks others until it expires; then another worker
// resumes and the checkpoint chain has no gap and no duplicate.
func TestCheckpointResumesAfterLeaseExpiryWithoutGapOrDuplicate(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		w2 := r.worker("w2", nil, nil)
		r.schedule(w2, func(ctx context.Context, tx store.Tx) error { return w2.j.ScheduleCheckpoint(ctx, tx, r.id) })
		r.append(r.id, "e1", "e2")
		// w1 takes the lease and "crashes": no renew, no release.
		name := "audit.checkpoint." + hex32(r.id)
		if _, ok, err := jobs.AcquireLease(context.Background(), r.db, name, "w1", 700*time.Millisecond); err != nil || !ok {
			t.Fatalf("w1 lease = %v, %v", ok, err)
		}
		r.runDue(w2, audit.JobCheckpoint)
		if n := r.checkpointCount(); n != 0 {
			t.Fatalf("w2 signed while w1 held the lease: %d", n)
		}
		time.Sleep(900 * time.Millisecond)
		r.append(r.id, "e3")
		r.runDue(w2, audit.JobCheckpoint)
		if n := r.checkpointCount(); n != 1 {
			t.Fatalf("w2 did not resume after the lease expired: %d checkpoints", n)
		}
		r.append(r.id, "e4")
		r.runDue(w2, audit.JobCheckpoint)
		if n := r.checkpointCount(); n != 2 {
			t.Fatalf("checkpoints = %d; want 2", n)
		}
		r.verifyChain()
	})
}

// A signer whose lease lapsed mid-run races a new holder: the signer lock keeps the checkpoint list a list.
func TestConcurrentSignersCannotForkTheCheckpointChain(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.append(r.id, fmt.Sprintf("c%d", i))
				if _, _, err := r.cp.Sign(context.Background(), r.db, r.id); err != nil && !errors.Is(err, audit.ErrAnchor) {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		r.verifyChain()
	})
}

// Acceptance 3: events then checkpoints, in chain order, and the cursor moves only on acknowledgement.
func TestForwardDeliversInOrderAndAdvancesOnlyOnAck(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		// Call 2 fails: the first batch (500) is acknowledged, the second is not.
		sink := &fakeSink{failAt: map[int]bool{2: true}}
		w := r.worker("w1", sink, nil)
		ids := make([]string, 1100)
		for i := range ids {
			ids[i] = fmt.Sprintf("n%d", i)
		}
		r.append(r.id, ids...)
		if _, _, err := r.cp.Sign(context.Background(), r.db, r.id); err != nil && !errors.Is(err, audit.ErrAnchor) {
			t.Fatal(err)
		}
		r.schedule(w, func(ctx context.Context, tx store.Tx) error { return w.j.ScheduleForward(ctx, tx, r.id, "siem") })

		if res := r.runDue(w, audit.JobForward); res != jobs.Retried {
			t.Fatalf("a failing sink gave %s; want retried", res)
		}
		st := r.status("siem")
		if st.EventSeq != 500 || st.ConsecutiveFailures != 1 || st.LastFailureCode != audit.CodeSinkUnavailable || st.LastFailureAt == nil {
			t.Fatalf("status after failure = %+v; want cursor at 500, 1 failure, sink_unavailable", st)
		}
		// Acceptance 4: the failure is visible in the job's status too, and it will be retried with backoff.
		codes, err := jobstest.QueuedErrorCodes(r.adminStrings, audit.JobForward, 1)
		if err != nil || len(codes) == 0 || codes[0] != audit.CodeSinkUnavailable {
			t.Fatalf("job status after the failure = %v, %v; want %s", codes, err, audit.CodeSinkUnavailable)
		}

		// The sink recovers: the retry resumes from the cursor and finishes.
		if res := r.runDue(w, audit.JobForward); res != jobs.Completed {
			t.Fatalf("recovered run = %s", res)
		}
		st = r.status("siem")
		if st.EventSeq != st.Head || st.ConsecutiveFailures != 0 || st.LastFailureCode != "" || st.CheckpointSeq == 0 {
			t.Fatalf("status after recovery = %+v", st)
		}
		var lastEvent, lastCP uint64
		seenCP := false
		for _, rec := range sink.got {
			switch rec.Kind {
			case audit.RecordEvent:
				if seenCP {
					t.Fatal("an event was delivered after a checkpoint of the same run")
				}
				if rec.Seq != lastEvent+1 {
					t.Fatalf("event %d after %d: gap or reorder", rec.Seq, lastEvent)
				}
				lastEvent = rec.Seq
			case audit.RecordCheckpoint:
				seenCP = true
				if rec.Seq <= lastCP {
					t.Fatalf("checkpoint %d after %d", rec.Seq, lastCP)
				}
				lastCP = rec.Seq
			}
		}
		if lastEvent != st.Head || lastCP != st.CheckpointSeq {
			t.Fatalf("delivered up to event %d / checkpoint %d; head %d, checkpoint cursor %d", lastEvent, lastCP, st.Head, st.CheckpointSeq)
		}
	})
}

func TestForwardSinkDownKeepsCursorAndRetriesAcrossRuns(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		sink := &fakeSink{failAll: true}
		w := r.worker("w1", sink, nil)
		r.append(r.id, "e1", "e2")
		r.schedule(w, func(ctx context.Context, tx store.Tx) error { return w.j.ScheduleForward(ctx, tx, r.id, "siem") })
		for i := 1; i <= 2; i++ {
			if res := r.runDue(w, audit.JobForward); res != jobs.Retried {
				t.Fatalf("run %d = %s; want retried", i, res)
			}
		}
		st := r.status("siem")
		if st.EventSeq != 0 || st.ConsecutiveFailures < 2 {
			t.Fatalf("status = %+v; the cursor must not move and failures must count", st)
		}
		if st.Head-st.EventSeq != st.Head {
			t.Fatalf("lag = %d", st.Head-st.EventSeq)
		}
		// The failure is a code on the job, not text.
		got, err := jobstest.FirstRetryErrorCode(r.adminStrings, audit.JobForward)
		if err != nil || len(got) != 1 || got[0] != audit.CodeSinkUnavailable {
			t.Fatalf("job failure = %v, %v; want the code %s", got, err, audit.CodeSinkUnavailable)
		}
	})
}

func TestForwardEndsWhenTheSinkIsRemoved(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		sink := &fakeSink{}
		gone := false
		w := r.worker("w1", sink, func(c *audit.JobsConfig) {
			c.Sinks = func(_ tenant.ID, id string) (audit.ForwardSink, bool) { return sink, !gone }
		})
		r.schedule(w, func(ctx context.Context, tx store.Tx) error { return w.j.ScheduleForward(ctx, tx, r.id, "siem") })
		gone = true
		if res := r.runDue(w, audit.JobForward); res != jobs.Completed {
			t.Fatalf("run = %s", res)
		}
		v, _ := jobstest.CountQueued(r.adminStrings, audit.JobForward)
		if v != "0" {
			t.Fatalf("a removed sink still has %s queued runs", v)
		}
	})
}

func TestInitTenantStartsTheCadence(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		w := r.worker("w1", nil, nil)
		r.cp.StartCadenceOnInit(w.j.ScheduleCheckpoint)
		id := r.newTenant("B")
		v, err := jobstest.CountForTenant(r.adminStrings, audit.JobCheckpoint, id.String())
		if err != nil || v != "1" {
			t.Fatalf("queued checkpoint runs for the new tenant = %v, %v", v, err)
		}
	})
}

func (r *rig) status(sink string) audit.ForwardStatus {
	r.t.Helper()
	var st audit.ForwardStatus
	err := r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) error {
		var e error
		st, e = audit.GetForwardStatus(ctx, tx, r.id, sink)
		return e
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return st
}

func hex32(id tenant.ID) string {
	s := id.String()
	out := make([]byte, 0, 32)
	for i := range len(s) {
		if s[i] != '-' {
			out = append(out, s[i])
		}
	}
	return string(out)
}
