package connection_test

import (
	"context"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type jobEnv struct {
	*env
	cl   *fakeClient
	rec  *recorder
	jreg *jobs.Registry
	jobs *connection.Jobs
	svc  *connection.Service
}

func newJobEnv(t *testing.T, s *storetest.Server) *jobEnv {
	t.Helper()
	e := setup(t, s)
	je := &jobEnv{env: e, cl: &fakeClient{}, rec: &recorder{}, jreg: jobs.NewRegistry()}
	// The scheduler needs the service for its body and the service needs the scheduler for activation:
	// the service is built first and the scheduler set through a forwarder, as compose does.
	fw := &fwd{}
	svc, err := connection.NewService(e.reg, je.cl, je.rec, connection.WithScheduler(fw))
	if err != nil {
		t.Fatal(err)
	}
	if je.jobs, err = connection.RegisterJobs(je.jreg, svc, time.Hour); err != nil {
		t.Fatal(err)
	}
	fw.j = je.jobs
	je.svc = svc
	return je
}

type fwd struct{ j *connection.Jobs }

func (f *fwd) ScheduleCheck(ctx context.Context, tx store.Tx, tid tenant.ID) error {
	return f.j.ScheduleCheck(ctx, tx, tid)
}

func queued(t *testing.T, e *env) int {
	t.Helper()
	var n int
	err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.jobs WHERE kind = $1 AND state = 'available'`,
			connection.JobScheduledCheck).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Acceptance 1: activation starts the cadence; when the job fires, a scheduled run is recorded for the
// active connection and its drift is audited, and the successor is queued.
func TestScheduledCheckJobRecordsRunAndAuditsDrift(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newJobEnv(t, s)
		ctx := context.Background()
		c, err := e.reg.Create(ctx, e.a, forest("corp"))
		if err != nil {
			t.Fatal(err)
		}
		e.cl.set(passing(), nil)
		if _, err := e.svc.Activate(ctx, e.a, c.ID, human("alice")); err != nil {
			t.Fatal(err)
		}
		if n := queued(t, e.env); n != 1 {
			t.Fatalf("activation must queue one scheduled check, got %d", n)
		}
		// Activation twice in a bucket converges (idempotent).
		if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			return e.jobs.Schedule(ctx, tx, e.a)
		}); err != nil {
			t.Fatal(err)
		}
		if n := queued(t, e.env); n != 1 {
			t.Fatalf("Schedule must be idempotent, got %d", n)
		}
		// Time passes: the rights drift and the job becomes due (the test cannot wait out the bucket, so it
		// moves the job to its own key, as a real run in a later bucket has).
		e.cl.set(overPriv("drift"), nil)
		if err := e.d.ExecOwner(ctx, `UPDATE public.jobs SET run_at = now() - interval '1 second', unique_key = 'due' WHERE kind = $1`, connection.JobScheduledCheck); err != nil {
			t.Fatal(err)
		}
		cl, err := jobs.Claim(ctx, e.db, e.jreg.Leases(), 5)
		if err != nil || len(cl) != 1 {
			t.Fatalf("claim: %v %v", cl, err)
		}
		res, err := jobs.NewRunner(e.db, e.jreg).Execute(ctx, cl[0])
		if err != nil || res != jobs.Completed {
			t.Fatalf("execute: %v %v", res, err)
		}
		h, err := e.reg.Health(ctx, e.a, c.ID, true, time.Now())
		if err != nil || h.ExcessiveCount != 1 || h.WriteGateOpen {
			t.Fatalf("health: %+v %v", h, err)
		}
		kinds := e.rec.kinds()
		if kinds[len(kinds)-1] != connection.AuditVerdictChanged {
			t.Fatalf("drift not audited: %v", kinds)
		}
		if n := queued(t, e.env); n != 1 {
			t.Fatalf("the successor must be queued, got %d", n)
		}
	})
}

func TestRegisterJobsRefusesBadInput(t *testing.T) {
	if _, err := connection.RegisterJobs(jobs.NewRegistry(), nil, time.Hour); err == nil {
		t.Fatal("a nil service must be refused")
	}
	svc, err := connection.NewService(connection.NewRegistry(nil), &fakeClient{}, &recorder{})
	if err == nil {
		if _, err := connection.RegisterJobs(jobs.NewRegistry(), svc, 48*time.Hour); err == nil {
			t.Fatal("a cadence longer than 24h must be refused")
		}
	}
}

// The cadence recovers a run stranded in verifying: the connection returns to draft with a failed run.
func TestScheduledCheckJobSweepsStrandedRuns(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newJobEnv(t, s)
		ctx := context.Background()
		c, err := e.reg.Create(ctx, e.a, forest("corp"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.reg.Transition(ctx, e.a, c.ID, connection.StateDraft, connection.StateVerifying); err != nil {
			t.Fatal(err)
		}
		if n, err := e.raw(e.a, `UPDATE public.connections SET updated_at = now() - interval '1 hour' WHERE id = $1::uuid`, string(c.ID)); err != nil || n != 1 {
			t.Fatalf("backdating: %d %v", n, err)
		}
		if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error { return e.jobs.Schedule(ctx, tx, e.a) }); err != nil {
			t.Fatal(err)
		}
		if err := e.d.ExecOwner(ctx, `UPDATE public.jobs SET run_at = now() - interval '1 second' WHERE kind = $1`, connection.JobScheduledCheck); err != nil {
			t.Fatal(err)
		}
		cl, err := jobs.Claim(ctx, e.db, e.jreg.Leases(), 5)
		if err != nil || len(cl) != 1 {
			t.Fatalf("claim: %v %v", cl, err)
		}
		if res, err := jobs.NewRunner(e.db, e.jreg).Execute(ctx, cl[0]); err != nil || res != jobs.Completed {
			t.Fatalf("execute: %v %v", res, err)
		}
		if got, err := e.reg.Get(ctx, e.a, c.ID); err != nil || got.State != connection.StateDraft || got.LastVerificationID == "" {
			t.Fatalf("connection: %+v %v", got, err)
		}
	})
}
