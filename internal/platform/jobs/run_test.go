package jobs

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// runKinds registers one kind per body under test and returns a runner over it.
func (e *env) runner(t *testing.T, kinds ...Kind) *Runner {
	t.Helper()
	reg := NewRegistry()
	for _, k := range kinds {
		if err := reg.Register(k); err != nil {
			t.Fatal(err)
		}
	}
	return NewRunner(e.db, reg)
}

func (e *env) claimOne(t *testing.T, kind string, lease time.Duration) Claimed {
	t.Helper()
	got, err := Claim(context.Background(), e.db, []KindLease{{Kind: kind, Lease: lease}}, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("claim %s = %+v, %v", kind, got, err)
	}
	return got[0]
}

func (e *env) code(t *testing.T, id int64) string {
	t.Helper()
	got, err := e.d.OwnerStrings(context.Background(), `SELECT COALESCE(error_code, '') FROM public.jobs WHERE id = $1`, id)
	if err != nil || len(got) != 1 {
		t.Fatalf("read code: %v %v", got, err)
	}
	return got[0]
}

func (e *env) countJobs(t *testing.T, kind string) string {
	t.Helper()
	got, err := e.d.OwnerStrings(context.Background(), `SELECT count(*)::text FROM public.jobs WHERE kind = $1`, kind)
	if err != nil || len(got) != 1 {
		t.Fatalf("count: %v %v", got, err)
	}
	return got[0]
}

// Acceptance 1: a default-mode body runs in one transaction for the claimed tenant, and the completion
// commits with the body's own writes.
func TestDefaultModeRunsInOneTenantTransaction(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		var seen string
		r := e.runner(t,
			Kind{Name: "t.child", Timeout: time.Minute, Mode: ModeDefault, Run: noop},
			Kind{Name: "t.parent", Timeout: time.Minute, Mode: ModeDefault, Run: func(ctx context.Context, tx store.Tx, c Claimed) error {
				if err := tx.QueryRow(ctx, `SELECT current_setting('app.tenant_id')`).Scan(&seen); err != nil {
					return err
				}
				_, err := r0(t, e).Enqueue(ctx, tx, Job{Kind: "t.child", Tenant: c.Tenant})
				return err
			}})
		id := e.enqueueKind(t, "t.parent")
		res, err := r.Execute(context.Background(), e.claimOne(t, "t.parent", time.Minute))
		if err != nil || res != Completed {
			t.Fatalf("Execute = %v, %v", res, err)
		}
		if seen != e.a.String() {
			t.Errorf("body ran in tenant %q, want %q", seen, e.a)
		}
		if st, _ := e.state(t, id); st != "completed" {
			t.Errorf("job is %s, want completed", st)
		}
		if n := e.countJobs(t, "t.child"); n != "1" {
			t.Errorf("body's write count = %s, want 1 (committed with Complete)", n)
		}
	})
}

// r0 is a registry that knows t.child, used by the body to enqueue in the wrapper's transaction.
func r0(t *testing.T, e *env) *Registry {
	r := NewRegistry()
	_ = r.Register(Kind{Name: "t.child", Timeout: time.Minute, Mode: ModeDefault, Run: noop})
	_ = r.Register(Kind{Name: "t.other", Timeout: time.Minute, Mode: ModeDefault, Run: noop})
	return r
}

func (e *env) enqueueKind(t *testing.T, kind string) int64 {
	t.Helper()
	j := Job{Kind: kind, Tenant: e.a}
	var id int64
	err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) error {
		r := r0(t, e)
		_ = r.Register(Kind{Name: kind, Timeout: time.Minute, Mode: ModeDefault, Run: noop})
		res, err := r.Enqueue(ctx, tx, j)
		id = res.ID
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Acceptance 3: an error or a panic rolls the transaction back and stores a code, never the text.
func TestFailureAndPanicRollBackAndStoreACode(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		secret := "S3CRET-value-in-error-text"
		write := func(ctx context.Context, tx store.Tx, c Claimed) error {
			_, err := r0(t, e).Enqueue(ctx, tx, Job{Kind: "t.child", Tenant: c.Tenant})
			return err
		}
		r := e.runner(t,
			Kind{Name: "t.err", Timeout: time.Minute, Mode: ModeDefault, Run: func(ctx context.Context, tx store.Tx, c Claimed) error {
				if err := write(ctx, tx, c); err != nil {
					return err
				}
				return errors.New(secret)
			}},
			Kind{Name: "t.panic", Timeout: time.Minute, Mode: ModeDefault, Run: func(ctx context.Context, tx store.Tx, c Claimed) error {
				if err := write(ctx, tx, c); err != nil {
					return err
				}
				panic(secret)
			}},
			Kind{Name: "t.perm", Timeout: time.Minute, Mode: ModeDefault, Run: func(context.Context, store.Tx, Claimed) error {
				return &Failure{Code: "bad_reference", Permanent: true, Err: errors.New(secret)}
			}},
			Kind{Name: "t.managed", Timeout: time.Minute, Mode: ModeManagedTx, RunManaged: func(context.Context, TenantTx, Claimed) error {
				return errors.New(secret)
			}})
		for _, c := range []struct {
			kind, code string
			res        Result
		}{
			{"t.err", CodeFailed, Retried},
			{"t.panic", CodePanic, Retried},
			{"t.perm", "bad_reference", Discarded},
			{"t.managed", CodeFailed, Retried},
		} {
			id := e.enqueueKind(t, c.kind)
			res, err := r.Execute(context.Background(), e.claimOne(t, c.kind, time.Minute))
			if err != nil || res != c.res {
				t.Fatalf("%s: Execute = %v, %v; want %v", c.kind, res, err, c.res)
			}
			if got := e.code(t, id); got != c.code {
				t.Errorf("%s: stored code %q, want %q", c.kind, got, c.code)
			}
			if st, _ := e.state(t, id); st != map[Result]string{Retried: "available", Discarded: "discarded"}[c.res] {
				t.Errorf("%s: state %s", c.kind, st)
			}
		}
		if n := e.countJobs(t, "t.child"); n != "0" {
			t.Errorf("%s child jobs survived a rolled-back body, want 0", n)
		}
		got, _ := e.d.OwnerStrings(context.Background(), `SELECT COALESCE(string_agg(error_code, ','), '') FROM public.jobs`)
		if len(got) == 1 && strings.Contains(got[0], "S3CRET") {
			t.Error("error text reached the table")
		}
	})
}

// Acceptance 2 and 4: a ManagedTx body gets a runner that opens short tenant transactions and holds none
// across the body; the claim is renewed while it runs so Rescue leaves it alone.
func TestManagedTxHoldsNoTransactionAndRenewsTheClaim(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		var tenants []string
		var idle atomic.Int32
		r := e.runner(t, Kind{Name: "t.long", Timeout: 5 * time.Second, Mode: ModeManagedTx,
			RunManaged: func(ctx context.Context, run TenantTx, c Claimed) error {
				for i := 0; i < 2; i++ {
					var got string
					if err := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
						return tx.QueryRow(ctx, `SELECT current_setting('app.tenant_id')`).Scan(&got)
					}); err != nil {
						return err
					}
					tenants = append(tenants, got)
					// No transaction is open while the body waits (as it would on a directory call).
					time.Sleep(700 * time.Millisecond)
					n, err := e.d.OwnerStrings(ctx, `SELECT count(*)::text FROM pg_stat_activity WHERE datname = current_database() AND state LIKE 'idle in transaction%'`)
					if err != nil || len(n) != 1 || n[0] != "0" {
						t.Errorf("idle-in-transaction sessions during the body = %v, %v", n, err)
					}
					idle.Add(1)
				}
				return nil
			}})
		r.leaseFor = func(Kind) time.Duration { return time.Second }
		id := e.enqueueKindManaged(t, "t.long")
		c := e.claimOne(t, "t.long", time.Second)
		done := make(chan struct{})
		var res Result
		var err error
		go func() { defer close(done); res, err = r.Execute(ctx, c) }()
		// The body outlives its 1 s lease; Rescue must not requeue it.
		time.Sleep(1200 * time.Millisecond)
		if rs, rerr := Rescue(ctx, e.db, 10); rerr != nil || rs != (Rescued{}) {
			t.Fatalf("Rescue mid-run = %+v, %v; want nothing (claim renewed)", rs, rerr)
		}
		<-done
		if err != nil || res != Completed {
			t.Fatalf("Execute = %v, %v", res, err)
		}
		if len(tenants) != 2 || tenants[0] != e.a.String() || tenants[1] != e.a.String() {
			t.Errorf("tenants seen = %v, want A twice", tenants)
		}
		if st, at := e.state(t, id); st != "completed" || at != 1 {
			t.Errorf("job = %s attempt %d, want completed attempt 1", st, at)
		}
	})
}

func (e *env) enqueueKindManaged(t *testing.T, kind string) int64 {
	t.Helper()
	var id int64
	err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) error {
		r := NewRegistry()
		_ = r.Register(Kind{Name: kind, Timeout: time.Minute, Mode: ModeManagedTx, RunManaged: noopManaged})
		res, err := r.Enqueue(ctx, tx, Job{Kind: kind, Tenant: e.a})
		id = res.ID
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A claim that is superseded stops the body and records nothing.
func TestManagedTxStopsWhenTheClaimIsLost(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		r := e.runner(t, Kind{Name: "t.lost", Timeout: 5 * time.Second, Mode: ModeManagedTx,
			RunManaged: func(ctx context.Context, run TenantTx, c Claimed) error {
				// Another worker takes the job over: the claim lapses and is rescued and re-claimed.
				_ = e.d.ExecOwner(context.Background(), `UPDATE public.jobs SET claimed_until = now() - interval '1 minute' WHERE id = $1`, c.ID)
				if _, err := Rescue(context.Background(), e.db, 10); err != nil {
					return err
				}
				<-ctx.Done()
				return ctx.Err()
			}})
		r.leaseFor = func(Kind) time.Duration { return 400 * time.Millisecond }
		id := e.enqueueKindManaged(t, "t.lost")
		res, err := r.Execute(ctx, e.claimOne(t, "t.lost", 400*time.Millisecond))
		if err != nil || res != Lost {
			t.Fatalf("Execute = %v, %v; want Lost", res, err)
		}
		if st, _ := e.state(t, id); st != "available" {
			t.Errorf("job is %s, want available (rescued, not failed by the old attempt)", st)
		}
	})
}

// Acceptance 5: a body cannot act for another tenant; the database refuses and the job fails.
func TestBodyCannotUseAnotherTenant(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		r := e.runner(t, Kind{Name: "t.cross", Timeout: time.Minute, Mode: ModeDefault,
			Run: func(ctx context.Context, tx store.Tx, c Claimed) error {
				// Args name B themselves, so the database guard (not the Go check) is what refuses.
				_, err := tx.Exec(ctx, insertJob, e.b.String(), "t.other", `{"tenant_id":"`+e.b.String()+`"}`, nil, 0, 5, nil)
				if err == nil {
					t.Error("the database accepted a job for another tenant")
				}
				return mapErr("enqueue", err)
			}})
		id := e.enqueueKind(t, "t.cross")
		res, err := r.Execute(context.Background(), e.claimOne(t, "t.cross", time.Minute))
		if err != nil || res != Retried {
			t.Fatalf("Execute = %v, %v; want Retried", res, err)
		}
		if got := e.code(t, id); got != CodeCrossTenant {
			t.Errorf("code = %q, want %q", got, CodeCrossTenant)
		}
	})
}

func TestExecuteRefusesPlatformAndUnregisteredJobs(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		r := e.runner(t, Kind{Name: "t.plat", Timeout: time.Minute, Mode: ModeDefault, Platform: true, Run: noop})
		if _, err := r.Execute(context.Background(), Claimed{Kind: "t.plat"}); !errors.Is(err, ErrPlatformJob) {
			t.Errorf("platform job: %v, want ErrPlatformJob", err)
		}
		if _, err := r.Execute(context.Background(), Claimed{Kind: "t.nope", Tenant: e.a}); !errors.Is(err, ErrKindUnknown) {
			t.Errorf("unknown kind: %v, want ErrKindUnknown", err)
		}
	})
}

// A Claimed whose tenant was swapped is refused by the database before any body code runs, in both modes.
func TestSwappedTenantNeverRunsTheBody(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		var calls atomic.Int32
		write := func(ctx context.Context, tx store.Tx, c Claimed) error {
			calls.Add(1)
			_, err := r0(t, e).Enqueue(ctx, tx, Job{Kind: "t.child", Tenant: c.Tenant})
			return err
		}
		r := e.runner(t,
			Kind{Name: "t.child", Timeout: time.Minute, Mode: ModeDefault, Run: noop},
			Kind{Name: "t.swapd", Timeout: time.Minute, Mode: ModeDefault, Run: write},
			Kind{Name: "t.swapm", Timeout: time.Minute, Mode: ModeManagedTx,
				RunManaged: func(ctx context.Context, run TenantTx, c Claimed) error {
					return run.Run(ctx, func(ctx context.Context, tx store.Tx) error { return write(ctx, tx, c) })
				}})
		e.enqueueKind(t, "t.swapd")
		e.enqueueKindManaged(t, "t.swapm")
		for _, kind := range []string{"t.swapd", "t.swapm"} {
			c := e.claimOne(t, kind, time.Minute)
			c.Tenant = e.b
			res, err := r.Execute(context.Background(), c)
			if err != nil || res != Lost {
				t.Fatalf("%s: Execute = %v, %v; want Lost", kind, res, err)
			}
		}
		if calls.Load() != 0 {
			t.Errorf("body ran %d times, want 0", calls.Load())
		}
		if n := e.countJobs(t, "t.child"); n != "0" {
			t.Errorf("child rows = %s, want 0", n)
		}
	})
}

// A runner kept past the body (completed, or superseded) refuses further work.
func TestRunnerIsClosedAfterTheBody(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		var kept TenantTx
		wrote := func(run TenantTx) error {
			return run.Run(context.Background(), func(ctx context.Context, tx store.Tx) error {
				_, err := r0(t, e).Enqueue(ctx, tx, Job{Kind: "t.child", Tenant: e.a})
				return err
			})
		}
		r := e.runner(t,
			Kind{Name: "t.child", Timeout: time.Minute, Mode: ModeDefault, Run: noop},
			Kind{Name: "t.keep", Timeout: time.Minute, Mode: ModeManagedTx,
				RunManaged: func(ctx context.Context, run TenantTx, c Claimed) error { kept = run; return nil }},
			Kind{Name: "t.keeplost", Timeout: 5 * time.Second, Mode: ModeManagedTx,
				RunManaged: func(ctx context.Context, run TenantTx, c Claimed) error {
					kept = run
					_ = e.d.ExecOwner(context.Background(), `UPDATE public.jobs SET claimed_until = now() - interval '1 minute' WHERE id = $1`, c.ID)
					if _, err := Rescue(context.Background(), e.db, 10); err != nil {
						return err
					}
					<-ctx.Done()
					return ctx.Err()
				}})
		r.leaseFor = func(k Kind) time.Duration {
			if k.Name == "t.keeplost" {
				return 400 * time.Millisecond
			}
			return time.Minute
		}
		for kind, want := range map[string]Result{"t.keep": Completed, "t.keeplost": Lost} {
			e.enqueueKindManaged(t, kind)
			res, err := r.Execute(context.Background(), e.claimOne(t, kind, 400*time.Millisecond))
			if err != nil || res != want {
				t.Fatalf("%s: Execute = %v, %v; want %v", kind, res, err, want)
			}
			if err := wrote(kept); !errors.Is(err, ErrRunnerClosed) {
				t.Errorf("%s: late Run = %v, want ErrRunnerClosed", kind, err)
			}
		}
		if n := e.countJobs(t, "t.child"); n != "0" {
			t.Errorf("child rows = %s, want 0", n)
		}
	})
}

// A body whose claim lapsed and was rescued gets ErrSuperseded from its very next Run, before any renewal
// tick, and nothing it wrote commits.
func TestManagedTxRunIsFencedOnTheLiveClaim(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		var runErr error
		r := e.runner(t,
			Kind{Name: "t.child", Timeout: time.Minute, Mode: ModeDefault, Run: noop},
			Kind{Name: "t.fenced", Timeout: time.Minute, Mode: ModeManagedTx,
				RunManaged: func(ctx context.Context, run TenantTx, c Claimed) error {
					_ = e.d.ExecOwner(context.Background(), `UPDATE public.jobs SET claimed_until = now() - interval '1 minute' WHERE id = $1`, c.ID)
					if _, err := Rescue(context.Background(), e.db, 10); err != nil {
						return err
					}
					ran := false
					runErr = run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
						ran = true
						_, err := r0(t, e).Enqueue(ctx, tx, Job{Kind: "t.child", Tenant: e.a})
						return err
					})
					if ran {
						t.Error("fn ran although the claim was superseded")
					}
					return runErr
				}})
		// Renewal ticks every 30s: none happens before Run.
		r.leaseFor = func(Kind) time.Duration { return time.Minute }
		id := e.enqueueKindManaged(t, "t.fenced")
		res, err := r.Execute(context.Background(), e.claimOne(t, "t.fenced", time.Minute))
		if err != nil || res != Lost {
			t.Fatalf("Execute = %v, %v; want Lost", res, err)
		}
		if !errors.Is(runErr, ErrSuperseded) {
			t.Errorf("Run = %v, want ErrSuperseded", runErr)
		}
		if n := e.countJobs(t, "t.child"); n != "0" {
			t.Errorf("child rows = %s, want 0", n)
		}
		if st, _ := e.state(t, id); st != "available" {
			t.Errorf("job is %s, want available", st)
		}
	})
}

// A runner closed while fn is in flight rolls fn's transaction back instead of committing it.
func TestManagedTxRunClosedMidFlightRollsBack(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		inFn, release, got := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		r := e.runner(t,
			Kind{Name: "t.child", Timeout: time.Minute, Mode: ModeDefault, Run: noop},
			Kind{Name: "t.inflight", Timeout: time.Minute, Mode: ModeManagedTx,
				RunManaged: func(ctx context.Context, run TenantTx, c Claimed) error {
					go func() {
						got <- run.Run(context.Background(), func(ctx context.Context, tx store.Tx) error {
							if _, err := r0(t, e).Enqueue(ctx, tx, Job{Kind: "t.child", Tenant: e.a}); err != nil {
								return err
							}
							close(inFn)
							<-release
							return nil
						})
					}()
					<-inFn
					return nil // the body returns: the runner closes while fn is in flight
				}})
		e.enqueueKindManaged(t, "t.inflight")
		c := e.claimOne(t, "t.inflight", time.Minute)
		done := make(chan struct{})
		go func() { defer close(done); _, _ = r.Execute(context.Background(), c) }()
		// Closing happens when the body returns; fn is still holding its share lock then.
		time.Sleep(300 * time.Millisecond)
		close(release)
		if err := <-got; !errors.Is(err, ErrRunnerClosed) {
			t.Errorf("Run = %v, want ErrRunnerClosed", err)
		}
		<-done
		if n := e.countJobs(t, "t.child"); n != "0" {
			t.Errorf("child rows = %s, want 0 (rolled back)", n)
		}
	})
}
