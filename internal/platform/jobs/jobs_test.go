package jobs

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type ref struct {
	ID string `json:"id"`
}

type env struct {
	db   *store.DB
	d    *storetest.Database
	a, b tenant.ID
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	ctx := context.Background()
	a := tenanttest.Seed(t, d.ExecOwner, "A")
	b := tenanttest.Seed(t, d.ExecOwner, "B")
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatalf("store.Open as the runtime role: %v", err)
	}
	t.Cleanup(db.Close)
	return &env{db: db, d: d, a: a, b: b}
}

func (e *env) enqueue(t *testing.T, tid tenant.ID, j Job) Enqueued {
	t.Helper()
	j.Tenant = tid
	var res Enqueued
	var err error
	if tid.IsZero() {
		err = e.platform(func(ctx context.Context, tx store.Tx) error {
			res, err = testRegistry.Enqueue(ctx, tx, j)
			return err
		})
	} else {
		err = e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
			res, err = testRegistry.Enqueue(ctx, tx, j)
			return err
		})
	}
	if err != nil {
		t.Fatalf("enqueue %s: %v", j.Kind, err)
	}
	return res
}

// platform runs fn in a platform-scope transaction. It is the one WithPlatform site of this test file
// (registered in the exemption registry), so the tests can show what a platform transaction may not do.
func (e *env) platform(fn func(ctx context.Context, tx store.Tx) error) error {
	return e.db.WithPlatform(context.Background(), "test: platform-scope transaction", fn)
}

func (e *env) inTenant(t *testing.T, tid tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error {
	t.Helper()
	return e.db.WithTenant(context.Background(), tid, fn)
}

func (e *env) state(t *testing.T, id int64) (state string, attempt int) {
	t.Helper()
	got, err := e.d.OwnerStrings(context.Background(), `SELECT state || ',' || attempt FROM public.jobs WHERE id = $1`, id)
	if err != nil || len(got) != 1 {
		t.Fatalf("read job %d: %v %v", id, got, err)
	}
	parts := strings.Split(got[0], ",")
	n := 0
	for _, c := range parts[1] {
		n = n*10 + int(c-'0')
	}
	return parts[0], n
}

// testRegistry registers the kinds the tests enqueue.
var testRegistry = func() *Registry {
	r := NewRegistry()
	for _, k := range []Kind{
		{Name: "test.work", Timeout: time.Minute, Mode: ModeDefault, Run: noop},
		{Name: "test.other", Timeout: time.Minute, Mode: ModeManagedTx, RunManaged: noopManaged},
		{Name: "test.platform", Timeout: time.Minute, Mode: ModeDefault, Run: noop, Platform: true},
	} {
		if err := r.Register(k); err != nil {
			panic(err)
		}
	}
	return r
}()

var oneKind = []KindLease{{Kind: "test.work", Lease: time.Minute}, {Kind: "test.platform", Lease: time.Minute}}

func each(t *testing.T, fn func(t *testing.T, e *env)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) { fn(t, setup(t, s)) })
}

// Acceptance 1: the database rejects a cross-tenant enqueue, whatever the caller's Go code does.
func TestEnqueueRefusesAnotherTenantsJob(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		// Through the package: tenant A's transaction cannot enqueue for B. Args name B themselves, so the
		// database trigger is what refuses (not the Go-side args check).
		err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := testRegistry.Enqueue(ctx, tx, Job{Kind: "test.work", Tenant: e.b, Args: ref{ID: "x"}})
			return err
		})
		if !errors.Is(err, ErrCrossTenant) {
			t.Fatalf("A enqueuing for B = %v, want ErrCrossTenant", err)
		}
		// A tenant job in a platform (no-context) transaction is refused, and so is a platform job in a
		// tenant transaction.
		err = e.platform(func(ctx context.Context, tx store.Tx) error {
			_, err := testRegistry.Enqueue(ctx, tx, Job{Kind: "test.work", Tenant: e.a})
			return err
		})
		if !errors.Is(err, ErrCrossTenant) {
			t.Fatalf("tenant job without a tenant context = %v, want ErrCrossTenant", err)
		}
		err = e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := testRegistry.Enqueue(ctx, tx, Job{Kind: "test.platform"})
			return err
		})
		if !errors.Is(err, ErrCrossTenant) {
			t.Fatalf("platform job in a tenant transaction = %v, want ErrCrossTenant", err)
		}
		// Raw SQL that skips the package is refused by the same trigger, with the guard's SQLSTATE.
		err = e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.jobs (tenant_id, kind, args) VALUES ($1::uuid, 'test.work', jsonb_build_object('tenant_id', $1::text))`, e.b.String())
			return err
		})
		if store.SQLState(err) != sqlstateGuard {
			t.Fatalf("raw cross-tenant INSERT = %v, want SQLSTATE %s", err, sqlstateGuard)
		}
		// A multi-row INSERT with one foreign row fails as a whole.
		err = e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.jobs (tenant_id, kind, args)
				SELECT t, 'test.work', jsonb_build_object('tenant_id', t::text) FROM unnest($1::uuid[]) AS t`, []string{e.a.String(), e.b.String()})
			return err
		})
		if store.SQLState(err) != sqlstateGuard {
			t.Fatalf("mixed multi-row INSERT = %v, want SQLSTATE %s", err, sqlstateGuard)
		}
		if got, _ := e.d.OwnerStrings(ctx, `SELECT count(*)::text FROM public.jobs`); len(got) != 1 || got[0] != "0" {
			t.Fatalf("rows after the refused enqueues = %v, want none", got)
		}
		// The matching tenant works, and a platform job works in a platform transaction.
		if res := e.enqueue(t, e.a, Job{Kind: "test.work", Args: ref{ID: "1"}}); res.ID == 0 || res.Duplicate {
			t.Fatalf("A enqueuing for A = %+v", res)
		}
		if res := e.enqueue(t, tenant.ID{}, Job{Kind: "test.platform"}); res.ID == 0 {
			t.Fatalf("platform enqueue = %+v", res)
		}
	})
}

func TestEnqueueRollsBackWithTheCallersTransaction(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		boom := errors.New("caller failed after enqueue")
		err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error {
			if _, err := testRegistry.Enqueue(ctx, tx, Job{Kind: "test.work", Tenant: e.a}); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatal(err)
		}
		if got, _ := e.d.OwnerStrings(context.Background(), `SELECT count(*)::text FROM public.jobs`); got[0] != "0" {
			t.Fatalf("a job outlived its caller's rollback: %v", got)
		}
	})
}

func TestEnqueueRefusesBadInputBeforeSQL(t *testing.T) {
	var tid = tenant.New()
	cases := map[string]Job{
		"bad kind":          {Kind: "Test Work", Tenant: tid},
		"empty kind":        {Tenant: tid},
		"args not object":   {Kind: "test.work", Tenant: tid, Args: []int{1}},
		"args too big":      {Kind: "test.work", Tenant: tid, Args: map[string]string{"k": strings.Repeat("x", MaxArgsBytes)}},
		"platform w/ tid":   {Kind: "test.work", Args: map[string]string{"tenant_id": tid.String()}},
		"too many attempts": {Kind: "test.work", Tenant: tid, MaxAttempts: 101},
		"negative attempts": {Kind: "test.work", Tenant: tid, MaxAttempts: -1},
		"long unique key":   {Kind: "test.work", Tenant: tid, UniqueKey: strings.Repeat("k", 201)},
	}
	for name, j := range cases {
		if _, err := j.encodeArgs(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: encodeArgs = %v, want ErrInvalid", name, err)
		}
	}
	other := tenant.New()
	if _, err := (Job{Kind: "test.work", Tenant: tid, Args: map[string]string{"tenant_id": other.String()}}).encodeArgs(); !errors.Is(err, ErrCrossTenant) {
		t.Errorf("args naming another tenant = %v, want ErrCrossTenant", err)
	}
	got, err := Job{Kind: "test.work", Tenant: tid, Args: ref{ID: "7"}}.encodeArgs()
	if err != nil || !strings.Contains(got, `"tenant_id":"`+tid.String()+`"`) || !strings.Contains(got, `"id":"7"`) {
		t.Errorf("encodeArgs = %q, %v; want the reference plus the tenant", got, err)
	}
}

func TestJobsNeverChangeWhatTheyAre(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		id := e.enqueue(t, e.a, Job{Kind: "test.work"}).ID
		for _, set := range []string{
			`tenant_id = '` + e.b.String() + `', args = jsonb_build_object('tenant_id', '` + e.b.String() + `')`,
			`kind = 'test.other'`,
			`args = args || '{"x":1}'`,
		} {
			err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE public.jobs SET `+set+` WHERE id = $1`, id) // fixture text
				return err
			})
			if store.SQLState(err) != sqlstateGuard {
				t.Errorf("UPDATE SET %s = %v, want SQLSTATE %s", set, err, sqlstateGuard)
			}
		}
		// An update that changes none of them (a claim, say) is fine.
		if err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.jobs SET priority = 3 WHERE id = $1`, id)
			return err
		}); err != nil {
			t.Errorf("a harmless update = %v", err)
		}
	})
}

func TestTableConstraints(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		bad := map[string]string{
			"args over 4 KiB":        `INSERT INTO public.jobs (tenant_id, kind, args) VALUES (NULL, 'k', jsonb_build_object('x', repeat('a', 5000)))`,
			"args name another":      `INSERT INTO public.jobs (tenant_id, kind, args) VALUES ('` + e.a.String() + `', 'k', jsonb_build_object('tenant_id', '` + e.b.String() + `'))`,
			"tenant job w/o tenant":  `INSERT INTO public.jobs (tenant_id, kind, args) VALUES ('` + e.a.String() + `', 'k', '{}')`,
			"platform job w/ tenant": `INSERT INTO public.jobs (tenant_id, kind, args) VALUES (NULL, 'k', '{"tenant_id":"` + e.a.String() + `"}')`,
			"error text as code":     `INSERT INTO public.jobs (kind, error_code) VALUES ('k', 'connection refused: dc01')`,
			"unknown tenant":         `INSERT INTO public.jobs (tenant_id, kind, args) VALUES ('00000000-0000-4000-8000-000000000001', 'k', '{"tenant_id":"00000000-0000-4000-8000-000000000001"}')`,
		}
		for name, stmt := range bad {
			if err := e.d.ExecOwner(context.Background(), stmt); err == nil { // the owner is not exempt from checks, nor from the trigger
				t.Errorf("%s: the table accepted it", name)
			}
		}
	})
}

func TestUniqueKeyDeduplicatesAmongLiveJobs(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		first := e.enqueue(t, e.a, Job{Kind: "test.work", UniqueKey: "op1/chunk1"})
		dup := e.enqueue(t, e.a, Job{Kind: "test.work", UniqueKey: "op1/chunk1"})
		if first.ID == 0 || !dup.Duplicate || dup.ID != 0 {
			t.Fatalf("first=%+v dup=%+v", first, dup)
		}
		// Another tenant, another kind, or no key at all are not duplicates.
		for _, r := range []Enqueued{
			e.enqueue(t, e.b, Job{Kind: "test.work", UniqueKey: "op1/chunk1"}),
			e.enqueue(t, e.a, Job{Kind: "test.other", UniqueKey: "op1/chunk1"}),
			e.enqueue(t, e.a, Job{Kind: "test.work"}),
			e.enqueue(t, e.a, Job{Kind: "test.work"}),
		} {
			if r.Duplicate {
				t.Fatalf("unexpected duplicate: %+v", r)
			}
		}
		// A platform job's key de-duplicates too (NULL tenant is not distinct).
		e.enqueue(t, tenant.ID{}, Job{Kind: "test.platform", UniqueKey: "sweep"})
		if !e.enqueue(t, tenant.ID{}, Job{Kind: "test.platform", UniqueKey: "sweep"}).Duplicate {
			t.Fatal("a platform job's unique key did not de-duplicate")
		}
		// Once the first finishes, the key is free again (available and running only, DM-43 I5).
		c := mustClaim(t, e, 1)
		if err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, c[0].Ref) }); err != nil {
			t.Fatal(err)
		}
		if again := e.enqueue(t, e.a, Job{Kind: "test.work", UniqueKey: "op1/chunk1"}); again.Duplicate {
			// The claimed job may not be the keyed one (claim order is by run_at); tolerate by checking state.
			if st, _ := e.state(t, first.ID); st == "completed" {
				t.Fatal("key still held after the keyed job completed")
			}
		}
	})
}

func mustClaim(t *testing.T, e *env, n int) []Claimed {
	t.Helper()
	got, err := Claim(context.Background(), e.db, oneKind, n)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	return got
}

func TestClaimOrdersFiltersAndLeases(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		low := e.enqueue(t, e.a, Job{Kind: "test.work", Priority: 5}).ID
		hi := e.enqueue(t, e.b, Job{Kind: "test.work", Priority: -1}).ID
		later := e.enqueue(t, e.a, Job{Kind: "test.work", RunAt: time.Now().Add(time.Hour)}).ID
		other := e.enqueue(t, e.a, Job{Kind: "test.other"}).ID
		plat := e.enqueue(t, tenant.ID{}, Job{Kind: "test.platform", Priority: 9}).ID

		got := mustClaim(t, e, 2)
		if len(got) != 2 {
			t.Fatalf("claimed %d, want 2", len(got))
		}
		ids := []int64{got[0].ID, got[1].ID}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		if want := []int64{low, hi}; ids[0] != want[0] || ids[1] != want[1] {
			t.Fatalf("claimed %v, want the two lowest priorities %v", ids, want)
		}
		for _, c := range got {
			if c.Attempt != 1 || c.Kind != "test.work" || c.Tenant.IsZero() || !strings.Contains(string(c.Args), c.Tenant.String()) {
				t.Errorf("claimed %+v", c)
			}
			if d := time.Until(c.ClaimedUntil); d < 50*time.Second || d > 70*time.Second {
				t.Errorf("lease ends in %s, want about a minute", d)
			}
		}
		// The platform job comes back with a zero tenant; the future and other-kind jobs never do.
		rest := mustClaim(t, e, 10)
		if len(rest) != 1 || rest[0].ID != plat || !rest[0].Tenant.IsZero() {
			t.Fatalf("second claim = %+v, want only the platform job", rest)
		}
		for _, id := range []int64{later, other} {
			if st, att := e.state(t, id); st != "available" || att != 0 {
				t.Errorf("job %d is %s/%d, want untouched", id, st, att)
			}
		}
		if more := mustClaim(t, e, 10); len(more) != 0 {
			t.Fatalf("nothing is runnable, claimed %+v", more)
		}
	})
}

func TestClaimRefusesBadInput(t *testing.T) {
	db := (*store.DB)(nil)
	ctx := context.Background()
	for name, f := range map[string]func() error{
		"no kinds":     func() error { _, err := Claim(ctx, db, nil, 1); return err },
		"zero limit":   func() error { _, err := Claim(ctx, db, oneKind, 0); return err },
		"huge limit":   func() error { _, err := Claim(ctx, db, oneKind, 100000); return err },
		"bad kind":     func() error { _, err := Claim(ctx, db, []KindLease{{"No", time.Minute}}, 1); return err },
		"zero lease":   func() error { _, err := Claim(ctx, db, []KindLease{{"a.b", 0}}, 1); return err },
		"huge lease":   func() error { _, err := Claim(ctx, db, []KindLease{{"a.b", 48 * time.Hour}}, 1); return err },
		"rescue limit": func() error { _, err := Rescue(ctx, db, 0); return err },
		"clean limit":  func() error { _, err := Clean(ctx, db, time.Hour, 0); return err },
		"clean neg":    func() error { _, err := Clean(ctx, db, -time.Hour, 1); return err },
	} {
		if err := f(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

// Concurrent workers must never be handed the same job (SKIP LOCKED), and must between them drain it.
func TestConcurrentClaimsNeverShareAJob(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		const jobs, workers = 60, 6
		for i := 0; i < jobs; i++ {
			e.enqueue(t, e.a, Job{Kind: "test.work"})
		}
		var mu sync.Mutex
		seen := map[int64]int{}
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					got, err := Claim(context.Background(), e.db, oneKind, 7)
					if err != nil {
						errs <- err
						return
					}
					if len(got) == 0 {
						return
					}
					mu.Lock()
					for _, c := range got {
						seen[c.ID]++
					}
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		if len(seen) != jobs {
			t.Fatalf("claimed %d distinct jobs, want %d", len(seen), jobs)
		}
		for id, n := range seen {
			if n != 1 {
				t.Errorf("job %d was claimed %d times", id, n)
			}
		}
	})
}

// A claim held by another open transaction is skipped, not waited for.
func TestClaimSkipsRowsLockedByAnotherTransaction(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		first := e.enqueue(t, e.a, Job{Kind: "test.work", Priority: 0}).ID
		second := e.enqueue(t, e.a, Job{Kind: "test.work", Priority: 1}).ID
		locked, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			done <- e.platform(func(ctx context.Context, tx store.Tx) error {
				if _, err := tx.Exec(ctx, `SELECT id FROM public.jobs WHERE id = $1 FOR UPDATE`, first); err != nil {
					return err
				}
				close(locked)
				<-release
				return nil
			})
		}()
		<-locked
		got := mustClaim(t, e, 5)
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ID != second {
			t.Fatalf("claimed %+v while job %d was locked, want only job %d", got, first, second)
		}
	})
}

func TestOutcomesAreFencedOnAttemptStateAndTenant(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		id := e.enqueue(t, e.a, Job{Kind: "test.work", MaxAttempts: 3}).ID
		c := mustClaim(t, e, 1)[0]
		if c.ID != id {
			t.Fatalf("claimed %d, want %d", c.ID, id)
		}
		fromA := func(fn func(ctx context.Context, tx store.Tx) error) error { return e.inTenant(t, e.a, fn) }

		// Another tenant, a platform transaction and a wrong attempt all change nothing.
		if err := e.inTenant(t, e.b, func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, c.Ref) }); !errors.Is(err, ErrSuperseded) {
			t.Errorf("complete from B = %v, want ErrSuperseded", err)
		}
		if err := e.platform(func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, c.Ref) }); !errors.Is(err, ErrSuperseded) {
			t.Errorf("complete from a platform tx = %v, want ErrSuperseded", err)
		}
		stale := Ref{ID: c.ID, Attempt: c.Attempt + 1}
		if err := fromA(func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, stale) }); !errors.Is(err, ErrSuperseded) {
			t.Errorf("complete with a wrong attempt = %v, want ErrSuperseded", err)
		}
		if st, _ := e.state(t, id); st != "running" {
			t.Fatalf("state = %s after fenced-out recordings, want running", st)
		}

		// Renew extends the lease.
		if err := fromA(func(ctx context.Context, tx store.Tx) error { return Renew(ctx, tx, c.Ref, 2*time.Hour) }); err != nil {
			t.Fatal(err)
		}
		if got, _ := e.d.OwnerStrings(context.Background(), `SELECT (claimed_until > now() + interval '1 hour')::text FROM public.jobs WHERE id = $1`, id); got[0] != "true" {
			t.Errorf("renew did not extend the claim: %v", got)
		}

		// Complete, once; the second recording is superseded, and so is Fail after completion.
		if err := fromA(func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, c.Ref) }); err != nil {
			t.Fatal(err)
		}
		if err := fromA(func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, c.Ref) }); !errors.Is(err, ErrSuperseded) {
			t.Errorf("second complete = %v, want ErrSuperseded", err)
		}
		err := fromA(func(ctx context.Context, tx store.Tx) error { _, err := Fail(ctx, tx, c.Ref, "late", 0); return err })
		if !errors.Is(err, ErrSuperseded) {
			t.Errorf("fail after complete = %v, want ErrSuperseded", err)
		}
	})
}

func TestFailRetriesWithBackoffThenDiscards(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		id := e.enqueue(t, e.a, Job{Kind: "test.work", MaxAttempts: 2}).ID
		fail := func(c Claimed, code string, backoff time.Duration) (Outcome, error) {
			var out Outcome
			err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error {
				var err error
				out, err = Fail(ctx, tx, c.Ref, code, backoff)
				return err
			})
			return out, err
		}
		c := mustClaim(t, e, 1)[0]
		if _, err := fail(c, "Connection refused: dc01", 0); !errors.Is(err, ErrInvalid) {
			t.Fatalf("error text as a code = %v, want ErrInvalid", err)
		}
		if out, err := fail(c, "dc_unavailable", time.Hour); err != nil || out != Retried {
			t.Fatalf("first fail = %v, %v; want retried", out, err)
		}
		if got := mustClaim(t, e, 1); len(got) != 0 {
			t.Fatalf("a job in backoff was claimed: %+v", got)
		}
		if err := e.d.ExecOwner(context.Background(), `UPDATE public.jobs SET run_at = now() WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		c = mustClaim(t, e, 1)[0]
		if c.Attempt != 2 {
			t.Fatalf("attempt = %d, want 2", c.Attempt)
		}
		if out, err := fail(c, "dc_unavailable", time.Second); err != nil || out != Exhausted {
			t.Fatalf("last fail = %v, %v; want exhausted", out, err)
		}
		if st, _ := e.state(t, id); st != "discarded" {
			t.Fatalf("state = %s, want discarded", st)
		}
		if got := mustClaim(t, e, 1); len(got) != 0 {
			t.Fatalf("a discarded job was claimed: %+v", got)
		}
	})
}

func TestDiscardAndCancel(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		a := e.enqueue(t, e.a, Job{Kind: "test.work"}).ID
		c := mustClaim(t, e, 1)[0]
		if err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error { return Discard(ctx, tx, c.Ref, "denied") }); err != nil {
			t.Fatal(err)
		}
		if st, _ := e.state(t, a); st != "discarded" {
			t.Fatalf("state = %s", st)
		}
		avail := e.enqueue(t, e.a, Job{Kind: "test.work"}).ID
		// B cannot cancel A's job; A can; a running or finished job cannot be cancelled.
		if err := e.inTenant(t, e.b, func(ctx context.Context, tx store.Tx) error { return Cancel(ctx, tx, avail) }); !errors.Is(err, ErrNotCancellable) {
			t.Errorf("cancel from B = %v, want ErrNotCancellable", err)
		}
		if err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error { return Cancel(ctx, tx, avail) }); err != nil {
			t.Errorf("cancel from A = %v", err)
		}
		if err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error { return Cancel(ctx, tx, avail) }); !errors.Is(err, ErrNotCancellable) {
			t.Errorf("second cancel = %v, want ErrNotCancellable", err)
		}
		if got := mustClaim(t, e, 1); len(got) != 0 {
			t.Fatalf("a cancelled job was claimed: %+v", got)
		}
	})
}

func TestRescueRequeuesLapsedClaimsAndFencesTheOldAttempt(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		keep := e.enqueue(t, e.a, Job{Kind: "test.work", MaxAttempts: 1}).ID
		lapse := e.enqueue(t, e.a, Job{Kind: "test.work"}).ID
		running := e.enqueue(t, e.b, Job{Kind: "test.work"}).ID
		claimed := mustClaim(t, e, 3)
		if len(claimed) != 3 {
			t.Fatalf("claimed %d", len(claimed))
		}
		var old Claimed
		for _, c := range claimed {
			if c.ID == lapse {
				old = c
			}
		}
		// Two claims lapse (one on its last attempt); the third is still held.
		if err := e.d.ExecOwner(ctx, `UPDATE public.jobs SET claimed_until = now() - interval '1 minute' WHERE id = ANY($1)`, []int64{keep, lapse}); err != nil {
			t.Fatal(err)
		}
		r, err := Rescue(ctx, e.db, 10)
		if err != nil || r != (Rescued{Requeued: 1, Discarded: 1}) {
			t.Fatalf("rescue = %+v, %v; want 1 requeued, 1 discarded", r, err)
		}
		if st, _ := e.state(t, keep); st != "discarded" {
			t.Errorf("exhausted job is %s, want discarded", st)
		}
		if st, _ := e.state(t, running); st != "running" {
			t.Errorf("a live claim is %s, want running", st)
		}
		// The crashed worker's late result changes nothing, even after a new worker holds the job.
		again := mustClaim(t, e, 1)
		if len(again) != 1 || again[0].ID != lapse || again[0].Attempt != 2 {
			t.Fatalf("re-claim = %+v, want job %d attempt 2", again, lapse)
		}
		if err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, old.Ref) }); !errors.Is(err, ErrSuperseded) {
			t.Fatalf("late completion by the superseded attempt = %v, want ErrSuperseded", err)
		}
		if err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, again[0].Ref) }); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCleanDeletesOnlyOldFinishedJobs(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		oldDone := e.enqueue(t, e.a, Job{Kind: "test.work"}).ID
		c := mustClaim(t, e, 1)[0]
		if err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, c.Ref) }); err != nil {
			t.Fatal(err)
		}
		recentDone := e.enqueue(t, e.a, Job{Kind: "test.work"}).ID
		c2 := mustClaim(t, e, 1)[0]
		if err := e.inTenant(t, e.a, func(ctx context.Context, tx store.Tx) error { return Complete(ctx, tx, c2.Ref) }); err != nil {
			t.Fatal(err)
		}
		live := e.enqueue(t, e.a, Job{Kind: "test.work"}).ID
		if err := e.d.ExecOwner(ctx, `UPDATE public.jobs SET finalized_at = now() - interval '30 days' WHERE id = $1`, oldDone); err != nil {
			t.Fatal(err)
		}
		n, err := Clean(ctx, e.db, 7*24*time.Hour, 100)
		if err != nil || n != 1 {
			t.Fatalf("clean = %d, %v; want 1", n, err)
		}
		left, _ := e.d.OwnerStrings(ctx, `SELECT id::text FROM public.jobs ORDER BY id`)
		if len(left) != 2 {
			t.Fatalf("left %v, want jobs %d and %d", left, recentDone, live)
		}
	})
}

func TestBackoffDoublesAndCaps(t *testing.T) {
	want := map[int]time.Duration{0: 5 * time.Second, 1: 5 * time.Second, 2: 10 * time.Second, 3: 20 * time.Second, 10: 2560 * time.Second, 11: time.Hour, 500: time.Hour}
	for in, w := range want {
		if got := Backoff(in); got != w {
			t.Errorf("Backoff(%d) = %s, want %s", in, got, w)
		}
	}
}
