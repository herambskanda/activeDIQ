package authn

import (
	"context"
	"encoding/base32"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

// pending creates a pending enrollment and returns its id and seed.
func (e *env) pending(t *testing.T, tid tenant.ID) (string, []byte) {
	t.Helper()
	var id string
	var seed []byte
	err := e.tx(t, tid, func(ctx context.Context, tx store.Tx) error {
		p, err := e.svc.Enroll(ctx, tx, tid, Subject{AccountID: acct}, "phone")
		if err != nil {
			return err
		}
		id = p.ID
		p.Seed.Expose(func(b []byte) { seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(b)) })
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, seed
}

func (e *env) info(t *testing.T, id string) Info {
	t.Helper()
	var in Info
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		var err error
		in, err = e.svc.Get(ctx, tx, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return in
}

// verifyRollback is a caller that rolls its transaction back whatever the outcome.
func (e *env) verifyRollback(t *testing.T, id, code string) error {
	t.Helper()
	var got error
	_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		got = e.svc.Verify(ctx, tx, e.a, id, code)
		return errors.New("caller rolls back")
	})
	return got
}

func Test_totp_enrolment_pause_after_10(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, seed := e.enrol(t, e.a)
		for i := 0; i < MaxFailuresPerHour; i++ { // several transactions, as several callers would
			if err := e.verify(t, e.a, id, "000000"); !errors.Is(err, ErrCodeRejected) {
				t.Fatalf("wrong code %d: %v", i, err)
			}
			e.now = e.now.Add(time.Minute)
		}
		in := e.info(t, id)
		if in.PausedUntil == nil || !in.PausedUntil.After(e.now) {
			t.Fatalf("paused_until = %v", in.PausedUntil)
		}
		// A correct, unused code is refused while paused, and does not spend its step.
		good := hotp(seed, stepAt(e.now)+1)
		if err := e.verify(t, e.a, id, good); !errors.Is(err, ErrFactorPaused) {
			t.Fatalf("correct code while paused: %v", err)
		}
		// After the pause it works.
		e.now = in.PausedUntil.Add(time.Second)
		if err := e.verify(t, e.a, id, hotp(seed, stepAt(e.now))); err != nil {
			t.Fatalf("after the pause: %v", err)
		}
	})
}

func Test_totp_budget_is_rolling_and_nine_do_not_pause(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, seed := e.enrol(t, e.a)
		for i := 0; i < MaxFailuresPerHour-1; i++ {
			_ = e.verify(t, e.a, id, "000000")
		}
		if err := e.verify(t, e.a, id, hotp(seed, stepAt(e.now)+1)); err != nil {
			t.Fatalf("9 failures paused: %v", err)
		}
		// Failures older than the hour no longer count: 9 now + 9 an hour and a bit later do not pause.
		e.now = e.now.Add(FailureWindow + time.Minute)
		for i := 0; i < MaxFailuresPerHour-1; i++ {
			_ = e.verify(t, e.a, id, "000000")
		}
		if in := e.info(t, id); in.PausedUntil != nil {
			t.Fatalf("paused by failures spread over two hours: %v", in.PausedUntil)
		}
	})
}

func Test_totp_failures_survive_caller_rollback(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, seed := e.enrol(t, e.a)
		for i := 0; i < MaxFailuresPerHour; i++ {
			if err := e.verifyRollback(t, id, "000000"); !errors.Is(err, ErrCodeRejected) {
				t.Fatalf("refusal %d: %v", i, err)
			}
		}
		if in := e.info(t, id); in.PausedUntil == nil {
			t.Fatal("ten rolled-back refusals did not pause the enrolment")
		}
		if err := e.verify(t, e.a, id, hotp(seed, stepAt(e.now)+1)); !errors.Is(err, ErrFactorPaused) {
			t.Fatalf("correct code after rolled-back failures: %v", err)
		}
	})
}

func Test_totp_pending_expiry_and_confirm_limit(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		activate := func(id, code string) error {
			var got error
			_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
				got = e.svc.Activate(ctx, tx, e.a, id, code)
				return errors.New("rollback")
			})
			return got
		}
		base := e.now // the database clamps an expiry to 10 minutes past its own clock
		// Older than 10 minutes.
		id, seed := e.pending(t, e.a)
		e.now = e.now.Add(PendingTTL)
		if err := activate(id, hotp(seed, stepAt(e.now))); !errors.Is(err, ErrCodeRejected) {
			t.Fatalf("expired activate: %v", err)
		}
		if in := e.info(t, id); in.State != StateExpired {
			t.Fatalf("state = %s", in.State)
		}
		// Five wrong confirms, then a correct code.
		e.now = base
		id, seed = e.pending(t, e.a)
		for i := 0; i < MaxConfirmAttempts; i++ {
			if err := activate(id, "000000"); !errors.Is(err, ErrCodeRejected) {
				t.Fatalf("confirm %d: %v", i, err)
			}
		}
		if in := e.info(t, id); in.State != StateExpired {
			t.Fatalf("after 5 wrong confirms state = %s", in.State)
		}
		if err := activate(id, hotp(seed, stepAt(e.now))); !errors.Is(err, ErrCodeRejected) {
			t.Fatalf("activate after limit: %v", err)
		}
		// Four wrong then correct still activates.
		e.now = base
		id, seed = e.pending(t, e.a)
		for i := 0; i < MaxConfirmAttempts-1; i++ {
			_ = activate(id, "000000")
		}
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			return e.svc.Activate(ctx, tx, e.a, id, hotp(seed, stepAt(e.now)))
		}); err != nil {
			t.Fatalf("4 wrong then right: %v", err)
		}
		if in := e.info(t, id); in.State != StateActive {
			t.Fatalf("4 wrong then right: state = %s", in.State)
		}
	})
}

func Test_totp_expired_is_terminal(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, _ := e.pending(t, e.a)
		if _, err := e.exec(t, e.a, `UPDATE public.authn_authenticator_enrollments SET state = 'expired' WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		for _, st := range []string{"active", "pending", "revoked"} {
			if _, err := e.exec(t, e.a, `UPDATE public.authn_authenticator_enrollments SET state = $2 WHERE id = $1::uuid`, id, st); err == nil {
				t.Errorf("expired -> %s allowed", st)
			}
		}
	})
}

func Test_totp_insert_starts_pending(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		blob := make([]byte, 48)
		insert := func(cols, vals string) error {
			_, err := e.exec(t, e.a, `INSERT INTO public.authn_authenticator_enrollments
				(tenant_id, account_id, method, sealed_secret, key_version, label`+cols+`)
				VALUES ($1::uuid, $2::uuid, 'totp', $3, 1, 'l'`+vals+`)`, e.a.String(), acct, blob)
			return err
		}
		for name, c := range map[string][2]string{
			"active":             {", state, expires_at", ", 'active', now()"},
			"expired":            {", state, expires_at", ", 'expired', now()"},
			"used step":          {", last_used_step, last_used, expires_at", ", 5, now(), now()"},
			"paused":             {", paused_until, expires_at", ", now(), now()"},
			"confirm attempts":   {", confirm_attempts, expires_at", ", 1, now()"},
			"pending, no expiry": {"", ""},
		} {
			if err := insert(c[0], c[1]); err == nil {
				t.Errorf("%s: INSERT was allowed", name)
			}
		}
		if err := insert(", expires_at", ", now() + interval '1000 years'"); err != nil {
			t.Errorf("a pending INSERT with a far expiry was refused: %v", err)
		}
		var late int
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_authenticator_enrollments WHERE expires_at > now() + interval '10 minutes'`).Scan(&late)
		}); err != nil || late != 0 {
			t.Errorf("%d enrolments expire later than 10 minutes after insert (%v); the database must clamp", late, err)
		}
		if err := insert(", expires_at", ", now() + interval '10 minutes'"); err != nil {
			t.Errorf("a plain pending INSERT was refused: %v", err)
		}
	})
}

func Test_totp_without_failure_store_fails_closed(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, seed := e.enrol(t, e.a)
		e.svc.Failures = nil
		if err := e.verify(t, e.a, id, hotp(seed, stepAt(e.now)+1)); err == nil || errors.Is(err, ErrCodeRejected) {
			t.Fatalf("verify without a failure store: %v", err)
		}
	})
}

func Test_totp_pause_cannot_be_cleared_by_app(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, _ := e.enrol(t, e.a)
		set := func(v string) error {
			_, err := e.exec(t, e.a, `UPDATE public.authn_authenticator_enrollments SET paused_until = `+v+` WHERE id = $1::uuid`, id)
			return err
		}
		if err := set(`now() + interval '1 hour'`); err != nil {
			t.Fatalf("setting a pause: %v", err)
		}
		if err := set(`now() + interval '2 hours'`); err != nil {
			t.Fatalf("extending a pause: %v", err)
		}
		if err := set(`NULL`); err == nil {
			t.Error("paused_until cleared by the app role")
		}
		if err := set(`now() + interval '1 minute'`); err == nil {
			t.Error("paused_until shortened by the app role")
		}
	})
}

func Test_totp_failure_rows_cannot_be_deleted_early(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, _ := e.enrol(t, e.a)
		for _, age := range []string{"1 minute", "80 minutes", "3 hours"} {
			if _, err := e.exec(t, e.a, `INSERT INTO public.authn_totp_failures (tenant_id, enrollment_id, at)
				VALUES ($1::uuid, $2::uuid, now() - $3::interval)`, e.a.String(), id, age); err != nil {
				t.Fatal(err)
			}
		}
		del := func(age string) error {
			_, err := e.exec(t, e.a, `DELETE FROM public.authn_totp_failures WHERE enrollment_id = $1::uuid AND at > now() - $2::interval AND at <= now() - $3::interval`,
				id, "10 hours", age)
			return err
		}
		if err := del("0 seconds"); err == nil {
			t.Error("recent failure rows deleted by the app role")
		}
		if err := del("2 hours"); err != nil {
			t.Errorf("pruning rows older than 2h refused: %v", err)
		}
	})
}

// Many requests racing on one enrolment: the attempt is charged before the code is evaluated, so only the
// budget's worth is ever evaluated, whatever the concurrency (security review T-0361, finding 1).
func Test_totp_parallel_guesses_bounded(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		run := func(id string, n int, call func(ctx context.Context, tx store.Tx, code string) error) (rejected, paused int) {
			var wg sync.WaitGroup
			var mu sync.Mutex
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					var got error
					_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
						got = call(ctx, tx, "000000")
						return nil
					})
					mu.Lock()
					defer mu.Unlock()
					switch {
					case errors.Is(got, ErrCodeRejected):
						rejected++
					case errors.Is(got, ErrFactorPaused):
						paused++
					default:
						t.Errorf("unexpected: %v", got)
					}
				}()
			}
			wg.Wait()
			return
		}
		id, _ := e.enrol(t, e.a)
		rej, pau := run(id, 60, func(ctx context.Context, tx store.Tx, c string) error { return e.svc.Verify(ctx, tx, e.a, id, c) })
		if rej != MaxFailuresPerHour || pau != 60-MaxFailuresPerHour {
			t.Fatalf("active: %d evaluated, %d paused; want %d and %d", rej, pau, MaxFailuresPerHour, 60-MaxFailuresPerHour)
		}
		if e.info(t, id).PausedUntil == nil {
			t.Error("not paused")
		}
		pid, _ := e.pending(t, e.a)
		run(pid, 60, func(ctx context.Context, tx store.Tx, c string) error { return e.svc.Activate(ctx, tx, e.a, pid, c) })
		// Every evaluated confirm is charged once; the later ones are refused unevaluated.
		var charged int
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT confirm_attempts FROM public.authn_authenticator_enrollments WHERE id = $1::uuid`, pid).Scan(&charged)
		}); err != nil || charged != MaxConfirmAttempts {
			t.Fatalf("pending: %d confirms charged (%v); want %d", charged, err, MaxConfirmAttempts)
		}
		if in := e.info(t, pid); in.State != StateExpired {
			t.Errorf("pending state = %s", in.State)
		}
	})
}

// Refusals hold a main-pool connection while they need a second one; the second comes from a pool of its
// own, so a burst cannot starve the main pool (finding 2).
func Test_totp_refusals_do_not_starve_pool(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN(), MaxConns: 4})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		tid := tenanttest.Seed(t, d.ExecOwner, "A")
		e := &env{db: db, d: d, a: tid, now: time.Now().Truncate(time.Second)}
		e.svc = &Service{Keys: &keySource{}, Failures: db, Now: func() time.Time { return e.now }}
		id, _ := e.enrol(t, tid)
		done := make(chan error, 16)
		for i := 0; i < 16; i++ {
			go func() {
				done <- db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
					err := e.svc.Verify(ctx, tx, tid, id, "000000")
					if errors.Is(err, ErrCodeRejected) || errors.Is(err, ErrFactorPaused) {
						return nil
					}
					return err
				})
			}()
		}
		timeout := time.After(30 * time.Second)
		for i := 0; i < 16; i++ {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("caller: %v", err)
				}
			case <-timeout:
				t.Fatal("the pool is stalled")
			}
		}
		if err := db.WithTenant(context.Background(), tid, func(context.Context, store.Tx) error { return nil }); err != nil {
			t.Fatal(err)
		}
	})
}

// A success is refunded only by the transaction that spent the step; the app cannot otherwise mark an
// attempt as succeeded.
func Test_totp_refund_only_with_spend(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, _ := e.enrol(t, e.a)
		if _, err := e.exec(t, e.a, `INSERT INTO public.authn_totp_failures (tenant_id, enrollment_id, at) VALUES ($1::uuid, $2::uuid, now())`, e.a.String(), id); err != nil {
			t.Fatal(err)
		}
		if _, err := e.exec(t, e.a, `UPDATE public.authn_totp_failures SET succeeded = true WHERE enrollment_id = $1::uuid`, id); err == nil {
			t.Error("a failure was marked succeeded without a spend")
		}
		if _, err := e.exec(t, e.a, `UPDATE public.authn_totp_failures SET at = now() + interval '1 day' WHERE enrollment_id = $1::uuid`, id); err == nil {
			t.Error("a failure row was rewritten")
		}
	})
}
