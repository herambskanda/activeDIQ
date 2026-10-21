package jobs

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Acceptance 1: of many concurrent callers for one name, exactly one holds it until release or expiry.
func TestAcquireLeaseIsExclusiveUnderConcurrency(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		const callers = 12
		var won atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, ok, err := AcquireLease(ctx, e.db, "test.singleton", "node-"+string(rune('a'+i)), time.Minute)
				if err != nil {
					t.Errorf("acquire: %v", err)
				}
				if ok {
					won.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if won.Load() != 1 {
			t.Fatalf("%d callers hold the lease, want exactly 1", won.Load())
		}
		// Different names are independent.
		if _, ok, err := AcquireLease(ctx, e.db, "test.other", "node-z", time.Minute); err != nil || !ok {
			t.Fatalf("a different name = %v, %v; want held", ok, err)
		}
	})
}

// Acceptance 2: a holder that stops renewing is replaced, and its renew (and release) are fenced.
func TestExpiredLeaseIsTakenOverAndOldHolderFenced(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		old, ok, err := AcquireLease(ctx, e.db, "test.singleton", "node-a", time.Minute)
		if err != nil || !ok {
			t.Fatalf("first acquire = %v, %v", ok, err)
		}
		if _, ok, _ := AcquireLease(ctx, e.db, "test.singleton", "node-b", time.Minute); ok {
			t.Fatal("second caller acquired a live lease")
		}
		if _, err := RenewLease(ctx, e.db, old, time.Minute); err != nil {
			t.Fatalf("holder renew: %v", err)
		}
		// The holder stops renewing: the lease lapses.
		if err := e.d.ExecOwner(ctx, `UPDATE public.platform_leases SET expires_at = now() - interval '1 second'`); err != nil {
			t.Fatal(err)
		}
		if _, err := RenewLease(ctx, e.db, old, time.Minute); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("renew after expiry = %v, want ErrLeaseLost", err)
		}
		next, ok, err := AcquireLease(ctx, e.db, "test.singleton", "node-b", time.Minute)
		if err != nil || !ok {
			t.Fatalf("takeover = %v, %v", ok, err)
		}
		if next.Token <= old.Token {
			t.Fatalf("fencing token %d did not rise above %d", next.Token, old.Token)
		}
		if _, err := RenewLease(ctx, e.db, old, time.Minute); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("old holder renew = %v, want ErrLeaseLost", err)
		}
		if err := ReleaseLease(ctx, e.db, old); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("old holder release = %v, want ErrLeaseLost", err)
		}
		// Release frees it at once and the token keeps rising.
		if err := ReleaseLease(ctx, e.db, next); err != nil {
			t.Fatal(err)
		}
		third, ok, err := AcquireLease(ctx, e.db, "test.singleton", "node-c", time.Minute)
		if err != nil || !ok || third.Token <= next.Token {
			t.Fatalf("acquire after release = %+v, %v, %v", third, ok, err)
		}
	})
}

func TestLeaseRefusesMalformedInput(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		for name, fn := range map[string]func() error{
			"name":   func() error { _, _, err := AcquireLease(ctx, e.db, "Bad Name", "n", time.Minute); return err },
			"holder": func() error { _, _, err := AcquireLease(ctx, e.db, "x.y", "", time.Minute); return err },
			"ttl":    func() error { _, _, err := AcquireLease(ctx, e.db, "x.y", "n", 0); return err },
		} {
			if err := fn(); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: %v, want ErrInvalid", name, err)
			}
		}
	})
}

// Acceptance 3: with two workers, only the lease holder executes Rescue and Clean; the lease is freed after.
func TestRescueAndCleanRunOnlyUnderTheirLease(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		// Worker B holds both leases: worker A's entry points do nothing.
		rl, _, _ := AcquireLease(ctx, e.db, LeaseRescue, "worker-b", time.Minute)
		cl, _, _ := AcquireLease(ctx, e.db, LeaseClean, "worker-b", time.Minute)
		if _, ran, err := RunRescue(ctx, e.db, "worker-a", 10); err != nil || ran {
			t.Fatalf("rescue while another holds the lease: ran=%v err=%v", ran, err)
		}
		if _, ran, err := RunClean(ctx, e.db, "worker-a", time.Hour, 10); err != nil || ran {
			t.Fatalf("clean while another holds the lease: ran=%v err=%v", ran, err)
		}
		// A lapsed claim stays running: nobody rescued it.
		id := e.enqueue(t, e.a, Job{Kind: "test.work", Args: ref{ID: "1"}, MaxAttempts: 3}).ID
		if got, _ := Claim(ctx, e.db, oneKind, 1); len(got) != 1 {
			t.Fatal("claim failed")
		}
		if err := e.d.ExecOwner(ctx, `UPDATE public.jobs SET claimed_until = now() - interval '1 second' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if st, _ := e.state(t, id); st != "running" {
			t.Fatalf("state = %s, want running (not rescued)", st)
		}
		// Once B lets go, A rescues, and releases its own lease.
		_ = ReleaseLease(ctx, e.db, rl)
		_ = ReleaseLease(ctx, e.db, cl)
		r, ran, err := RunRescue(ctx, e.db, "worker-a", 10)
		if err != nil || !ran || r.Requeued != 1 {
			t.Fatalf("rescue = %+v ran=%v err=%v; want 1 requeued", r, ran, err)
		}
		if st, _ := e.state(t, id); st != "available" {
			t.Fatalf("state = %s, want available", st)
		}
		if _, ran, err := RunClean(ctx, e.db, "worker-b", time.Hour, 10); err != nil || !ran {
			t.Fatalf("clean after the lease was released: ran=%v err=%v", ran, err)
		}
		if _, ok, _ := AcquireLease(ctx, e.db, LeaseRescue, "worker-b", time.Minute); !ok {
			t.Fatal("rescue lease was not released after the run")
		}
	})
}
