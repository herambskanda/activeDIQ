package saml_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso/saml"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type pgRig struct {
	d      *storetest.Database
	nodeA  *saml.PGReplayCache
	nodeB  *saml.PGReplayCache
	dbA    *store.DB
	t1, t2 tenant.ID
}

func eachPG(t *testing.T, fn func(t *testing.T, r *pgRig)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		open := func() (*store.DB, *saml.PGReplayCache) {
			db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(db.Close)
			c, err := saml.NewPGReplayCache(db)
			if err != nil {
				t.Fatal(err)
			}
			return db, c
		}
		r := &pgRig{d: d}
		r.dbA, r.nodeA = open()
		_, r.nodeB = open() // a second node: its own pool, the same database
		r.t1 = tenanttest.Seed(t, d.ExecOwner, "A")
		r.t2 = tenanttest.Seed(t, d.ExecOwner, "B")
		fn(t, r)
	})
}

// Acceptance 1: the same assertion ID posted to two nodes is refused the second time.
func TestPGReplayTwoNodesRefuseTheSecondPost(t *testing.T) {
	eachPG(t, func(t *testing.T, r *pgRig) {
		ctx := context.Background()
		until := time.Now().Add(5 * time.Minute)
		fresh, err := r.nodeA.Remember(ctx, r.t1, "idp-1", "_a1", until)
		if err != nil || !fresh {
			t.Fatalf("node A first: fresh=%v err=%v", fresh, err)
		}
		fresh, err = r.nodeB.Remember(ctx, r.t1, "idp-1", "_a1", until)
		if err != nil || fresh {
			t.Fatalf("node B second must be a replay: fresh=%v err=%v", fresh, err)
		}
	})
}

func TestPGReplayKeyIsTenantIdPAndID(t *testing.T) {
	eachPG(t, func(t *testing.T, r *pgRig) {
		ctx := context.Background()
		until := time.Now().Add(time.Minute)
		for _, c := range []struct {
			t       tenant.ID
			idp, id string
		}{{r.t1, "idp-1", "_a"}, {r.t2, "idp-1", "_a"}, {r.t1, "idp-2", "_a"}, {r.t1, "idp-1", "_b"}} {
			fresh, err := r.nodeA.Remember(ctx, c.t, c.idp, c.id, until)
			if err != nil || !fresh {
				t.Fatalf("%v: fresh=%v err=%v", c, fresh, err)
			}
		}
	})
}

func TestPGReplayRaceHasOneWinner(t *testing.T) {
	eachPG(t, func(t *testing.T, r *pgRig) {
		ctx := context.Background()
		until := time.Now().Add(time.Minute)
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			c := r.nodeA
			if i%2 == 1 {
				c = r.nodeB
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				fresh, err := c.Remember(ctx, r.t1, "idp-1", "_race", until)
				if err != nil {
					t.Error(err)
				}
				if fresh {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("winners = %d, want exactly 1", wins.Load())
		}
	})
}

func TestPGReplayExpiredRowDoesNotBlockAndUnexpiredIsNotTrimmed(t *testing.T) {
	eachPG(t, func(t *testing.T, r *pgRig) {
		ctx := context.Background()
		if fresh, err := r.nodeA.Remember(ctx, r.t1, "idp-1", "_short", time.Now().Add(1500*time.Millisecond)); err != nil || !fresh {
			t.Fatalf("fresh=%v err=%v", fresh, err)
		}
		if fresh, err := r.nodeA.Remember(ctx, r.t1, "idp-1", "_long", time.Now().Add(time.Hour)); err != nil || !fresh {
			t.Fatalf("fresh=%v err=%v", fresh, err)
		}
		time.Sleep(2 * time.Second)
		// Any later call trims the expired row; the unexpired one stays and still refuses.
		if fresh, err := r.nodeB.Remember(ctx, r.t1, "idp-1", "_other", time.Now().Add(time.Minute)); err != nil || !fresh {
			t.Fatalf("fresh=%v err=%v", fresh, err)
		}
		if fresh, err := r.nodeB.Remember(ctx, r.t1, "idp-1", "_long", time.Now().Add(time.Hour)); err != nil || fresh {
			t.Fatalf("unexpired row must still refuse: fresh=%v err=%v", fresh, err)
		}
		var n int
		err := r.dbA.WithTenant(ctx, r.t1, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_saml_replay WHERE assertion_id = '_short'`).Scan(&n)
		})
		if err != nil || n != 0 {
			t.Fatalf("expired row should be trimmed: n=%d err=%v", n, err)
		}
	})
}

func TestPGReplayRefusesBadInputWithoutWriting(t *testing.T) {
	eachPG(t, func(t *testing.T, r *pgRig) {
		ctx := context.Background()
		long := make([]byte, 1025)
		for i := range long {
			long[i] = 'x'
		}
		now := time.Now()
		for name, f := range map[string]func() (bool, error){
			"zero tenant":  func() (bool, error) { return r.nodeA.Remember(ctx, tenant.ID{}, "i", "a", now.Add(time.Minute)) },
			"empty idp":    func() (bool, error) { return r.nodeA.Remember(ctx, r.t1, "", "a", now.Add(time.Minute)) },
			"empty id":     func() (bool, error) { return r.nodeA.Remember(ctx, r.t1, "i", "", now.Add(time.Minute)) },
			"long id":      func() (bool, error) { return r.nodeA.Remember(ctx, r.t1, "i", string(long), now.Add(time.Minute)) },
			"zero expiry":  func() (bool, error) { return r.nodeA.Remember(ctx, r.t1, "i", "a", time.Time{}) },
			"past expiry":  func() (bool, error) { return r.nodeA.Remember(ctx, r.t1, "i", "a", now.Add(-time.Minute)) },
			"too far away": func() (bool, error) { return r.nodeA.Remember(ctx, r.t1, "i", "a", now.Add(48*time.Hour)) },
		} {
			fresh, err := f()
			if fresh || !errors.Is(err, saml.ErrReplayInput) {
				t.Errorf("%s: fresh=%v err=%v, want ErrReplayInput", name, fresh, err)
			}
		}
	})
}

// RememberTx commits or rolls back with the caller's transaction (SAML-16: same tx as consuming the Transaction).
func TestPGRememberTxRollsBackWithTheCaller(t *testing.T) {
	eachPG(t, func(t *testing.T, r *pgRig) {
		ctx := context.Background()
		until := time.Now().Add(time.Minute)
		boom := errors.New("rollback")
		err := r.dbA.WithTenant(ctx, r.t1, func(ctx context.Context, tx store.Tx) error {
			if fresh, err := saml.RememberTx(ctx, tx, r.t1, "idp-1", "_tx", until); err != nil || !fresh {
				t.Fatalf("fresh=%v err=%v", fresh, err)
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
		if fresh, err := r.nodeB.Remember(ctx, r.t1, "idp-1", "_tx", until); err != nil || !fresh {
			t.Fatalf("after rollback the ID must be new: fresh=%v err=%v", fresh, err)
		}
	})
}

// Row security: a transaction of tenant 2 cannot write or see tenant 1's rows, nor delete or update them.
func TestPGReplayTenantIsolationAndInsertOnly(t *testing.T) {
	eachPG(t, func(t *testing.T, r *pgRig) {
		ctx := context.Background()
		until := time.Now().Add(time.Hour)
		if _, err := r.nodeA.Remember(ctx, r.t1, "idp-1", "_iso", until); err != nil {
			t.Fatal(err)
		}
		err := r.dbA.WithTenant(ctx, r.t2, func(ctx context.Context, tx store.Tx) error {
			if _, err := saml.RememberTx(ctx, tx, r.t1, "idp-1", "_cross", until); err == nil {
				t.Error("writing another tenant's row must fail")
			}
			return nil
		})
		_ = err
		for _, q := range []string{
			`SELECT count(*) FROM public.authn_saml_replay`,
		} {
			var n int
			if err := r.dbA.WithTenant(ctx, r.t2, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, q).Scan(&n)
			}); err != nil || n != 0 {
				t.Errorf("tenant 2 sees %d rows (err %v)", n, err)
			}
		}
		// Own tenant: no UPDATE, and no DELETE of an unexpired row.
		_ = r.dbA.WithTenant(ctx, r.t1, func(ctx context.Context, tx store.Tx) error { return nil })
		upd := r.dbA.WithTenant(ctx, r.t1, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.authn_saml_replay SET expires_at = expires_at + interval '1 minute'`)
			return err
		})
		if upd == nil {
			t.Error("the runtime role must not UPDATE replay rows")
		}
		var del int64
		if err := r.dbA.WithTenant(ctx, r.t1, func(ctx context.Context, tx store.Tx) error {
			tag, err := tx.Exec(ctx, `DELETE FROM public.authn_saml_replay`)
			del = tag.RowsAffected()
			return err
		}); err != nil || del != 0 {
			t.Errorf("deleted %d unexpired rows (err %v)", del, err)
		}
	})
}

// Acceptance 1 (T-0524): the trim-safety invariant. Once an assertion's row has expired and been trimmed,
// presenting the same assertion again (same, deterministic expiry) is still refused, as ErrReplayInput.
func TestPGReplayAfterTrimIsStillRefused(t *testing.T) {
	eachPG(t, func(t *testing.T, r *pgRig) {
		ctx := context.Background()
		until := time.Now().Add(1500 * time.Millisecond)
		if fresh, err := r.nodeA.Remember(ctx, r.t1, "idp-1", "_trim", until); err != nil || !fresh {
			t.Fatalf("fresh=%v err=%v", fresh, err)
		}
		time.Sleep(2 * time.Second)
		// A later call trims the expired row.
		if _, err := r.nodeB.Remember(ctx, r.t1, "idp-1", "_other", time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := r.dbA.WithTenant(ctx, r.t1, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_saml_replay WHERE assertion_id = '_trim'`).Scan(&n)
		}); err != nil || n != 0 {
			t.Fatalf("row should be trimmed: n=%d err=%v", n, err)
		}
		fresh, err := r.nodeB.Remember(ctx, r.t1, "idp-1", "_trim", until)
		if fresh || !errors.Is(err, saml.ErrReplayInput) {
			t.Fatalf("replay after trim: fresh=%v err=%v, want ErrReplayInput", fresh, err)
		}
	})
}

// Acceptance 3 (T-0524): a long transaction that trimmed expired rows does not make a concurrent
// RememberTx of the same tenant wait for it.
func TestPGRememberTxTrimDoesNotSerialise(t *testing.T) {
	eachPG(t, func(t *testing.T, r *pgRig) {
		ctx := context.Background()
		for _, id := range []string{"_e1", "_e2"} {
			if _, err := r.nodeA.Remember(ctx, r.t1, "idp-1", id, time.Now().Add(1200*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(1800 * time.Millisecond)

		trimmed, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		var once sync.Once
		releaseTx := func() { once.Do(func() { close(release) }) }
		defer releaseTx() // a failing assertion must not leave the transaction open
		go func() {
			done <- r.dbA.WithTenant(ctx, r.t1, func(ctx context.Context, tx store.Tx) error {
				if _, err := saml.RememberTx(ctx, tx, r.t1, "idp-1", "_long1", time.Now().Add(time.Minute)); err != nil {
					return err
				}
				close(trimmed)
				<-release // keep the transaction (and any row locks) open
				return nil
			})
		}()
		<-trimmed

		second := make(chan error, 1)
		go func() {
			_, err := r.nodeB.Remember(ctx, r.t1, "idp-1", "_long2", time.Now().Add(time.Minute))
			second <- err
		}()
		select {
		case err := <-second:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("second RememberTx blocked behind the first transaction's trim")
		}
		releaseTx()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}
