package signin_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/signin"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type txRig struct {
	d      *storetest.Database
	a, b   *signin.TxStore // two nodes: own pools, one database
	t1, t2 tenant.ID
	now    *atomic.Int64 // unix nanos, the stores' clock
}

func eachTx(t *testing.T, fn func(t *testing.T, r *txRig)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		r := &txRig{d: d, now: new(atomic.Int64)}
		r.now.Store(time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC).UnixNano())
		clock := func() time.Time { return time.Unix(0, r.now.Load()).UTC() }
		open := func() *signin.TxStore {
			db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(db.Close)
			ts, err := signin.NewTxStore(db, clock)
			if err != nil {
				t.Fatal(err)
			}
			return ts
		}
		r.a, r.b = open(), open()
		r.t1 = tenanttest.Seed(t, d.ExecOwner, "A")
		r.t2 = tenanttest.Seed(t, d.ExecOwner, "B")
		fn(t, r)
	})
}

func tx() sso.Transaction {
	return sso.Transaction{IdPID: "idp1", Intent: sso.IntentSignin, State: "s", Nonce: "n", Verifier: "v", ReturnPath: "/users"}
}

func TestTxStoreRoundTripAcrossNodes(t *testing.T) {
	eachTx(t, func(t *testing.T, r *txRig) {
		ctx := context.Background()
		h, err := r.a.Put(ctx, r.t1, tx())
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.b.Consume(ctx, r.t1, h)
		if err != nil {
			t.Fatalf("node B consume: %v", err)
		}
		if got.IdPID != "idp1" || got.State != "s" || got.Nonce != "n" || got.Verifier != "v" || got.ReturnPath != "/users" {
			t.Fatalf("got %+v", got)
		}
	})
}

// SSO-1: the same callback twice is refused, even when both arrive at once on two nodes.
func TestTxStoreConsumedOnce(t *testing.T) {
	eachTx(t, func(t *testing.T, r *txRig) {
		ctx := context.Background()
		h, err := r.a.Put(ctx, r.t1, tx())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.a.Consume(ctx, r.t1, h); err != nil {
			t.Fatal(err)
		}
		if _, err := r.b.Consume(ctx, r.t1, h); !errors.Is(err, signin.ErrNoTransaction) {
			t.Fatalf("second consume = %v, want ErrNoTransaction", err)
		}

		h, _ = r.a.Put(ctx, r.t1, tx())
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				s := r.a
				if i%2 == 1 {
					s = r.b
				}
				if _, err := s.Consume(ctx, r.t1, h); err == nil {
					wins.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d concurrent consumers won, want exactly 1", wins.Load())
		}
	})
}

// SSO-1: older than five minutes is refused, and the row is gone afterwards.
func TestTxStoreExpired(t *testing.T) {
	eachTx(t, func(t *testing.T, r *txRig) {
		ctx := context.Background()
		h, err := r.a.Put(ctx, r.t1, tx())
		if err != nil {
			t.Fatal(err)
		}
		r.now.Add(int64(signin.TransactionTTL)) // exactly five minutes: expired
		if _, err := r.b.Consume(ctx, r.t1, h); !errors.Is(err, signin.ErrTransactionExpired) {
			t.Fatalf("consume at 5m = %v, want ErrTransactionExpired", err)
		}
		if _, err := r.b.Consume(ctx, r.t1, h); !errors.Is(err, signin.ErrNoTransaction) {
			t.Fatalf("after an expired consume = %v, want ErrNoTransaction", err)
		}
		// Just under five minutes is still good.
		h, _ = r.a.Put(ctx, r.t1, tx())
		r.now.Add(int64(signin.TransactionTTL - time.Second))
		if _, err := r.a.Consume(ctx, r.t1, h); err != nil {
			t.Fatalf("consume at 4m59s: %v", err)
		}
	})
}

// SSO-1: a handle is useless in another tenant and unguessable shapes are refused.
func TestTxStoreOtherTenantAndBadHandle(t *testing.T) {
	eachTx(t, func(t *testing.T, r *txRig) {
		ctx := context.Background()
		h, _ := r.a.Put(ctx, r.t1, tx())
		if _, err := r.a.Consume(ctx, r.t2, h); !errors.Is(err, signin.ErrNoTransaction) {
			t.Fatalf("other tenant = %v", err)
		}
		if _, err := r.a.Consume(ctx, r.t1, h); err != nil {
			t.Fatalf("the owner tenant must still be able to consume: %v", err)
		}
		if _, err := signin.ParseHandle("short"); !errors.Is(err, signin.ErrNoTransaction) {
			t.Fatalf("short handle = %v", err)
		}
	})
}

func TestTxStoreStoresOnlyTheHash(t *testing.T) {
	eachTx(t, func(t *testing.T, r *txRig) {
		ctx := context.Background()
		h, _ := r.a.Put(ctx, r.t1, tx())
		rows, err := r.d.OwnerStrings(ctx, `SELECT t::text FROM public.authn_sso_transactions t WHERE t::text LIKE '%' || $1 || '%'`, h.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		n := len(rows)
		if n != 0 {
			t.Fatal("the raw handle is stored")
		}
		if strings.Contains(h.String(), h.Reveal()) {
			t.Fatal("String leaks the handle")
		}
	})
}

func TestTxStoreRejectsInvalid(t *testing.T) {
	eachTx(t, func(t *testing.T, r *txRig) {
		bad := tx()
		bad.ReturnPath = ""
		if _, err := r.a.Put(context.Background(), r.t1, bad); err == nil {
			t.Fatal("empty return path accepted")
		}
	})
}
