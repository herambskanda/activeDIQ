package limiter

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

// node opens a second connection pool to the database: a separate server node in the same cluster.
func node(t *testing.T, d *storetest.Database) *PGStore {
	t.Helper()
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatalf("store.Open as the runtime role: %v", err)
	}
	t.Cleanup(db.Close)
	s, err := NewPGStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func eachDB(t *testing.T, fn func(t *testing.T, d *storetest.Database)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		fn(t, d)
	})
}

func limiterOn(t *testing.T, s PrincipalStore) *Limiter {
	t.Helper()
	l, err := New(Config{Principals: s})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// Acceptance 1: two limiters (two nodes) share one store; burst+1 calls across both refuse the last.
func TestBurstPlusOneAcrossTwoNodes(t *testing.T) {
	eachDB(t, func(t *testing.T, d *storetest.Database) {
		a, b := limiterOn(t, node(t, d)), limiterOn(t, node(t, d))
		p := apihost.Principal{ID: "human-1", Tenant: "t1", Kind: apihost.KindSession}
		burst := principalClasses["reveal"].Burst
		for i := 0; i < burst; i++ {
			l := a
			if i%2 == 1 {
				l = b
			}
			dec, err := l.AllowPrincipal(context.Background(), "reveal", p)
			if err != nil || !dec.Allowed {
				t.Fatalf("call %d inside the burst = %+v, %v", i+1, dec, err)
			}
		}
		for name, l := range map[string]*Limiter{"a": a, "b": b} {
			dec, err := l.AllowPrincipal(context.Background(), "reveal", p)
			if err != nil || dec.Allowed || dec.RetryAfter <= 0 {
				t.Fatalf("burst+1 on node %s = %+v, %v; want refused with RetryAfter > 0", name, dec, err)
			}
		}
	})
}

// Acceptance 2: a store error refuses; the Decision is never an admission.
func TestStoreErrorRefuses(t *testing.T) {
	eachDB(t, func(t *testing.T, d *storetest.Database) {
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		ps, _ := NewPGStore(db)
		l := limiterOn(t, ps)
		db.Close() // every later statement fails
		dec, err := l.AllowPrincipal(context.Background(), "secret", apihost.Principal{ID: "h", Tenant: "t"})
		if err == nil || dec.Allowed {
			t.Fatalf("closed database = %+v, %v; want an error and no admission", dec, err)
		}
	})
}

// Acceptance 4: concurrent takes on one key, from two pools, consume exactly the burst.
func TestTakeIsAtomicUnderConcurrency(t *testing.T) {
	eachDB(t, func(t *testing.T, d *storetest.Database) {
		stores := []*PGStore{node(t, d), node(t, d)}
		lim := Limit{Rate: 1, Burst: 20} // refills 1 token a minute: none during the test
		const callers = 120
		var admitted atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				dec, err := stores[i%2].Take(context.Background(), "race", lim)
				if err != nil {
					t.Errorf("take: %v", err)
					return
				}
				if dec.Allowed {
					admitted.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := admitted.Load(); got != int32(lim.Burst) {
			t.Fatalf("%d of %d concurrent takes admitted, want exactly the burst (%d)", got, callers, lim.Burst)
		}
	})
}

// Acceptance 5: the same principal ID in two tenants has two budgets.
func TestSameIDInTwoTenantsHasSeparateBudgets(t *testing.T) {
	eachDB(t, func(t *testing.T, d *storetest.Database) {
		l := limiterOn(t, node(t, d))
		ctx := context.Background()
		a := apihost.Principal{ID: "u-1", Tenant: "tenant-a"}
		b := apihost.Principal{ID: "u-1", Tenant: "tenant-b"}
		for i := 0; i < principalClasses["reveal"].Burst; i++ {
			if dec, err := l.AllowPrincipal(ctx, "reveal", a); err != nil || !dec.Allowed {
				t.Fatalf("tenant a call %d = %+v, %v", i+1, dec, err)
			}
		}
		if dec, _ := l.AllowPrincipal(ctx, "reveal", a); dec.Allowed {
			t.Fatal("tenant a was not drained")
		}
		if dec, err := l.AllowPrincipal(ctx, "reveal", b); err != nil || !dec.Allowed {
			t.Fatalf("tenant b after tenant a drained = %+v, %v; want admitted", dec, err)
		}
	})
}

// Acceptance 6 (part): the table is created by the migration and the runtime role cannot be refused its
// own bucket through RLS. The registry and domain-keys checks run in fitness-tenancy / fitness-domain-keys.
func TestBucketRowIsWrittenByTheRuntimeRole(t *testing.T) {
	eachDB(t, func(t *testing.T, d *storetest.Database) {
		s := node(t, d)
		if _, err := s.Take(context.Background(), "k", Limit{Rate: 60, Burst: 2}); err != nil {
			t.Fatal(err)
		}
		got, err := d.OwnerStrings(context.Background(), `SELECT count(*)::text FROM public.platform_rate_buckets`)
		if err != nil || len(got) != 1 || got[0] != "1" {
			t.Fatalf("rows = %v, %v; want 1", got, err)
		}
	})
}

func TestPGStoreRefusesInvalidLimit(t *testing.T) {
	s := &PGStore{}
	for _, l := range []Limit{{Rate: 0, Burst: 1}, {Rate: 1, Burst: 0}, {Rate: -1, Burst: 5}} {
		if _, err := s.Take(context.Background(), "k", l); err == nil {
			t.Errorf("limit %+v accepted", l)
		}
	}
}

type errStore struct{}

func (errStore) Take(context.Context, string, Limit) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, errors.New("boom") // even a store that says Allowed with an error
}

// Acceptance 2, without a database: an error is never an admission, whatever the Decision says.
func TestAllowPrincipalErrorIsNeverAdmission(t *testing.T) {
	l := limiterOn(t, errStore{})
	dec, err := l.AllowPrincipal(context.Background(), "reveal", apihost.Principal{ID: "h"})
	if err == nil || dec.Allowed {
		t.Fatalf("= %+v, %v; want error and zero Decision", dec, err)
	}
}

// Acceptance 3 (limiter half): more than one node needs a shared store.
func TestRequireShared(t *testing.T) {
	mem := NewMemoryStore(nil)
	if err := RequireShared(mem, 1); err != nil {
		t.Errorf("memory with one node: %v", err)
	}
	if err := RequireShared(mem, 2); !errors.Is(err, ErrUnsharedStore) {
		t.Errorf("memory with two nodes = %v, want ErrUnsharedStore", err)
	}
	if err := RequireShared(&PGStore{}, 3); err != nil {
		t.Errorf("postgres with three nodes: %v", err)
	}
	if err := RequireShared(mem, 0); err == nil {
		t.Error("zero nodes accepted")
	}
	if err := RequireShared(nil, 1); err == nil {
		t.Error("nil store accepted")
	}
}

func TestPrincipalKeyIsUnambiguous(t *testing.T) {
	a := principalKey("reveal", apihost.Principal{ID: "bc", Tenant: "a"})
	b := principalKey("reveal", apihost.Principal{ID: "c", Tenant: "ab"})
	if a == b {
		t.Fatal("tenant/ID boundary is ambiguous")
	}
	if principalKey("reveal", apihost.Principal{ID: "x", Tenant: "t"}) == principalKey("secret", apihost.Principal{ID: "x", Tenant: "t"}) {
		t.Fatal("classes share a key")
	}
}
