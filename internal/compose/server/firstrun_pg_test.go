package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	setupsecret "github.com/skenzeriq/activediq/internal/platform/setup"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

type recSink struct {
	mu   sync.Mutex
	evs  []audit.Event
	fail error
}

func (r *recSink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.evs = append(r.evs, ev)
	return nil
}

func firstOwnerEnv(t *testing.T, s *storetest.Server, sink audit.Sink) (*firstOwners, *store.DB, string) {
	t.Helper()
	ctx := context.Background()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ten := tenanttest.Seed(t, d.ExecOwner, "A")
	if err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error { return rbac.SeedBuiltIns(ctx, tx, ten) }); err != nil {
		t.Fatal(err)
	}
	console, err := buildConsole(db, nopSink{}, testKeys(), nil)
	if err != nil {
		t.Fatal(err)
	}
	oa, err := buildOwnerAssignments(db, nopSink{}, console.Sessions)
	if err != nil {
		t.Fatal(err)
	}
	f, err := newFirstOwners(db, sink, oa)
	if err != nil {
		t.Fatal(err)
	}
	f.SetTenant(ten)
	return f, db, ten.String()
}

// T-0707 AC1/AC2/AC3: the owner, its grant and both audit events commit together; a second creation is
// refused; the events carry the source address and install id and nothing secret.
func TestFirstOwnerCreatedOnceAndAudited(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		sink := &recSink{}
		f, db, install := firstOwnerEnv(t, s, sink)
		ctx := context.Background()
		d := setupsecret.OwnerDetails{DisplayName: "First Owner", Email: "owner@example.com"}
		if err := f.CreateFirstOwner(ctx, d, "203.0.113.9"); err != nil {
			t.Fatal(err)
		}
		if err := f.CreateFirstOwner(ctx, d, "203.0.113.10"); !errors.Is(err, setupsecret.ErrOwnerExists) {
			t.Fatalf("second creation = %v", err)
		}
		var kinds []audit.Kind
		for _, ev := range sink.evs {
			kinds = append(kinds, ev.Kind)
			if ev.Kind != KindSetupClaimed && ev.Kind != KindSetupOwnerCreated {
				continue
			}
			got := map[string]string{}
			for _, dt := range ev.Details {
				got[dt.Key] = dt.Value
			}
			if got["source_ip"] != "203.0.113.9" || got["install_id"] != install || ev.At.IsZero() {
				t.Errorf("%s details = %v", ev.Kind, got)
			}
		}
		want := []audit.Kind{KindSetupClaimed, KindSetupOwnerCreated}
		if len(kinds) != len(want) {
			t.Fatalf("audit kinds = %v, want %v", kinds, want)
		}
		for i := range want {
			if kinds[i] != want[i] {
				t.Fatalf("audit kinds = %v, want %v", kinds, want)
			}
		}
		var owners []string
		if err := db.WithTenant(ctx, *f.tenant.Load(), func(ctx context.Context, tx store.Tx) (err error) {
			owners, err = rbac.Owners{}.TenantOwners(ctx, tx, *f.tenant.Load())
			return
		}); err != nil || len(owners) != 1 {
			t.Fatalf("owners = %v, %v", owners, err)
		}
	})
}

// A failure after the account insert (here the audit write) leaves no account and no owner, so the
// claimant can retry with the same secret.
func TestFirstOwnerRollsBackOnAuditFailure(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		sink := &recSink{fail: errors.New("chain unavailable")}
		f, db, _ := firstOwnerEnv(t, s, sink)
		ctx := context.Background()
		d := setupsecret.OwnerDetails{DisplayName: "First Owner", Email: "owner@example.com"}
		if err := f.CreateFirstOwner(ctx, d, "203.0.113.9"); err == nil {
			t.Fatal("creation succeeded with a failing audit sink")
		}
		sink.fail = nil
		if err := f.CreateFirstOwner(ctx, d, "203.0.113.9"); err != nil {
			t.Fatalf("retry after rollback: %v", err)
		}
		var n int
		if err := db.WithTenant(ctx, *f.tenant.Load(), func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_accounts`).Scan(&n)
		}); err != nil || n != 1 {
			t.Fatalf("accounts = %d, %v (want exactly the retried one)", n, err)
		}
	})
}

// Concurrent creations: exactly one wins.
func TestFirstOwnerConcurrentOneWinner(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		f, _, _ := firstOwnerEnv(t, s, &recSink{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if f.CreateFirstOwner(context.Background(), setupsecret.OwnerDetails{DisplayName: "O", Email: "o@example.com"}, "203.0.113.9") == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d creations succeeded, want 1", wins)
		}
	})
}

var _ = authn.KindLocal
