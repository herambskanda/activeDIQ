package syslog

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type sink struct {
	mu   sync.Mutex
	evs  []audit.Event
	fail bool
}

func (r *sink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	if r.fail {
		return errors.New("sink down")
	}
	if err := ev.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

var human = authority.Chain{Requester: authority.Principal{ID: "u1", Kind: authority.Human}}

var other tenant.ID

func each(t *testing.T, fn func(t *testing.T, s *Store, ten tenant.ID, snk *sink, db *store.DB)) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		d := srv.NewDatabase(t)
		d.Migrate(t)
		ten := tenanttest.Seed(t, d.ExecOwner, "t1")
		other = tenanttest.Seed(t, d.ExecOwner, "t2")
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		snk := &sink{}
		s, err := NewStore(db, snk)
		if err != nil {
			t.Fatal(err)
		}
		fn(t, s, ten, snk, db)
	})
}

// Acceptance 1: no transport stored is TLS-verified and the View says so.
func TestCreateDefaultsToVerifiedTLS(t *testing.T) {
	each(t, func(t *testing.T, s *Store, ten tenant.ID, snk *sink, _ *store.DB) {
		v, err := s.Create(context.Background(), ten, Spec{Host: "siem.example.com"}, human, "r1")
		if err != nil {
			t.Fatal(err)
		}
		if v.Transport != "tls" || !v.TLSVerified || v.PlaintextOptIn || v.Port != 6514 || v.Warning != "" || v.ID == "" {
			t.Fatalf("view = %+v", v)
		}
		if len(snk.evs) != 0 {
			t.Fatalf("a TLS destination must not append an opt-in event: %v", snk.evs)
		}
		got, err := s.Get(context.Background(), ten, v.ID)
		if err != nil || got != v {
			t.Fatalf("get = %+v, %v", got, err)
		}
	})
}

// Acceptance 2: plaintext appends the OptInEvent in the storing transaction.
func TestPlaintextAppendsOptInEvent(t *testing.T) {
	each(t, func(t *testing.T, s *Store, ten tenant.ID, snk *sink, _ *store.DB) {
		ctx := context.Background()
		v, err := s.Create(ctx, ten, Spec{Host: "10.0.0.5", Transport: TCP, PlaintextOptIn: true}, human, "r1")
		if err != nil {
			t.Fatal(err)
		}
		if v.Transport != "tcp" || v.TLSVerified || !v.PlaintextOptIn || v.Warning == "" || v.Port != 514 {
			t.Fatalf("view = %+v", v)
		}
		if len(snk.evs) != 1 || snk.evs[0].Kind != KindPlaintextOptIn || snk.evs[0].Target.GUID != v.ID || snk.evs[0].Actor.Requester.ID != "u1" {
			t.Fatalf("events = %+v", snk.evs)
		}
		// Updating TLS -> plaintext appends again; plaintext -> TLS does not.
		tv, _ := s.Create(ctx, ten, Spec{Host: "a.example.com"}, human, "r2")
		if _, err := s.Update(ctx, ten, tv.ID, Spec{Host: "a.example.com", Transport: TCP, PlaintextOptIn: true}, human, "r3"); err != nil {
			t.Fatal(err)
		}
		if len(snk.evs) != 2 {
			t.Fatalf("events after update = %d", len(snk.evs))
		}
		if _, err := s.Update(ctx, ten, tv.ID, Spec{Host: "a.example.com"}, human, "r4"); err != nil {
			t.Fatal(err)
		}
		if len(snk.evs) != 2 {
			t.Fatalf("events after back to TLS = %d", len(snk.evs))
		}
	})
}

// The destination and its event commit together: a failing sink leaves no destination.
func TestAuditFailureRollsBackDestination(t *testing.T) {
	each(t, func(t *testing.T, s *Store, ten tenant.ID, snk *sink, _ *store.DB) {
		ctx := context.Background()
		snk.fail = true
		if _, err := s.Create(ctx, ten, Spec{Host: "10.0.0.5", Transport: TCP, PlaintextOptIn: true}, human, "r1"); err == nil {
			t.Fatal("create succeeded with the audit sink down")
		}
		l, err := s.List(ctx, ten)
		if err != nil || len(l) != 0 {
			t.Fatalf("list = %v, %v; want empty", l, err)
		}
	})
}

func TestRefusals(t *testing.T) {
	each(t, func(t *testing.T, s *Store, ten tenant.ID, snk *sink, db *store.DB) {
		ctx := context.Background()
		if _, err := s.Create(ctx, ten, Spec{Host: "h.example.com", Transport: TCP}, human, "r"); !errors.Is(err, ErrPlaintextNotOptedIn) {
			t.Fatalf("tcp without opt-in: %v", err)
		}
		if _, err := s.Create(ctx, ten, Spec{Host: "bad host"}, human, "r"); !errors.Is(err, ErrBadDestination) {
			t.Fatalf("bad host: %v", err)
		}
		if _, err := s.Create(ctx, ten, Spec{Host: "h.example.com"}, authority.Chain{}, "r"); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("no actor: %v", err)
		}
		if _, err := s.Update(ctx, ten, "00000000-0000-4000-8000-000000000001", Spec{Host: "h.example.com"}, human, "r"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("update missing: %v", err)
		}
		if _, err := s.Get(ctx, ten, "x"); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("get bad id: %v", err)
		}
		// The table states the rule too: plaintext without the opt-in flag is refused by the database.
		err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.notify_syslog_destinations (tenant_id, host, port, transport, plaintext_opt_in) VALUES ($1, 'h.example.com', 514, 'tcp', false)`, ten.String())
			return err
		})
		if store.SQLState(err) != "23514" {
			t.Fatalf("db accepted plaintext without opt-in: %v", err)
		}
	})
}

func TestTenantIsolation(t *testing.T) {
	each(t, func(t *testing.T, s *Store, ten tenant.ID, snk *sink, _ *store.DB) {
		ctx := context.Background()
		v, err := s.Create(ctx, ten, Spec{Host: "h.example.com"}, human, "r")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, other, v.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("other tenant get: %v", err)
		}
		if _, err := s.Update(ctx, other, v.ID, Spec{Host: "x.example.com"}, human, "r2"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("other tenant update: %v", err)
		}
		if l, _ := s.List(ctx, other); len(l) != 0 {
			t.Fatalf("other tenant list: %v", l)
		}
	})
}
