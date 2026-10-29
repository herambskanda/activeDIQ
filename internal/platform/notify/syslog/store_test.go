package syslog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/keys"
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
		if len(snk.evs) != 1 || snk.evs[0].Kind != KindDestinationCreated {
			t.Fatalf("a TLS create appends exactly one created event, no opt-in: %v", snk.evs)
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
		if len(snk.evs) != 2 || snk.evs[1].Kind != KindPlaintextOptIn || snk.evs[1].Target.GUID != v.ID || snk.evs[1].Actor.Requester.ID != "u1" {
			t.Fatalf("events = %+v", snk.evs)
		}
		snk.evs = nil
		// Updating TLS -> plaintext appends again; plaintext -> TLS does not.
		tv, _ := s.Create(ctx, ten, Spec{Host: "a.example.com"}, human, "r2")
		if _, err := s.Update(ctx, ten, tv.ID, Spec{Host: "a.example.com", Transport: TCP, PlaintextOptIn: true}, human, "r3"); err != nil {
			t.Fatal(err)
		}
		if n := count(snk.evs, KindPlaintextOptIn); n != 1 {
			t.Fatalf("opt-in events after update = %d", n)
		}
		if _, err := s.Update(ctx, ten, tv.ID, Spec{Host: "a.example.com"}, human, "r4"); err != nil {
			t.Fatal(err)
		}
		if n := count(snk.evs, KindPlaintextOptIn); n != 1 {
			t.Fatalf("opt-in events after back to TLS = %d", n)
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

func count(evs []audit.Event, k audit.Kind) (n int) {
	for _, e := range evs {
		if e.Kind == k {
			n++
		}
	}
	return n
}

// A TLS host change is recorded with the old and new target, and a failing sink rolls it back.
func TestTLSHostChangeIsAudited(t *testing.T) {
	each(t, func(t *testing.T, s *Store, ten tenant.ID, snk *sink, _ *store.DB) {
		ctx := context.Background()
		v, _ := s.Create(ctx, ten, Spec{Host: "siem.corp.example"}, human, "r1")
		if _, err := s.Update(ctx, ten, v.ID, Spec{Host: "attacker.example.net"}, human, "r2"); err != nil {
			t.Fatal(err)
		}
		if len(snk.evs) != 2 || snk.evs[1].Kind != KindDestinationUpdated {
			t.Fatalf("events = %+v", snk.evs)
		}
		got := map[string]string{}
		for _, d := range snk.evs[1].Details {
			got[d.Key] = d.Value
		}
		if got["previous_host"] != "siem.corp.example" || got["host"] != "attacker.example.net" || got["previous_transport"] != "tls" {
			t.Fatalf("details = %v", got)
		}
		snk.fail = true
		if _, err := s.Update(ctx, ten, v.ID, Spec{Host: "other.example.net"}, human, "r3"); err == nil {
			t.Fatal("update succeeded with the audit sink down")
		}
		if cur, _ := s.Get(ctx, ten, v.ID); cur.Host != "attacker.example.net" {
			t.Fatalf("host after failed update = %s", cur.Host)
		}
		if _, err := s.Create(ctx, ten, Spec{Host: "n.example.com"}, human, "r4"); err == nil {
			t.Fatal("TLS create succeeded with the audit sink down")
		}
		if l, _ := s.List(ctx, ten); len(l) != 1 {
			t.Fatalf("list = %d", len(l))
		}
	})
}

// With the real chain: envelope checks pass and the rows carry kind and target.
func TestRealChainerRecordsEvents(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		d := srv.NewDatabase(t)
		d.Migrate(t)
		ctx := context.Background()
		ten := tenanttest.Seed(t, d.ExecOwner, "t1")
		db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ch := audit.NewChainer(db)
		cp := audit.NewCheckpointer(ch, fixedKeys{}, noAnchor{})
		if err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, ten) }); err != nil {
			t.Fatal(err)
		}
		s, _ := NewStore(db, ch)
		v, err := s.Create(ctx, ten, Spec{Host: "10.0.0.5", Transport: TCP, PlaintextOptIn: true}, human, "req-1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Update(ctx, ten, v.ID, Spec{Host: "siem.example.com"}, human, "req-2"); err != nil {
			t.Fatal(err)
		}
		var kinds []string
		err = db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.Query(ctx, `SELECT kind FROM public.audit_event WHERE tenant_id = $1 AND event_id LIKE $2 ORDER BY seq`, ten.String(), "siem.destination."+v.ID+".%")
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var k string
				if err := rows.Scan(&k); err != nil {
					return err
				}
				kinds = append(kinds, k)
			}
			return rows.Err()
		})
		want := []string{"siem.destination.created", "siem.destination.plaintext_opt_in", "siem.destination.updated"}
		if err != nil || fmt.Sprint(kinds) != fmt.Sprint(want) {
			t.Fatalf("kinds = %v, %v; want %v", kinds, err, want)
		}
	})
}

type fixedKeys struct{}

func (fixedKeys) DEK(context.Context, store.Tx, tenant.ID, uint32) (keys.DEK, error) {
	return keys.DEKFromBytes(1, bytes.Repeat([]byte{9}, keys.DEKSize))
}

type noAnchor struct{}

func (noAnchor) Anchor(context.Context, chain.Checkpoint) error { return nil }

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
		for _, bad := range []string{"", "has space", "caf\u00e9", string(make([]byte, 129))} {
			if _, err := s.Create(ctx, ten, Spec{Host: "h.example.com"}, human, bad); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("request id %q: %v", bad, err)
			}
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

// A replayed update must not re-point the destination without a new audit event (security review of
// T-0423): with the real chain, K1 (A->X), K2 (X->A), replay K1 is refused and every row change has its
// own audit event.
func TestReplayedUpdateCannotChangeRowWithoutAuditEvent(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		d := srv.NewDatabase(t)
		d.Migrate(t)
		ctx := context.Background()
		ten := tenanttest.Seed(t, d.ExecOwner, "t1")
		db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ch := audit.NewChainer(db)
		cp := audit.NewCheckpointer(ch, fixedKeys{}, noAnchor{})
		if err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, ten) }); err != nil {
			t.Fatal(err)
		}
		s, _ := NewStore(db, ch)
		a := Spec{Host: "siem.example.com"}
		x := Spec{Host: "attacker.example.com"}
		v, err := s.Create(ctx, ten, a, human, "req-create")
		if err != nil {
			t.Fatal(err)
		}
		events := func() (n int) {
			if err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE tenant_id = $1`, ten.String()).Scan(&n)
			}); err != nil {
				t.Fatal(err)
			}
			return n
		}
		if _, err := s.Update(ctx, ten, v.ID, x, human, "K1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Update(ctx, ten, v.ID, a, human, "K2"); err != nil {
			t.Fatal(err)
		}
		before := events()
		if _, err := s.Update(ctx, ten, v.ID, x, human, "K1"); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("replay of K1 with the old body: err = %v; want ErrIdempotencyConflict", err)
		}
		// K2 reused with another body is a conflict, not an internal error.
		if _, err := s.Update(ctx, ten, v.ID, Spec{Host: "other.example.com"}, human, "K2"); !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("K2 with another body: err = %v; want ErrIdempotencyConflict", err)
		}
		// Replaying K2 with its own body is a no-op that returns the current row.
		got, err := s.Update(ctx, ten, v.ID, a, human, "K2")
		if err != nil || got.Host != "siem.example.com" {
			t.Fatalf("replay of K2: %+v, %v", got, err)
		}
		if cur, _ := s.Get(ctx, ten, v.ID); cur.Host != "siem.example.com" {
			t.Fatalf("host = %q; the replay changed the destination", cur.Host)
		}
		if after := events(); after != before {
			t.Fatalf("audit events %d -> %d; refused replays must write nothing", before, after)
		}
	})
}
