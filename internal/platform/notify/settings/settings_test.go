package settings

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/notify/mailaddr"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

func relay() *Relay {
	return &Relay{Host: "Smtp.OK.example", Security: StartTLS, From: "NoReply@ok.example"}
}

func TestNormalizeDomains(t *testing.T) {
	got, err := Update{AllowedDomains: []string{"B.example", "a.example", "A.EXAMPLE", "bücher.example"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example", "b.example", "xn--bcher-kva.example"}
	if !slices.Equal(got.AllowedDomains, want) {
		t.Fatalf("got %v, want %v", got.AllowedDomains, want)
	}
	if got.Relay != nil {
		t.Fatal("relay invented")
	}
	// An empty list is valid and stays empty (not nil).
	e, err := Update{}.Normalize()
	if err != nil || e.AllowedDomains == nil || len(e.AllowedDomains) != 0 {
		t.Fatalf("empty: %v %v", e, err)
	}
}

func TestNormalizeRefusesNonDomains(t *testing.T) {
	for _, d := range []string{"*.ok.example", ".ok.example", "ok.example.", "a@ok.example", "[10.0.0.1]", "10.0.0.1", "", " ok.example", "ok .example", "ok.example/x", "ok.example:25"} {
		if _, err := (Update{AllowedDomains: []string{d}}).Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted: %v", d, err)
		}
	}
}

func TestNormalizeCapsList(t *testing.T) {
	var ds []string
	for i := 0; i < MaxAllowedDomains; i++ {
		ds = append(ds, "d"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26))+".example")
	}
	if _, err := (Update{AllowedDomains: ds}).Normalize(); err != nil {
		t.Fatalf("%d domains: %v", len(ds), err)
	}
	ds = append(ds, "one-more.example")
	if _, err := (Update{AllowedDomains: ds}).Normalize(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over the cap: %v", err)
	}
}

func TestNormalizeRelay(t *testing.T) {
	n, err := Update{Relay: relay()}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if r := n.Relay; r.Host != "smtp.ok.example" || r.Port != 587 || r.From != "NoReply@ok.example" {
		t.Fatalf("relay %+v", r)
	}
	for sec, port := range map[Security]int{StartTLS: 587, ImplicitTLS: 465} {
		r := *relay()
		r.Security = sec
		n, err := Update{Relay: &r}.Normalize()
		if err != nil || n.Relay.Port != port {
			t.Errorf("%s: %+v %v", sec, n.Relay, err)
		}
	}
	plain := *relay()
	plain.Security, plain.PlaintextOptIn = Plaintext, true
	if n, err := (Update{Relay: &plain}).Normalize(); err != nil || n.Relay.Port != 25 {
		t.Errorf("plaintext with opt-in: %+v %v", n.Relay, err)
	}

	bad := map[string]func(r *Relay){
		"plaintext without opt-in": func(r *Relay) { r.Security = Plaintext },
		"opt-in with TLS":          func(r *Relay) { r.PlaintextOptIn = true },
		"unknown security":         func(r *Relay) { r.Security = "ssl" },
		"empty security":           func(r *Relay) { r.Security = "" },
		"empty host":               func(r *Relay) { r.Host = "" },
		"host with port":           func(r *Relay) { r.Host = "smtp.ok.example:25" },
		"host with path":           func(r *Relay) { r.Host = "smtp.ok.example/x" },
		"host with space":          func(r *Relay) { r.Host = "smtp ok.example" },
		"unicode host":             func(r *Relay) { r.Host = "smtp.bücher.example" },
		"zoned ip":                 func(r *Relay) { r.Host = "fe80::1%eth0" },
		"port high":                func(r *Relay) { r.Port = 70000 },
		"port negative":            func(r *Relay) { r.Port = -1 },
		"display-name sender":      func(r *Relay) { r.From = "Bob <b@ok.example>" },
		"empty sender":             func(r *Relay) { r.From = "" },
		"crlf sender":              func(r *Relay) { r.From = "b@ok.example\r\nBcc: x@evil.example" },
	}
	for name, mut := range bad {
		r := *relay()
		mut(&r)
		if _, err := (Update{Relay: &r}).Normalize(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := (Update{Relay: &Relay{Host: "10.0.0.5", Security: StartTLS, From: "n@ok.example"}}).Normalize(); err != nil {
		t.Errorf("ip host: %v", err)
	}
}

func TestClassify(t *testing.T) {
	var zero Settings
	a, c, err := zero.ClassifyString("ann@ok.example")
	if err != nil || c != External || a.String() != "ann@ok.example" {
		t.Fatalf("empty list: %v %v %v", a, c, err)
	}
	if zero.Classify(mailaddr.Address{}) != External {
		t.Fatal("zero address is not external")
	}

	n, err := Update{AllowedDomains: []string{"ok.example", "bücher.example"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	s := Settings{AllowedDomains: n.AllowedDomains}
	for raw, want := range map[string]Class{
		"ann@ok.example":                  Internal,
		"Ann@OK.Example":                  Internal,
		"ann@bücher.example":              Internal,
		"ann@xn--bcher-kva.example":       Internal,
		"ann@sub.ok.example":              External,
		"ann@ok.example.evil.example":     External,
		"ann@evilok.example":              External,
		"ann@ok.example.":                 External, // refused by the parser; never internal
		"ann@bucher.example":              External,
		"ann@bücher.example.evil.example": External,
		"ann@оk.example":                  External, // Cyrillic о: a lookalike
	} {
		_, c, _ := s.ClassifyString(raw)
		if c != want {
			t.Errorf("%s: %v, want %v", raw, c, want)
		}
	}
	for _, raw := range []string{"Bob <ann@ok.example>", "\"a b\"@ok.example", "ann@[10.0.0.1]", "a@b@ok.example", "ann@ok.example\r\nBcc: x@evil.example"} {
		if _, c, err := s.ClassifyString(raw); err == nil || c != External {
			t.Errorf("%q: %v %v", raw, c, err)
		}
	}
}

// noTenantTx runs fn in a transaction with no tenant context. It is the one WithPlatform site of this test
// file (registered in the exemption registry), so the test can show that Get refuses to run without a tenant.
func noTenantTx(ctx context.Context, db *store.DB, fn func(ctx context.Context, tx store.Tx) error) error {
	return db.WithPlatform(ctx, "settings test: no tenant context", fn)
}

func seedTenant(t *testing.T, s *storetest.Server) (*store.DB, tenant.ID) {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db, tid
}

func TestGetDefaultAndNoTenant(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		db, tid := seedTenant(t, s)
		ctx := context.Background()
		if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			got, err := Store{}.Get(ctx, tx)
			if err != nil {
				return err
			}
			if got.Version != 0 || got.Relay != nil || got.AllowedDomains == nil || len(got.AllowedDomains) != 0 {
				t.Errorf("default %+v", got)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := noTenantTx(ctx, db, func(ctx context.Context, tx store.Tx) error {
			if _, err := (Store{}).Get(ctx, tx); !errors.Is(err, ErrNoTenant) {
				t.Errorf("no tenant: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

// Writes are optimistic: the version the plan read must still be current, the row is created at version 1,
// and the relay round-trips.
func TestSetVersioned(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		db, tid := seedTenant(t, s)
		ctx := context.Background()
		run := func(f func(ctx context.Context, tx store.Tx)) {
			t.Helper()
			if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error { f(ctx, tx); return nil }); err != nil {
				t.Fatal(err)
			}
		}
		st := Store{}
		run(func(ctx context.Context, tx store.Tx) {
			if _, err := st.set(ctx, tx, Update{AllowedDomains: []string{"a.example"}}, 3); !errors.Is(err, ErrStale) {
				t.Errorf("insert at wrong version: %v", err)
			}
		})
		run(func(ctx context.Context, tx store.Tx) {
			got, err := st.set(ctx, tx, Update{AllowedDomains: []string{"B.example", "a.example"}, Relay: relay()}, 0)
			if err != nil || got.Version != 1 || got.Relay == nil || got.Relay.Host != "smtp.ok.example" || got.Relay.Port != 587 ||
				!slices.Equal(got.AllowedDomains, []string{"a.example", "b.example"}) {
				t.Errorf("first write %+v %v", got, err)
			}
		})
		run(func(ctx context.Context, tx store.Tx) {
			if _, err := st.set(ctx, tx, Update{}, 0); !errors.Is(err, ErrStale) {
				t.Errorf("stale update: %v", err)
			}
			got, err := st.Get(ctx, tx)
			if err != nil || got.Version != 1 || len(got.AllowedDomains) != 2 {
				t.Errorf("stale write changed the row: %+v %v", got, err)
			}
		})
		run(func(ctx context.Context, tx store.Tx) {
			got, err := st.set(ctx, tx, Update{}, 1)
			if err != nil || got.Version != 2 || got.Relay != nil || len(got.AllowedDomains) != 0 {
				t.Errorf("clear %+v %v", got, err)
			}
		})
		run(func(ctx context.Context, tx store.Tx) {
			if _, err := st.set(ctx, tx, Update{Relay: &Relay{Host: "x", Security: Plaintext, From: "n@ok.example"}}, 2); !errors.Is(err, ErrInvalid) {
				t.Errorf("invalid update: %v", err)
			}
		})
	})
}
