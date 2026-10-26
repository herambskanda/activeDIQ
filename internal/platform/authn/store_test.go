package authn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

// fakeClock is shared by every node of a test, so time moves for all of them at once.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type sessEnv struct {
	d   *storetest.Database
	ten tenant.ID
	clk *fakeClock
}

func (e *sessEnv) node(t *testing.T, p Policy) *Store {
	t.Helper()
	db, err := store.Open(context.Background(), store.Config{DSN: e.d.AppDSN()})
	if err != nil {
		t.Fatalf("store.Open as the runtime role: %v", err)
	}
	t.Cleanup(db.Close)
	s, err := New(Config{DB: db, Policies: StaticPolicy(p), Clock: e.clk.now, TouchEvery: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func each(t *testing.T, fn func(t *testing.T, e *sessEnv)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		fn(t, &sessEnv{d: d, ten: tenanttest.Seed(t, d.ExecOwner, "t1"), clk: &fakeClock{t: time.Now().UTC().Truncate(time.Millisecond)}})
	})
}

var pol = Policy{Idle: 10 * time.Minute, Absolute: time.Hour, MaxConcurrent: 3, Eviction: EvictOldestCreated}

func create(t *testing.T, s *Store, ten tenant.ID, acct string) CreateResult {
	t.Helper()
	r, err := s.Create(context.Background(), CreateInput{Tenant: ten, Account: acct, Methods: []string{"password"}, ClientIP: netip.MustParseAddr("192.0.2.9")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return r
}

func TestSessionIDStoredHashed(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		s := e.node(t, pol)
		acct := tenant.New().String()
		r := create(t, s, e.ten, acct)
		plain := r.Token.Reveal()
		if _, err := ParseToken(plain); err != nil {
			t.Fatalf("the returned token does not parse: %v", err)
		}
		c, err := e.d.Admin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(context.Background())
		var stored []byte
		if err := c.QueryRow(context.Background(), `SELECT id_hash FROM public.authn_sessions WHERE id = $1::uuid`, r.Session.ID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(plain))
		if !bytes.Equal(stored, sum[:]) {
			t.Fatal("the stored value is not the SHA-256 of the token")
		}
		// No column of the row holds the token or its secret half.
		var leaked bool
		secret := plain[37:]
		if err := c.QueryRow(context.Background(), `SELECT strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0 FROM public.authn_sessions t WHERE id = $3::uuid`, plain, secret, r.Session.ID).Scan(&leaked); err != nil {
			t.Fatal(err)
		}
		if leaked {
			t.Fatal("the plain session ID appears in the table")
		}
		if strings.Contains(r.Token.String(), secret) {
			t.Fatal("Token.String leaks the secret")
		}
		got, err := s.Lookup(context.Background(), r.Token)
		if err != nil || got.ID != r.Session.ID || got.Account != acct {
			t.Fatalf("Lookup = %+v, %v", got, err)
		}
	})
}

func TestSessionExpiry(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		s := e.node(t, pol)
		acct := tenant.New().String()
		state := func(id string) (st, reason string) {
			c, err := e.d.Admin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close(context.Background())
			if err := c.QueryRow(context.Background(), `SELECT state, end_reason FROM public.authn_sessions WHERE id = $1::uuid`, id).Scan(&st, &reason); err != nil {
				t.Fatal(err)
			}
			return
		}

		// Idle: refused after the idle window, marked expired.
		a := create(t, s, e.ten, acct)
		e.clk.advance(pol.Idle + time.Second)
		if _, err := s.Lookup(context.Background(), a.Token); !errors.Is(err, ErrExpired) {
			t.Fatalf("idle lookup = %v, want ErrExpired", err)
		}
		if st, why := state(a.Session.ID); st != "expired" || why != "idle_timeout" {
			t.Fatalf("state = %s/%s, want expired/idle_timeout", st, why)
		}
		if _, err := s.Lookup(context.Background(), a.Token); !errors.Is(err, ErrExpired) {
			t.Fatalf("second lookup = %v, want ErrExpired", err)
		}

		// Activity slides the idle expiry but never past the absolute one.
		b := create(t, s, e.ten, acct)
		for i := 0; i < 5; i++ {
			e.clk.advance(pol.Idle - time.Minute)
			got, err := s.Lookup(context.Background(), b.Token)
			if err != nil {
				t.Fatalf("lookup %d: %v", i, err)
			}
			if got.IdleExpiry.After(got.AbsoluteExpiry) {
				t.Fatal("idle expiry slid past the absolute expiry")
			}
		}
		e.clk.advance(pol.Idle - time.Minute) // 6 x 9m = 54m, still inside the hour
		e.clk.advance(10 * time.Minute)
		if _, err := s.Lookup(context.Background(), b.Token); !errors.Is(err, ErrExpired) {
			t.Fatalf("absolute lookup = %v, want ErrExpired", err)
		}
		if st, why := state(b.Session.ID); st != "expired" || why != "absolute_timeout" {
			t.Fatalf("state = %s/%s, want expired/absolute_timeout", st, why)
		}

		// A policy tightened below the session's age ends it on the next lookup.
		c := create(t, s, e.ten, acct)
		e.clk.advance(2 * time.Minute)
		tight := e.node(t, Policy{Idle: 5 * time.Minute, Absolute: 15 * time.Minute, MaxConcurrent: 3, Eviction: EvictOldestCreated})
		e.clk.advance(4 * time.Minute) // 6 minutes since last seen: within old idle (10m), past new (5m)
		if _, err := tight.Lookup(context.Background(), c.Token); !errors.Is(err, ErrExpired) {
			t.Fatalf("tightened lookup = %v, want ErrExpired", err)
		}
	})
}

func TestSessionConcurrentLimit(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		for _, ev := range []EvictionPolicy{EvictOldestCreated, EvictLeastRecentlyUsed} {
			p := pol
			p.Eviction = ev
			s := e.node(t, p)
			acct := tenant.New().String()
			var rs []CreateResult
			for i := 0; i < 3; i++ {
				e.clk.advance(time.Second)
				rs = append(rs, create(t, s, e.ten, acct))
			}
			if ev == EvictLeastRecentlyUsed { // the oldest-created is the most recently used
				e.clk.advance(2 * time.Second)
				if _, err := s.Lookup(context.Background(), rs[0].Token); err != nil {
					t.Fatal(err)
				}
			}
			e.clk.advance(time.Second)
			n := create(t, s, e.ten, acct)
			if n.Evicted != 1 {
				t.Fatalf("%s: evicted %d, want 1", ev, n.Evicted)
			}
			victim := 0
			if ev == EvictLeastRecentlyUsed {
				victim = 1
			}
			for i, r := range rs {
				_, err := s.Lookup(context.Background(), r.Token)
				if i == victim && !errors.Is(err, ErrRevoked) {
					t.Fatalf("%s: session %d = %v, want ErrRevoked", ev, i, err)
				}
				if i != victim && err != nil {
					t.Fatalf("%s: session %d = %v, want alive", ev, i, err)
				}
			}
			if _, err := s.Lookup(context.Background(), n.Token); err != nil {
				t.Fatalf("%s: new session: %v", ev, err)
			}
		}
	})
}

func TestConcurrentLimitHoldsUnderRace(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		a, b := e.node(t, pol), e.node(t, pol)
		acct := tenant.New().String()
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				s := a
				if i%2 == 1 {
					s = b
				}
				if _, err := s.Create(context.Background(), CreateInput{Tenant: e.ten, Account: acct, Methods: []string{"password"}}); err != nil {
					t.Error(err)
				}
			}(i)
		}
		wg.Wait()
		live, err := a.ListActive(context.Background(), e.ten, acct)
		if err != nil || len(live) != pol.MaxConcurrent {
			t.Fatalf("live sessions = %d (%v), want %d", len(live), err, pol.MaxConcurrent)
		}
	})
}

func TestSessionRevocationOnEvents(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		nodeA, nodeB := e.node(t, pol), e.node(t, pol)
		for _, why := range []Reason{ReasonAccountDisabled, ReasonRoleChanged, ReasonPasswordReset, ReasonMFAReset, ReasonOnDemand} {
			acct, other := tenant.New().String(), tenant.New().String()
			mine := []CreateResult{create(t, nodeA, e.ten, acct), create(t, nodeB, e.ten, acct)}
			bystander := create(t, nodeA, e.ten, other)
			for _, r := range mine {
				if _, err := nodeB.Lookup(context.Background(), r.Token); err != nil {
					t.Fatal(err)
				}
			}
			n, err := nodeA.RevokeAccount(context.Background(), e.ten, acct, why)
			if err != nil || n != 2 {
				t.Fatalf("%s: RevokeAccount = %d, %v; want 2", why, n, err)
			}
			for _, r := range mine { // every node refuses at once
				for _, s := range []*Store{nodeA, nodeB} {
					if _, err := s.Lookup(context.Background(), r.Token); !errors.Is(err, ErrRevoked) {
						t.Fatalf("%s: lookup after revoke = %v, want ErrRevoked", why, err)
					}
				}
			}
			if _, err := nodeB.Lookup(context.Background(), bystander.Token); err != nil {
				t.Fatalf("%s: another account's session was revoked: %v", why, err)
			}
			if n, _ := nodeA.RevokeAccount(context.Background(), e.ten, acct, why); n != 0 {
				t.Fatalf("%s: second revoke ended %d", why, n)
			}
		}
		// On demand, one session by handle; and logout.
		acct := tenant.New().String()
		x, y := create(t, nodeA, e.ten, acct), create(t, nodeA, e.ten, acct)
		if ok, err := nodeB.Revoke(context.Background(), e.ten, x.Session.ID, ReasonOnDemand); err != nil || !ok {
			t.Fatalf("Revoke = %v, %v", ok, err)
		}
		if _, err := nodeA.Lookup(context.Background(), x.Token); !errors.Is(err, ErrRevoked) {
			t.Fatalf("revoked-by-handle lookup = %v", err)
		}
		if err := nodeA.Logout(context.Background(), y.Token); err != nil {
			t.Fatal(err)
		}
		if _, err := nodeB.Lookup(context.Background(), y.Token); !errors.Is(err, ErrRevoked) {
			t.Fatalf("logged-out lookup = %v", err)
		}
		if _, err := nodeA.RevokeAccount(context.Background(), e.ten, acct, Reason("because")); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unknown reason = %v, want ErrInvalid", err)
		}
	})
}

func TestTenantIsolationAndForgedTokens(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		s := e.node(t, pol)
		other := tenanttest.Seed(t, e.d.ExecOwner, "t2")
		acct := tenant.New().String()
		r := create(t, s, e.ten, acct)
		// The same secret presented under another tenant's prefix finds nothing.
		forged, err := ParseToken(other.String() + r.Token.Reveal()[36:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Lookup(context.Background(), forged); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("cross-tenant lookup = %v, want ErrSessionNotFound", err)
		}
		if n, err := s.RevokeAccount(context.Background(), other, acct, ReasonOnDemand); err != nil || n != 0 {
			t.Fatalf("cross-tenant revoke = %d, %v", n, err)
		}
		for _, bad := range []string{"", "x", strings.Repeat("a", 80), r.Token.Reveal() + "A", r.Token.Reveal()[:79]} {
			if _, err := ParseToken(bad); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("ParseToken(%q) = %v", bad, err)
			}
		}
		unknown, _ := newToken(e.ten)
		if _, err := s.Lookup(context.Background(), unknown); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("unknown token = %v", err)
		}
	})
}

func TestEndedSessionsAreFinalAndNotDeletable(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		s := e.node(t, pol)
		r := create(t, s, e.ten, tenant.New().String())
		if _, err := s.Revoke(context.Background(), e.ten, r.Session.ID, ReasonOnDemand); err != nil {
			t.Fatal(err)
		}
		err := s.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM public.authn_sessions`)
			return err
		})
		if err == nil {
			t.Fatal("the runtime role can delete sessions")
		}
	})
}

func TestPolicyOutsideBoundsIsRefused(t *testing.T) {
	for _, p := range []Policy{
		{Idle: time.Second, Absolute: time.Hour, MaxConcurrent: 1, Eviction: EvictOldestCreated},
		{Idle: time.Minute * 10, Absolute: 48 * time.Hour, MaxConcurrent: 1, Eviction: EvictOldestCreated},
		{Idle: time.Hour, Absolute: 30 * time.Minute, MaxConcurrent: 1, Eviction: EvictOldestCreated},
		{Idle: time.Hour, Absolute: 2 * time.Hour, MaxConcurrent: 0, Eviction: EvictOldestCreated},
		{Idle: time.Hour, Absolute: 2 * time.Hour, MaxConcurrent: 21, Eviction: EvictOldestCreated},
		{Idle: time.Hour, Absolute: 2 * time.Hour, MaxConcurrent: 1, Eviction: "newest"},
	} {
		if err := p.Validate(DefaultBounds); !errors.Is(err, ErrPolicy) {
			t.Errorf("%+v: %v, want ErrPolicy", p, err)
		}
	}
	if err := DefaultPolicy.Validate(DefaultBounds); err != nil {
		t.Fatalf("the default policy is outside the default bounds: %v", err)
	}
}
