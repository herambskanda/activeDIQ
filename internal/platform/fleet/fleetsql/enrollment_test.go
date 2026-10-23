package fleetsql_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type fakeAuthz struct{ allow bool }

func (f fakeAuthz) Allow(_ context.Context, _ apihost.Principal, perm, scope string) (bool, error) {
	return f.allow && perm == fleetsql.PermissionIssue && scope == "tenant", nil
}

type fakeStepUp struct{ fresh bool }

func (f fakeStepUp) Fresh(context.Context, apihost.Principal) (bool, error) { return f.fresh, nil }

type env struct {
	db   *store.DB
	d    *storetest.Database
	a, b tenant.ID
}

func (e *env) svc(allow, fresh bool, lim fleetsql.FailureLimiter) *fleetsql.Enrollment {
	if lim == nil {
		lim = fleetsql.NewMemoryLimiter(fleetsql.MemoryLimiterConfig{})
	}
	return &fleetsql.Enrollment{DB: e.db, Authz: fakeAuthz{allow}, StepUp: fakeStepUp{fresh}, Limiter: lim}
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	a := tenanttest.Seed(t, d.ExecOwner, "A")
	b := tenanttest.Seed(t, d.ExecOwner, "B")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return &env{db: db, d: d, a: a, b: b}
}

var admin = apihost.Principal{ID: "human-1", Kind: apihost.KindSession}

func (e *env) raw(tid tenant.ID, sql string, args ...any) (int64, error) {
	var n int64
	err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

func TestIssue(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()

		// AC1: refused without the permission, refused without step-up; nothing is written.
		if _, err := e.svc(false, true, nil).Issue(ctx, e.a, admin, fleetsql.NewComponent{Kind: fleetsql.KindConnector, Name: "c"}); !errors.Is(err, fleetsql.ErrForbidden) {
			t.Fatalf("no permission: %v", err)
		}
		if _, err := e.svc(true, false, nil).Issue(ctx, e.a, admin, fleetsql.NewComponent{Kind: fleetsql.KindConnector, Name: "c"}); !errors.Is(err, fleetsql.ErrStepUpRequired) {
			t.Fatalf("no step-up: %v", err)
		}
		var cnt int
		_ = e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.components`).Scan(&cnt)
		})
		if cnt != 0 {
			t.Fatalf("a refused issue wrote %d components", cnt)
		}

		for _, bad := range []fleetsql.NewComponent{
			{Kind: "x", Name: "c"}, {Kind: fleetsql.KindAgent, Name: " "}, {Kind: fleetsql.KindAgent, Name: "a", TTL: 48 * time.Hour},
			{Kind: fleetsql.KindAgent, Name: "a", TTL: time.Second}, {Kind: fleetsql.KindAgent, Name: "a\nb"},
		} {
			if _, err := e.svc(true, true, nil).Issue(ctx, e.a, admin, bad); !errors.Is(err, fleetsql.ErrInvalid) {
				t.Fatalf("%+v: %v", bad, err)
			}
		}

		iss, err := e.svc(true, true, nil).Issue(ctx, e.a, admin, fleetsql.NewComponent{Kind: fleetsql.KindConnector, Name: "branch-1"})
		if err != nil {
			t.Fatal(err)
		}
		plain := iss.Token.String()
		if plain == "" || strings.Contains(fmt.Sprintf("%v %+v %s %#v", iss.Token, iss.Token, iss.Token, iss.Token), plain) {
			t.Fatal("token empty or leaks through fmt")
		}
		if d := time.Until(iss.ExpiresAt); d <= 0 || d > fleetsql.DefaultTTL {
			t.Fatalf("expires_at %v is not within the default ttl", iss.ExpiresAt)
		}
		// Only the hash is stored: the plaintext (or its secret half) is nowhere in the row.
		var hashLen int
		var issuer string
		var plainInRow bool
		_ = e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT octet_length(token_hash), issued_by,
				position(convert_to($1, 'UTF8') IN token_hash) > 0 OR t::text LIKE '%' || $1 || '%'
				FROM public.enrollment_tokens t WHERE id = $2::uuid`, plain, iss.TokenID).Scan(&hashLen, &issuer, &plainInRow)
		})
		if hashLen != 32 || issuer != "human-1" || plainInRow {
			t.Fatalf("stored row: hash len %d issuer %q plaintext in row %v", hashLen, issuer, plainInRow)
		}
	})
}

func TestRedeem(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		// This test is about redeem semantics, not the limiter: a generous budget for its many failures from one source.
		svc := e.svc(true, true, fleetsql.NewMemoryLimiter(fleetsql.MemoryLimiterConfig{Burst: 1000}))
		issue := func(tid tenant.ID) fleetsql.Issued {
			iss, err := svc.Issue(ctx, tid, admin, fleetsql.NewComponent{Kind: fleetsql.KindAgent, Name: "dc1"})
			if err != nil {
				t.Fatal(err)
			}
			return iss
		}

		// Unreadable source: refused as a programming error, not as an invalid token, and no other
		// source is affected.
		iss := issue(e.a)
		for _, src := range []string{"", "garbage"} {
			if _, err := svc.Redeem(ctx, src, iss.Token); err == nil || errors.Is(err, fleetsql.ErrTokenInvalid) || errors.Is(err, fleetsql.ErrRateLimited) {
				t.Fatalf("Redeem(source %q) = %v, want a not-configured error", src, err)
			}
		}

		// AC2: sequential double redeem.
		got, err := svc.Redeem(ctx, "192.0.2.1", iss.Token)
		if err != nil || got.TenantID != e.a || got.ComponentID != iss.ComponentID || got.Kind != fleetsql.KindAgent || got.Name != "dc1" {
			t.Fatalf("first redeem: %+v %v", got, err)
		}
		if _, err := svc.Redeem(ctx, "192.0.2.1", iss.Token); !errors.Is(err, fleetsql.ErrTokenInvalid) {
			t.Fatalf("second redeem: %v", err)
		}
		var used bool
		_ = e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT used_at IS NOT NULL FROM public.enrollment_tokens WHERE id = $1::uuid`, iss.TokenID).Scan(&used)
		})
		if !used {
			t.Fatal("used_at not set")
		}

		// AC2: concurrent redeem, exactly one winner.
		iss = issue(e.a)
		var wins, losses atomic.Int32
		var wg sync.WaitGroup
		for i := range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// A generous per-source budget: this test is about the race, not the limiter.
				lim := fleetsql.NewMemoryLimiter(fleetsql.MemoryLimiterConfig{Burst: 100})
				_, err := e.svc(true, true, lim).Redeem(ctx, fmt.Sprintf("192.0.2.%d", i), iss.Token)
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, fleetsql.ErrTokenInvalid):
					losses.Add(1)
				default:
					t.Errorf("redeem: %v", err)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 || losses.Load() != 15 {
			t.Fatalf("concurrent redeem: %d won, %d lost", wins.Load(), losses.Load())
		}

		// AC3: expired. The guard forbids writing expires_at, so age the row as the owner.
		iss = issue(e.a)
		// Superuser with the guard trigger off and RLS bypassed (the database is this test's own): a test-only way to age a row.
		adm, err := e.d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer adm.Close(ctx)
		if _, err := adm.Exec(ctx, `ALTER TABLE public.enrollment_tokens DISABLE TRIGGER enrollment_tokens_guard`); err != nil {
			t.Fatal(err)
		}
		if tag, err := adm.Exec(ctx, `UPDATE public.enrollment_tokens SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1::uuid`, iss.TokenID); err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("age token: %v %v", tag, err)
		}
		if _, err := svc.Redeem(ctx, "192.0.2.1", iss.Token); !errors.Is(err, fleetsql.ErrTokenInvalid) {
			t.Fatalf("expired redeem: %v", err)
		}

		// A token of tenant A, relabelled with tenant B's ID, finds nothing in B.
		iss = issue(e.a)
		forged := fleetsql.ParseToken(strings.Replace(iss.Token.String(), e.a.String(), e.b.String(), 1))
		if _, err := svc.Redeem(ctx, "192.0.2.1", forged); !errors.Is(err, fleetsql.ErrTokenInvalid) {
			t.Fatalf("cross-tenant redeem: %v", err)
		}
		// Garbage and unknown tokens answer the same way.
		for _, g := range []string{"", "enr1.", "nope", "enr1." + e.a.String() + ".AAAA", "enr1." + e.a.String() + "." + strings.Repeat("A", 43)} {
			if _, err := svc.Redeem(ctx, "192.0.2.1", fleetsql.ParseToken(g)); !errors.Is(err, fleetsql.ErrTokenInvalid) {
				t.Fatalf("%q: %v", g, err)
			}
		}
		// A token whose component is no longer pending is refused.
		iss = issue(e.a)
		if n, err := e.raw(e.a, `UPDATE public.components SET state = 'removed' WHERE id = $1::uuid`, iss.ComponentID); err != nil || n != 1 {
			t.Fatalf("remove component: %d %v", n, err)
		}
		if _, err := svc.Redeem(ctx, "192.0.2.1", iss.Token); !errors.Is(err, fleetsql.ErrTokenInvalid) {
			t.Fatalf("removed component: %v", err)
		}
	})
}

func TestRedeemRateLimit(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		now := time.Now()
		lim := fleetsql.NewMemoryLimiter(fleetsql.MemoryLimiterConfig{Burst: 3, Refill: time.Minute, Now: func() time.Time { now = now.Add(time.Nanosecond); return now }})
		svc := e.svc(true, true, lim)
		iss, err := svc.Issue(ctx, e.a, admin, fleetsql.NewComponent{Kind: fleetsql.KindConnector, Name: "c"})
		if err != nil {
			t.Fatal(err)
		}
		bad := fleetsql.ParseToken("enr1." + e.a.String() + "." + strings.Repeat("A", 43))
		for range 3 {
			if _, err := svc.Redeem(ctx, "198.51.100.7", bad); !errors.Is(err, fleetsql.ErrTokenInvalid) {
				t.Fatalf("%v", err)
			}
		}
		// AC4: budget spent. The real token and a bad one are refused identically from this source.
		var rl *fleetsql.RateLimitedError
		_, errReal := svc.Redeem(ctx, "198.51.100.7", iss.Token)
		_, errBad := svc.Redeem(ctx, "198.51.100.7", bad)
		if !errors.As(errReal, &rl) || rl.RetryAfter <= 0 || !errors.Is(errBad, fleetsql.ErrRateLimited) || errReal.Error() != errBad.Error() {
			t.Fatalf("real %v / bad %v", errReal, errBad)
		}
		// Another source is unaffected, and the refused attempt did not consume the token.
		if _, err := svc.Redeem(ctx, "198.51.100.8", iss.Token); err != nil {
			t.Fatalf("other source: %v", err)
		}
	})
}

func TestDatabaseGuards(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		iss, err := e.svc(true, true, nil).Issue(ctx, e.a, admin, fleetsql.NewComponent{Kind: fleetsql.KindConnector, Name: "c"})
		if err != nil {
			t.Fatal(err)
		}
		for name, sql := range map[string]string{
			"extend expiry":       `UPDATE public.enrollment_tokens SET expires_at = expires_at + interval '1 hour'`,
			"swap hash":           `UPDATE public.enrollment_tokens SET token_hash = '\x00'::bytea || substring(token_hash from 2)`,
			"delete token":        `DELETE FROM public.enrollment_tokens`,
			"delete component":    `DELETE FROM public.components`,
			"skip a transition":   `UPDATE public.components SET state = 'active'`,
			"insert past pending": `INSERT INTO public.components (tenant_id, kind, name, state) VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, 'agent', 'x', 'active')`,
			"insert used token": `INSERT INTO public.enrollment_tokens (tenant_id, component_id, token_hash, issued_by, expires_at, used_at)
				SELECT tenant_id, id, '\x0000000000000000000000000000000000000000000000000000000000000001'::bytea, 'h', now() + interval '1 hour', now() FROM public.components LIMIT 1`,
			"24h cap": `INSERT INTO public.enrollment_tokens (tenant_id, component_id, token_hash, issued_by, expires_at)
				SELECT tenant_id, id, '\x0000000000000000000000000000000000000000000000000000000000000002'::bytea, 'h', now() + interval '25 hours' FROM public.components LIMIT 1`,
		} {
			if _, err := e.raw(e.a, sql); err == nil {
				t.Errorf("%s: the database accepted it", name)
			}
		}
		// used_at is write-once.
		if n, err := e.raw(e.a, `UPDATE public.enrollment_tokens SET used_at = now() WHERE id = $1::uuid`, iss.TokenID); err != nil || n != 1 {
			t.Fatalf("first use: %d %v", n, err)
		}
		if _, err := e.raw(e.a, `UPDATE public.enrollment_tokens SET used_at = now() + interval '1 second' WHERE id = $1::uuid`, iss.TokenID); err == nil {
			t.Error("used_at rewritten")
		}
		// Tenant isolation: B sees nothing of A's.
		var n int
		_ = e.db.WithTenant(ctx, e.b, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM public.components) + (SELECT count(*) FROM public.enrollment_tokens)`).Scan(&n)
		})
		if n != 0 {
			t.Fatalf("tenant B sees %d rows of A", n)
		}
	})
}
