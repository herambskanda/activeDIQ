package server

import (
	"context"
	"encoding/base32"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

type auditRec struct {
	mu sync.Mutex
	ev []audit.Event
}

func (r *auditRec) Append(_ context.Context, _ store.Tx, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = append(r.ev, e)
	return nil
}

func hardeningDB(t *testing.T, s *storetest.Server, maxConns int32) (*store.DB, tenant.ID, *keys.Store) {
	t.Helper()
	ctx := context.Background()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN(), MaxConns: maxConns})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ks := keys.NewStore(keystest.New("kek-1"))
	ten := tenanttest.Seed(t, d.ExecOwner, firstRunTenantName)
	if err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error { return ks.Provision(ctx, tx, ten) }); err != nil {
		t.Fatal(err)
	}
	return db, ten, ks
}

func hardeningHandler(t *testing.T, db *store.DB, ten tenant.ID, ks *keys.Store) (http.Handler, *consoleStack) {
	t.Helper()
	console, err := buildConsole(db, nopSink{}, ks.KeySource(), nil)
	if err != nil {
		t.Fatal(err)
	}
	console.SetTenant(ten)
	src, err := rbac.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	az, err := rbac.New(src)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{APIBodyBudget: config.DefaultAPIBodyBudget, PublicURL: chainOrigin}
	h, err := buildAPIPorts(cfg, permissionCatalogue(), console.ports(testLimiter(t), az, permissionCatalogue()), console.Tags(), directory.Handlers{Connections: activeConns{}, Search: &oneUser{}, Scopes: consoleScopes{}}.Bind())
	if err != nil {
		t.Fatal(err)
	}
	return h, console
}

// Security review of T-0783, finding 1: the 64 MiB hash runs outside any transaction and under a process-
// wide cap. With a pool of two, a burst of distinct names cannot exceed the cap, is refused (429, not
// queued) above it, and a read in parallel still gets a connection.
func TestSignInBurstIsCappedAndHoldsNoConnection(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		db, ten, ks := hardeningDB(t, s, 2)
		h, console := hardeningHandler(t, db, ten, ks)
		console.Local.MaxConcurrent = 2

		var wg sync.WaitGroup
		var ok401, busy429, other atomic.Int32
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body := `{"username":"user` + string(rune('a'+i)) + `","password":"not the password at all"}`
				switch postJSON(h, "/api/v1/auth/break-glass/password", body).Code {
				case http.StatusUnauthorized:
					ok401.Add(1)
				case http.StatusTooManyRequests:
					busy429.Add(1)
				default:
					other.Add(1)
				}
			}()
		}
		var readErr error
		var reads int
		deadline := time.Now().Add(250 * time.Millisecond)
		for time.Now().Before(deadline) {
			rc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			readErr = db.WithTenant(rc, ten, func(ctx context.Context, tx store.Tx) error {
				var n int
				return tx.QueryRow(ctx, `SELECT 1`).Scan(&n)
			})
			cancel()
			if readErr != nil {
				break
			}
			reads++
		}
		wg.Wait()
		if readErr != nil {
			t.Errorf("a read starved during the sign-in burst (after %d): %v", reads, readErr)
		}
		if p := console.Local.PeakVerifications(); p > 2 {
			t.Errorf("peak concurrent verifications %d exceeds the cap 2", p)
		}
		if other.Load() != 0 || busy429.Load() == 0 || ok401.Load() == 0 {
			t.Errorf("answers: 401=%d 429=%d other=%d; want some of each of the first two and no other", ok401.Load(), busy429.Load(), other.Load())
		}
	})
}

// T-0809: one source saturating AN-8 cannot hold every in-flight slot. While a burst of distinct names from
// one address keeps its share busy, a second address that signs in with the right password gets its
// pending cookie every time, and the burst's own overflow is refused (429) without queueing.
func TestSignInFairShareLetsASecondSourceIn(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		db, ten, ks := hardeningDB(t, s, 0)
		deps := localAccountDeps{DB: db, Sink: nopSink{}, Keys: ks.KeySource()}
		la, err := createLocalAccount(ctx, deps, LocalAccountSpec{Username: "break.glass", Password: secret.FromBytes([]byte(signInPassword))})
		if err != nil {
			t.Fatal(err)
		}
		var seedText string
		la.Seed.Expose(func(b []byte) { seedText = string(b) })
		seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(seedText))
		if err != nil {
			t.Fatal(err)
		}
		if err := confirmTOTP(ctx, deps, la, totpCode(seed, time.Now())); err != nil { // the account is active only now
			t.Fatal(err)
		}
		h, console := hardeningHandler(t, db, ten, ks)
		console.Local.MaxConcurrent = 2 // MaxPerSource stays at its default of 1

		const path = "/api/v1/auth/break-glass/password"
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var hogBusy, hogOther atomic.Int32
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for n := 0; ; n++ {
					select {
					case <-stop:
						return
					default:
					}
					body := `{"username":"hog` + string(rune('a'+i)) + string(rune('a'+n%26)) + `","password":"not the password at all"}`
					switch postJSONFrom(h, "198.51.100.7:4000", path, body).Code {
					case http.StatusTooManyRequests:
						hogBusy.Add(1)
					case http.StatusUnauthorized:
					default:
						hogOther.Add(1)
					}
				}
			}()
		}
		login := `{"username":"break.glass","password":"` + signInPassword + `"}`
		for i := 0; i < 5; i++ {
			w := postJSONFrom(h, "203.0.113.50:5000", path, login)
			if w.Code != http.StatusNoContent || len(w.Result().Cookies()) != 1 {
				t.Errorf("second source, try %d: %d %s (want 204 and the pending cookie)", i, w.Code, w.Body)
			}
		}
		close(stop)
		wg.Wait()
		if hogBusy.Load() == 0 || hogOther.Load() != 0 {
			t.Errorf("saturating source: 429=%d other=%d; want its overflow refused and nothing unexpected", hogBusy.Load(), hogOther.Load())
		}
		if p := console.Local.PeakVerifications(); p > 2 {
			t.Errorf("peak concurrent verifications %d exceeds the cap 2", p)
		}
	})
}

// Finding 2 and the non-atomic flow of finding 4: every write of init-local names the CLI principal and
// none names an existing account; a wrong confirmation code leaves the account unable to sign in.
func TestInitLocalAttributionAndFailedConfirm(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		db, ten, ks := hardeningDB(t, s, 0)
		sink := &auditRec{}
		deps := localAccountDeps{DB: db, Sink: sink, Keys: ks.KeySource()}
		pw := func() secret.Secret { return secret.FromBytes([]byte(signInPassword)) }

		first, err := createLocalAccount(ctx, deps, LocalAccountSpec{Username: "first.admin", Password: pw()})
		if err != nil {
			t.Fatal(err)
		}
		sink.mu.Lock()
		sink.ev = nil // only the second run's events count
		sink.mu.Unlock()
		second, err := createLocalAccount(ctx, deps, LocalAccountSpec{Username: "second.admin", Password: pw()})
		if err != nil {
			t.Fatal(err)
		}
		sink.mu.Lock()
		for _, e := range sink.ev {
			if string(e.Actor.Requester.ID) == first.ID || string(e.Actor.Requester.ID) == second.ID {
				t.Errorf("event %s names account %s as its actor", e.Kind, e.Actor.Requester.ID)
			}
		}
		sink.mu.Unlock()
		var grantors []string
		err = db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.Query(ctx, `SELECT DISTINCT granted_by FROM public.authz_assignments WHERE account_id = $1::uuid`, second.ID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var g string
				if err := rows.Scan(&g); err != nil {
					return err
				}
				grantors = append(grantors, g)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(grantors) == 0 {
			t.Fatal("the second account holds no assignment")
		}
		for _, g := range grantors {
			if g != string(cliActor.Requester.ID) {
				t.Errorf("assignment granted_by %q, want %q", g, cliActor.Requester.ID)
			}
		}

		// A wrong code: the account stays inactive and cannot pass the password step.
		if err := confirmTOTP(ctx, deps, second, "000000"); err == nil {
			t.Fatal("a wrong code confirmed the enrolment")
		}
		h, _ := hardeningHandler(t, db, ten, ks)
		w := postJSON(h, "/api/v1/auth/break-glass/password", `{"username":"second.admin","password":"`+signInPassword+`"}`)
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Header().Get("Set-Cookie"), "pending") {
			t.Errorf("an unconfirmed account got past the password step: %d %s", w.Code, w.Body)
		}
	})
}
