package server

import (
	"context"
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

// The directory read behind the session is T-0680's real handler (modules/directory.Handlers); only its two
// backends are fakes here: a registry with one verified active AD connection and a searcher that answers
// one user. The connector tunnel is not under test; the session, its grant and the handler are.
type activeConns struct{}

func (activeConns) List(context.Context, tenant.ID, bool) ([]connection.Connection, error) {
	return []connection.Connection{{ID: "c1", Kind: connection.KindADForest, State: connection.StateActive}}, nil
}

func (activeConns) Health(context.Context, tenant.ID, connection.ID, bool, time.Time) (connection.Health, error) {
	now := time.Now()
	return connection.Health{Verdict: connection.VerdictPass, RightsCheckedAt: &now}, nil
}

type oneUser struct{ tid tenant.ID }

// consoleScopes is the producer behind the fake search: it never narrows (one naming-context grant),
// so these tests keep exercising the sign-in plane, not the trimming (that is modules/directory's).
type consoleScopes struct{}

func (consoleScopes) ReadScope(context.Context, tenant.ID, authority.Chain, authz.Permission) (authz.ReadScope, error) {
	return authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: authz.ObjectID{15: 1}, Root: authz.ObjectID{15: 2}}}}), nil
}

func (o *oneUser) Users(_ context.Context, tid tenant.ID, _ connection.ID, _ string, _ int, _ authz.ReadScope) (client.UserSearchResult, error) {
	o.tid = tid
	return client.UserSearchResult{Users: []client.FoundUser{{ObjectGUID: "aaaaaaaa-0000-4000-8000-00000000000a", DisplayName: "Ada Bianchi", SAMAccountName: "ada.bianchi", Enabled: true}}}, nil
}

var traceID = regexp.MustCompile(`"traceId":"[0-9a-f]+",?`)

const signInPassword = "correct horse battery staple"

func postJSON(h http.Handler, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return postJSONFrom(h, "203.0.113.7:1", path, body, cookies...)
}

// postJSONFrom is postJSON from the given TCP peer ("ip:port").
func postJSONFrom(h http.Handler, peer, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = peer
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// T-0783 acceptance: a booted server (the console stack composed exactly as Run composes it) and a local
// account with TOTP enrolled: the password step answers a pending cookie and nothing else, the TOTP step
// sets the session cookie, and that session carries the account's directory.read through the real chain.
func TestLocalAccountSignInThroughTheMountedRoutes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ks := keys.NewStore(keystest.New("kek-1"))
		ten := tenanttest.Seed(t, d.ExecOwner, firstRunTenantName)
		if err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error { return ks.Provision(ctx, tx, ten) }); err != nil {
			t.Fatal(err)
		}
		deps := localAccountDeps{DB: db, Sink: nopSink{}, Keys: ks.KeySource()}
		la, err := createLocalAccount(ctx, deps, LocalAccountSpec{Username: "Break.Glass", Password: secret.FromBytes([]byte(signInPassword))})
		if err != nil {
			t.Fatal(err)
		}
		var seedText string
		la.Seed.Expose(func(b []byte) { seedText = string(b) })
		seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(seedText))
		if err != nil {
			t.Fatal(err)
		}
		if err := confirmTOTP(ctx, deps, la, totpCode(seed, time.Now())); err != nil {
			t.Fatal(err)
		}

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
		found := &oneUser{}
		cfg := config.Config{APIBodyBudget: config.DefaultAPIBodyBudget, PublicURL: chainOrigin}
		h, err := buildAPIPorts(cfg, bootedCatalogue(), console.ports(testLimiter(t), az, bootedCatalogue()), console.Tags(), directory.Handlers{Connections: activeConns{}, Search: found, Scopes: consoleScopes{}}.Bind())
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now() // the sign-in plane's clock, so the throttle can be waited out
		console.Local.Clock = func() time.Time { return now }
		login := `{"username":"break.glass","password":"` + signInPassword + `"}`

		t.Run("wrong, unknown and empty look the same", func(t *testing.T) {
			var want string
			for _, body := range []string{
				`{"username":"break.glass","password":"not the password at all"}`,
				`{"username":"nobody.here","password":"not the password at all"}`,
			} {
				w := postJSON(h, "/api/v1/auth/break-glass/password", body)
				if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "/problems/sign-in-failed") || len(w.Result().Cookies()) != 0 {
					t.Fatalf("%s: %d %s %v", body, w.Code, w.Body, w.Result().Cookies())
				}
				if want == "" {
					want = traceID.ReplaceAllString(w.Body.String(), "")
				} else if traceID.ReplaceAllString(w.Body.String(), "") != want {
					t.Errorf("failure bodies differ:\n%s\n%s", want, w.Body)
				}
			}
			if w := postJSON(h, "/api/v1/auth/break-glass/password", `{"username":"break.glass","password":""}`); w.Code == http.StatusNoContent {
				t.Errorf("an empty password signed in: %d", w.Code)
			}
		})

		t.Run("repeated failures delay the account but never lock it", func(t *testing.T) {
			wrong := `{"username":"break.glass","password":"still not the password"}`
			for i := 0; i < authn.ThrottleBurst+2; i++ {
				if w := postJSON(h, "/api/v1/auth/break-glass/password", wrong); w.Code != http.StatusUnauthorized {
					t.Fatalf("wrong attempt %d: %d", i, w.Code)
				}
			}
			before := console.Local.Verifications()
			w := postJSON(h, "/api/v1/auth/break-glass/password", login)
			if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
				t.Fatalf("the right password while throttled: %d %v", w.Code, w.Result().Cookies())
			}
			if got := console.Local.Verifications() - before; got != 1 {
				t.Errorf("a throttled attempt ran %d hash verifications, want exactly 1", got)
			}
			now = now.Add(authn.ThrottleCeiling + time.Minute)
			if w := postJSON(h, "/api/v1/auth/break-glass/password", login); w.Code != http.StatusNoContent {
				t.Fatalf("the right password after the delay: %d %s", w.Code, w.Body)
			}
		})

		t.Run("password then TOTP makes a session that reaches the directory", func(t *testing.T) {
			w := postJSON(h, "/api/v1/auth/break-glass/password", login)
			if w.Code != http.StatusNoContent || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Name != authn.PendingCookieName {
				t.Fatalf("password step: %d %s %v", w.Code, w.Body, w.Result().Cookies())
			}
			pending := w.Result().Cookies()[0]
			// The pending cookie is not a session.
			r := httptest.NewRequest(http.MethodGet, "/api/v1/directory/users?q=a", nil)
			r.AddCookie(pending)
			r.RemoteAddr = "203.0.113.7:1"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("pending cookie on a read: %d %s", rec.Code, rec.Body)
			}

			w = postJSON(h, "/api/v1/auth/second-factor/totp/verify", `{"code":"`+totpCode(seed, time.Now().Add(30*time.Second))+`"}`, pending)
			var session *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == "__Host-adiq_session" || strings.Contains(c.Name, "session") {
					session = c
				}
			}
			if w.Code != http.StatusNoContent && w.Code != http.StatusOK || session == nil {
				t.Fatalf("totp step: %d %s %v", w.Code, w.Body, w.Result().Cookies())
			}

			r = httptest.NewRequest(http.MethodGet, "/api/v1/directory/users?q=a", nil)
			r.AddCookie(session)
			r.RemoteAddr = "203.0.113.7:1"
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			t.Logf("directory read with the new session: %d %s", rec.Code, rec.Body)
			if rec.Code != http.StatusOK {
				t.Fatalf("directory read with the session: %d %s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), "ada.bianchi") {
				t.Errorf("the real handler's answer is missing the found user: %s", rec.Body)
			}
			if found.tid != ten {
				t.Errorf("the search ran for tenant %v, want the session's tenant %v", found.tid, ten)
			}
		})
	})
}
