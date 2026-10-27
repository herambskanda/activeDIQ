package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/httpx/authnhttp"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	chainCred   = "11111111-1111-4111-8111-111111111111"
	chainEntra  = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	chainPerm   = "connections.takeover.attest"
	chainOrigin = "https://diq.example.com"
)

type chainEnv struct {
	db    *store.DB
	ten   tenant.ID
	conn  connection.Connection
	sess  *authn.Store
	acct  string
	build func(t *testing.T, as ...rbac.Assignment) http.Handler
}

// chainSetup is a real database, a real session store and account, and an active Entra connection. The
// handler under test is composed exactly as Run composes it: buildConsole, buildAttestation (the real
// Entra adapters, which Start never calls) and buildAPIPorts over console.ports.
func chainSetup(t *testing.T, s *storetest.Server) *chainEnv {
	t.Helper()
	ctx := context.Background()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e := &chainEnv{db: db, ten: tenanttest.Seed(t, d.ExecOwner, "A")}
	console, err := buildConsole(db, nopSink{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.sess = console.Sessions

	accts, err := authn.NewAccounts(db, e.sess, rbac.Owners{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := accts.Create(ctx, authn.NewAccount{Tenant: e.ten, Kind: authn.KindLocal, DisplayName: "ga", CreatedBy: "system"})
	if err != nil {
		t.Fatal(err)
	}
	sys := authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}
	if _, err := accts.SetState(ctx, e.ten, a.ID, authn.AccountActive, sys); err != nil {
		t.Fatal(err)
	}
	e.acct = a.ID

	reg := connection.NewRegistry(db)
	c, err := reg.Create(ctx, e.ten, connection.New{Kind: connection.KindEntraTenant, DisplayName: "tenant", CredentialID: chainCred})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Transition(ctx, e.ten, c.ID, connection.StateDraft, connection.StateVerifying); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.SetDirectoryIdentity(ctx, e.ten, c.ID, chainEntra); err != nil {
		t.Fatal(err)
	}
	err = db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
		if _, err := (connection.Store{}).RecordVerification(ctx, tx, connection.NewVerification{
			ID: "00000000-0000-4000-b000-000000000475", ConnectionID: c.ID, CredentialID: chainCred, Kind: connection.KindManual,
			RequestedBy: "principal-test", StartedAt: time.Now().UTC(), CheckListVersion: 1, Verdict: connection.VerdictPass,
			Outcomes: map[connection.Check]connection.Outcome{"EV2": connection.OutcomePass,
				connection.CheckEV3OverPrivilege: connection.OutcomePass, connection.CheckEV4Sufficiency: connection.OutcomePass},
		}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.connector_bindings (tenant_id, connection_id, target)
			VALUES (current_setting('app.tenant_id')::uuid, $1::uuid, 'embedded')`, string(c.ID)); err != nil {
			return err
		}
		c, err = connection.Store{}.Activate(ctx, tx, c.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	e.conn = c

	e.build = func(t *testing.T, as ...rbac.Assignment) http.Handler {
		t.Helper()
		az, err := rbac.New(memSrc{as})
		if err != nil {
			t.Fatal(err)
		}
		cfg := config.Config{APIBodyBudget: config.DefaultAPIBodyBudget, AttestClientID: "app-client", PublicURL: chainOrigin}
		tags, err := buildAttestation(cfg, db, nopSink{}, az, sessionStepUp{console.StepUp})
		if err != nil || len(tags) != 1 {
			t.Fatalf("attestation: %d tags, %v", len(tags), err)
		}
		h, err := buildAPIPorts(cfg, console.ports(testLimiter(t), az), tags...)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	return e
}

// signIn opens a console session; mfaAt nil is a session that never passed MFA.
func (e *chainEnv) signIn(t *testing.T, mfaAt *time.Time) authn.Token {
	t.Helper()
	ep, err := e.sess.Epoch(context.Background(), e.ten, e.acct)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.sess.Create(context.Background(), authn.CreateInput{Tenant: e.ten, Account: e.acct,
		Methods: []string{"password", "totp"}, MFAAt: mfaAt, AuthorityFactorAt: mfaAt,
		ClientIP: netip.MustParseAddr("192.0.2.7"), Epoch: ep})
	if err != nil {
		t.Fatal(err)
	}
	return res.Token
}

// grant is a Global-Administrator-shaped assignment: the permission over the tenant store root (chain
// step 12) and over the connection's entra_tenant scope (the handler's own check).
func (e *chainEnv) grant(perm authz.Permission) rbac.Assignment {
	return rbac.Assignment{Permissions: []authz.Permission{perm}, Roots: []rbac.Root{
		{Kind: rbac.TenantStore, Connection: e.ten.String(), GUID: e.ten.String()},
		{Kind: rbac.EntraTenant, Connection: string(e.conn.ID), GUID: string(e.conn.ID)},
	}}
}

func (e *chainEnv) do(h http.Handler, tok authn.Token, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.AddCookie(authnhttp.SessionCookie(tok, time.Hour))
	r.Header.Set(authnhttp.CSRFHeader, authnhttp.CSRFValue(tok))
	r.RemoteAddr = "203.0.113.7:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// T-0475 AC1 without a live Entra: the real chain from the session cookie through step-up freshness and
// RBAC to Attester.Start and SetMaxAge.
func TestConsoleChainStartAndMaxAge(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := chainSetup(t, s)
		start := "/api/v1/connections/" + string(e.conn.ID) + "/takeover-attestation"
		maxAge := start + "/max-age"
		now := time.Now().UTC()
		stale := now.Add(-time.Hour)

		t.Run("fresh MFA and tenant-root permission returns authorizeUrl", func(t *testing.T) {
			h := e.build(t, e.grant(chainPerm))
			w := e.do(h, e.signIn(t, &now), http.MethodPost, start, "")
			if w.Code != http.StatusOK {
				t.Fatalf("start: %d %s", w.Code, w.Body)
			}
			var out struct {
				AuthorizeURL string `json:"authorizeUrl"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(out.AuthorizeURL)
			if err != nil || u.Host != "login.microsoftonline.com" || !strings.HasPrefix(u.Path, "/"+chainEntra+"/oauth2/v2.0/authorize") ||
				u.Query().Get("client_id") != "app-client" || u.Query().Get("state") == "" || u.Query().Get("code_challenge_method") != "S256" {
				t.Fatalf("authorizeUrl = %q (%v)", out.AuthorizeURL, err)
			}
		})

		t.Run("session without MFA freshness is refused a step-up", func(t *testing.T) {
			h := e.build(t, e.grant(chainPerm))
			for name, at := range map[string]*time.Time{"never passed MFA": nil, "MFA an hour old": &stale} {
				w := e.do(h, e.signIn(t, at), http.MethodPost, start, "")
				if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "/problems/step-up-required") || strings.Contains(w.Body.String(), "authorizeUrl") {
					t.Errorf("%s: start %d %s", name, w.Code, w.Body)
				}
				w = e.do(h, e.signIn(t, at), http.MethodPut, maxAge, `{"maxAgeSeconds":3600}`)
				if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "/problems/step-up-required") {
					t.Errorf("%s: max-age %d %s", name, w.Code, w.Body)
				}
			}
		})

		t.Run("a role without the permission is 403", func(t *testing.T) {
			h := e.build(t, e.grant("inventory.read"))
			tok := e.signIn(t, &now)
			if w := e.do(h, tok, http.MethodPost, start, ""); w.Code != http.StatusForbidden {
				t.Errorf("start: %d %s", w.Code, w.Body)
			}
			if w := e.do(h, tok, http.MethodPut, maxAge, `{"maxAgeSeconds":3600}`); w.Code != http.StatusForbidden {
				t.Errorf("max-age: %d %s", w.Code, w.Body)
			}
		})

		t.Run("no cookie is 401", func(t *testing.T) {
			h := e.build(t, e.grant(chainPerm))
			r := httptest.NewRequest(http.MethodPost, start, nil)
			r.RemoteAddr = "203.0.113.7:1"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("start: %d", w.Code)
			}
		})

		t.Run("SetMaxAge happy path", func(t *testing.T) {
			h := e.build(t, e.grant(chainPerm))
			w := e.do(h, e.signIn(t, &now), http.MethodPut, maxAge, `{"maxAgeSeconds":3600}`)
			if w.Code < 200 || w.Code > 299 {
				t.Fatalf("max-age: %d %s", w.Code, w.Body)
			}
		})
	})
}
