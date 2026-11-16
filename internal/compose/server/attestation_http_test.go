package server

// Composition test: the module's attestation HTTP flow driven through the composed Entra adapters
// (entra.OIDCIdP, entra.GraphReader), as the composition root wires them. It lives here, not under
// internal/modules, next to the code that wires the attestation (attestation.go), because a module must not import internal/compose (ADR-0002 rule 1; T-0943).
// Cases that need no adapter (TestWindowGate, TestStateTenant) stay in internal/modules/connections.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/server/entra"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	attEntraTenantID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	attOtherTenantID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	attGAOID         = "99999999-9999-4999-8999-999999999999"
	attCred          = "11111111-1111-4111-8111-111111111111"
)

// attHTTPAuthz grants TakeoverAttestPermission to the named requesters over entra_tenant.
type attHTTPAuthz map[authority.PrincipalID]bool

func (a attHTTPAuthz) Authorize(ctx context.Context, c authority.Chain, p authz.Permission, t authority.TargetRef) error {
	// The real authorizer (RBAC) refuses a call with no tenant on the context (no_tenant).
	if tid, ok := authority.TenantFrom(ctx); !ok || tid == "" {
		return errors.New("no tenant on the authorisation context")
	}
	if p == connections.TakeoverAttestPermission && t.Class == "entra_tenant" && a[c.Requester.ID] {
		return nil
	}
	return errors.New("not granted")
}

type attHTTPStepUp struct{ fresh bool }

func (s attHTTPStepUp) Fresh(context.Context, tenant.ID, string) (bool, error) { return s.fresh, nil }

type attHTTPRecorder struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (r *attHTTPRecorder) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *attHTTPRecorder) all() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.evs...)
}

// attHTTPBase is the tenant, an active Entra connection and the recording sinks the HTTP flow runs over.
type attHTTPBase struct {
	db   *store.DB
	d    *storetest.Database
	reg  *connection.Registry
	tid  tenant.ID
	conn connection.Connection
	rec  *attHTTPRecorder
	now  time.Time
	seq  int
}

func newAttHTTPBase(t *testing.T, s *storetest.Server) *attHTTPBase {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e := &attHTTPBase{db: db, d: d, reg: connection.NewRegistry(db), tid: tid, rec: &attHTTPRecorder{},
		now: time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)}
	e.conn = e.activeEntra(t)
	return e
}

// activeEntra walks a tenant connection through the one legal door into active.
func (e *attHTTPBase) activeEntra(t *testing.T) connection.Connection {
	t.Helper()
	ctx := context.Background()
	c, err := e.reg.Create(ctx, e.tid, connection.New{Kind: connection.KindEntraTenant, DisplayName: "tenant", CredentialID: attCred})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.Transition(ctx, e.tid, c.ID, connection.StateDraft, connection.StateVerifying); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.SetDirectoryIdentity(ctx, e.tid, c.ID, attEntraTenantID); err != nil {
		t.Fatal(err)
	}
	err = e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
		if _, err := (connection.Store{}).RecordVerification(ctx, tx, connection.NewVerification{
			ID: "00000000-0000-4000-b000-000000000280", ConnectionID: c.ID, CredentialID: attCred, Kind: connection.KindManual,
			RequestedBy: "principal-test", StartedAt: e.now, CheckListVersion: 1, Verdict: connection.VerdictPass,
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
	return c
}

func attStateOf(t *testing.T, authURL string) (state string, q url.Values) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state"), u.Query()
}

func (e *attHTTPBase) takeover(t *testing.T) connection.Takeover {
	t.Helper()
	tk, err := e.reg.GetTakeover(context.Background(), e.tid, e.conn.ID, e.now)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func (e *attHTTPBase) attemptRows(t *testing.T) int {
	t.Helper()
	var n int
	err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.connection_attestation_attempts`).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// fakeMicrosoft plays login.microsoftonline.com and graph.microsoft.com on one TLS server. It checks what the
// real services check: the PKCE verifier against the challenge the start sent, and the bearer on the read.
type fakeMicrosoft struct {
	srv        *httptest.Server
	mu         sync.Mutex
	challenge  string
	tokenCalls int
	graphCalls int
	issued     string
	hard, soft bool
}

func newFakeMicrosoft(t *testing.T) *fakeMicrosoft {
	t.Helper()
	m := &fakeMicrosoft{hard: true, soft: true}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /"+attEntraTenantID+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.tokenCalls++
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("code") != "ms-code" ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != m.challenge || r.PostForm.Get("scope") != connections.AttestScope {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
		m.issued = enc(map[string]string{"alg": "RS256"}) + "." + enc(map[string]any{"tid": attEntraTenantID, "oid": attGAOID,
			"iss": "https://login.microsoftonline.com/" + attEntraTenantID + "/v2.0", "aud": "00000003-0000-0000-c000-000000000000",
			"exp": time.Now().Add(time.Hour).Unix(), "scp": connections.AttestScope}) + ".c2ln"
		_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "access_token": m.issued, "scope": connections.AttestScope,
			"refresh_token": "REFRESH-TOKEN-VALUE", "id_token": "ID-TOKEN-VALUE"})
	})
	mux.HandleFunc("GET /v1.0/directory/onPremisesSynchronization", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.graphCalls++
		if r.Header.Get("Authorization") != "Bearer "+m.issued || m.issued == "" {
			w.WriteHeader(401)
			return
		}
		fmt.Fprintf(w, `{"value":[{"features":{"blockCloudObjectTakeoverThroughHardMatchEnabled":%t,"blockSoftMatchEnabled":%t}}]}`, m.hard, m.soft)
	})
	m.srv = httptest.NewTLSServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

// attHTTPPorts: one console session principal, everything allowed, so the test exercises the handlers
// and the Attester's own checks rather than the (separately tested) ports.
type attHTTPPorts struct{ p apihost.Principal }

func (s attHTTPPorts) Authenticate(*http.Request) (apihost.Principal, error) { return s.p, nil }
func (attHTTPPorts) CheckCSRF(*http.Request, apihost.Principal) error        { return nil }
func (attHTTPPorts) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (attHTTPPorts) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (attHTTPPorts) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (attHTTPPorts) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

type attHTTPEnv struct {
	*attHTTPBase
	ms  *fakeMicrosoft
	api http.Handler
}

func newAttHTTPEnv(t *testing.T, s *storetest.Server, gate connections.CallbackGate) *attHTTPEnv {
	t.Helper()
	e := newAttHTTPBase(t, s)
	ms := newFakeMicrosoft(t)
	at, err := connections.NewAttester(connections.AttestConfig{
		DB: e.db, Audit: e.rec, Authz: attHTTPAuthz{"admin": true}, StepUp: attHTTPStepUp{fresh: true},
		IdP:      &entra.OIDCIdP{HTTP: ms.srv.Client(), Authority: ms.srv.URL, ClientID: "app-client"},
		Graph:    &entra.GraphReader{HTTP: ms.srv.Client(), Base: ms.srv.URL + "/v1.0"},
		ClientID: "app-client", RedirectURI: "https://diq.example/api/v1/connections/takeover-attestation/callback", Authority: ms.srv.URL,
		Component: "connections", NewID: func() string { e.seq++; return fmt.Sprintf("ev-%d", e.seq) },
		Now: func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h := &connections.AttestHandlers{Attester: at, Gate: gate}
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	sp := attHTTPPorts{p: apihost.Principal{ID: "admin", Tenant: e.tid.String(), Kind: apihost.KindSession, SessionID: "sess"}}
	srv, err := apihost.Build(doc, []apihost.TagHandlers{h.Bind()}, pol, bootedCatalogue(),
		apihost.Ports{Authn: sp, Authz: sp, Limits: sp, StepUp: sp})
	if err != nil {
		t.Fatal(err)
	}
	return &attHTTPEnv{attHTTPBase: e, ms: ms, api: srv}
}

func (e *attHTTPEnv) do(method, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, r)
	return w
}

// begin runs POST start and returns the state the browser would carry back, having told the fake
// Microsoft the challenge it must see verified.
func (e *attHTTPEnv) begin(t *testing.T) string {
	t.Helper()
	w := e.do("POST", "/api/v1/connections/"+string(e.conn.ID)+"/takeover-attestation")
	if w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	var body struct {
		AuthorizeURL string `json:"authorizeUrl"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	state, q := attStateOf(t, body.AuthorizeURL)
	e.ms.mu.Lock()
	e.ms.challenge = q.Get("code_challenge")
	e.ms.mu.Unlock()
	if q.Get("code_challenge_method") != "S256" || !strings.HasPrefix(body.AuthorizeURL, e.ms.srv.URL+"/"+attEntraTenantID+"/oauth2/v2.0/authorize") {
		t.Fatalf("authorize url %q", body.AuthorizeURL)
	}
	return state
}

func (e *attHTTPEnv) callbackURL(state, code string) string {
	return "/api/v1/connections/takeover-attestation/callback?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code)
}

// Acceptance 1: start and callback over HTTP against the real adapters record the attestation and
// persist nothing but the DM-10.I7 columns.
func TestAttestOverHTTPWithRealAdapters(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newAttHTTPEnv(t, s, &connections.WindowGate{})
		state := e.begin(t)
		w := e.do("GET", e.callbackURL(state, "ms-code"))
		if w.Code != 303 || w.Header().Get("Location") != connections.AttestRecordedLocation {
			t.Fatalf("callback: %d %q", w.Code, w.Header().Get("Location"))
		}
		tk := e.takeover(t)
		if tk.State != connection.TakeoverAttested || tk.Record.Attestation == nil || tk.Record.Attestation.By != attGAOID {
			t.Fatalf("takeover %+v", tk)
		}
		if n := e.attemptRows(t); n != 0 {
			t.Fatalf("%d attempt rows left", n)
		}
		if e.ms.tokenCalls != 1 || e.ms.graphCalls != 1 {
			t.Fatalf("token %d graph %d", e.ms.tokenCalls, e.ms.graphCalls)
		}
		// Nothing the IdP issued is stored or audited.
		for _, needle := range []string{e.ms.issued, "REFRESH-TOKEN-VALUE", "ID-TOKEN-VALUE", "ms-code", state} {
			for _, ev := range e.rec.all() {
				if strings.Contains(fmt.Sprintf("%+v", ev), needle) {
					t.Fatalf("audit event carries %q", needle[:6])
				}
			}
			for _, tb := range []string{"connections", "connection_attestation_attempts"} {
				hits, err := e.d.OwnerStrings(context.Background(), fmt.Sprintf(`SELECT 'hit' FROM public.%q x WHERE x::text LIKE $1 LIMIT 1`, tb), "%"+needle+"%")
				if err != nil {
					t.Fatal(err)
				}
				if len(hits) != 0 {
					t.Fatalf("%s stores %q", tb, needle[:6])
				}
			}
		}
		// A replayed callback finds no attempt and records nothing more.
		if w := e.do("GET", e.callbackURL(state, "ms-code")); w.Header().Get("Location") != connections.AttestFailedLocation {
			t.Fatalf("replay: %d %q", w.Code, w.Header().Get("Location"))
		}
		if e.ms.tokenCalls != 1 {
			t.Fatal("a replayed state reached the token endpoint")
		}
	})
}

func TestAttestCallbackRefusals(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newAttHTTPEnv(t, s, &connections.WindowGate{})
		state := e.begin(t)
		for name, target := range map[string]string{
			"wrong code":     e.callbackURL(state, "other"),
			"idp error":      "/api/v1/connections/takeover-attestation/callback?state=" + url.QueryEscape(state) + "&error=access_denied",
			"no tenant":      e.callbackURL("nonsense", "ms-code"),
			"foreign tenant": e.callbackURL(attOtherTenantID+".abc", "ms-code"),
			"forged nonce":   e.callbackURL(e.tid.String()+".forged", "ms-code"),
		} {
			w := e.do("GET", target)
			if w.Code != 303 || w.Header().Get("Location") != connections.AttestFailedLocation {
				t.Fatalf("%s: %d %q", name, w.Code, w.Header().Get("Location"))
			}
		}
		if tk := e.takeover(t); tk.State == connection.TakeoverAttested {
			t.Fatal("a refused callback attested")
		}
	})
}

func TestAttestCallbackIsRateLimited(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newAttHTTPEnv(t, s, &connections.WindowGate{PerSource: 2, PerTenant: 100})
		for i := 0; i < 2; i++ {
			e.do("GET", e.callbackURL(e.tid.String()+".x", "c"))
		}
		before := len(e.rec.all())
		if w := e.do("GET", e.callbackURL(e.tid.String()+".x", "c")); w.Code != 429 {
			t.Fatalf("third from one source: %d", w.Code)
		}
		if len(e.rec.all()) != before {
			t.Fatal("a limited callback still wrote an audit row")
		}
	})
}
