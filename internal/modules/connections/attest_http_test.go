package connections_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// microsoft plays login.microsoftonline.com and graph.microsoft.com on one TLS server. It checks what the
// real services check: the PKCE verifier against the challenge the start sent, and the bearer on the read.
type microsoft struct {
	srv        *httptest.Server
	mu         sync.Mutex
	challenge  string
	tokenCalls int
	graphCalls int
	issued     string
	hard, soft bool
}

func newMicrosoft(t *testing.T) *microsoft {
	t.Helper()
	m := &microsoft{hard: true, soft: true}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /"+entraTenantID+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
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
		m.issued = enc(map[string]string{"alg": "RS256"}) + "." + enc(map[string]any{"tid": entraTenantID, "oid": gaOID,
			"iss": "https://login.microsoftonline.com/" + entraTenantID + "/v2.0", "aud": "00000003-0000-0000-c000-000000000000",
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

// sessionPorts: one console session principal, everything allowed, so the test exercises the handlers
// and the Attester's own checks rather than the (separately tested) ports.
type sessionPorts struct{ p apihost.Principal }

func (s sessionPorts) Authenticate(*http.Request) (apihost.Principal, error) { return s.p, nil }
func (sessionPorts) CheckCSRF(*http.Request, apihost.Principal) error        { return nil }
func (sessionPorts) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (sessionPorts) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (sessionPorts) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (sessionPorts) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

type httpEnv struct {
	*attestEnv
	ms  *microsoft
	api http.Handler
}

func newHTTPEnv(t *testing.T, s *storetest.Server, gate connections.CallbackGate) *httpEnv {
	t.Helper()
	e := newAttestEnv(t, s)
	ms := newMicrosoft(t)
	at, err := connections.NewAttester(connections.AttestConfig{
		DB: e.db, Audit: e.rec, Authz: attestAuthz{"admin": true}, StepUp: stepUp{fresh: true},
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
	sp := sessionPorts{p: apihost.Principal{ID: "admin", Tenant: e.tid.String(), Kind: apihost.KindSession, SessionID: "sess"}}
	srv, err := apihost.Build(doc, []apihost.TagHandlers{h.Bind()}, pol, apihost.Permissions{"connections.takeover.attest", "siem.destination.manage", "siem.destination.read", "directory.read"},
		apihost.Ports{Authn: sp, Authz: sp, Limits: sp, StepUp: sp})
	if err != nil {
		t.Fatal(err)
	}
	return &httpEnv{attestEnv: e, ms: ms, api: srv}
}

func (e *httpEnv) do(method, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, r)
	return w
}

// begin runs POST start and returns the state the browser would carry back, having told the fake
// Microsoft the challenge it must see verified.
func (e *httpEnv) begin(t *testing.T) string {
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
	state, q := stateOf(t, body.AuthorizeURL)
	e.ms.mu.Lock()
	e.ms.challenge = q.Get("code_challenge")
	e.ms.mu.Unlock()
	if q.Get("code_challenge_method") != "S256" || !strings.HasPrefix(body.AuthorizeURL, e.ms.srv.URL+"/"+entraTenantID+"/oauth2/v2.0/authorize") {
		t.Fatalf("authorize url %q", body.AuthorizeURL)
	}
	return state
}

func (e *httpEnv) callbackURL(state, code string) string {
	return "/api/v1/connections/takeover-attestation/callback?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code)
}

// Acceptance 1: start and callback over HTTP against the real adapters record the attestation and
// persist nothing but the DM-10.I7 columns.
func TestAttestOverHTTPWithRealAdapters(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newHTTPEnv(t, s, &connections.WindowGate{})
		state := e.begin(t)
		w := e.do("GET", e.callbackURL(state, "ms-code"))
		if w.Code != 303 || w.Header().Get("Location") != connections.AttestRecordedLocation {
			t.Fatalf("callback: %d %q", w.Code, w.Header().Get("Location"))
		}
		tk := e.takeover(t)
		if tk.State != connection.TakeoverAttested || tk.Record.Attestation == nil || tk.Record.Attestation.By != gaOID {
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
		e := newHTTPEnv(t, s, &connections.WindowGate{})
		state := e.begin(t)
		for name, target := range map[string]string{
			"wrong code":     e.callbackURL(state, "other"),
			"idp error":      "/api/v1/connections/takeover-attestation/callback?state=" + url.QueryEscape(state) + "&error=access_denied",
			"no tenant":      e.callbackURL("nonsense", "ms-code"),
			"foreign tenant": e.callbackURL(otherTenantID+".abc", "ms-code"),
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
		e := newHTTPEnv(t, s, &connections.WindowGate{PerSource: 2, PerTenant: 100})
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

func TestWindowGate(t *testing.T) {
	now := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	g := &connections.WindowGate{PerSource: 1, PerTenant: 1, MaxKeys: 1, Now: func() time.Time { return now }}
	if !g.AllowSource("2001:db8::1") || g.AllowSource("2001:db8::ffff") {
		t.Fatal("IPv6 sources in one /64 share a bucket")
	}
	if g.AllowSource("198.51.100.1") && g.AllowSource("198.51.100.2") {
		t.Fatal("overflow keys must share one bucket")
	}
	now = now.Add(2 * time.Minute)
	if !g.AllowSource("2001:db8::1") {
		t.Fatal("a new window starts empty")
	}
}

func TestStateTenant(t *testing.T) {
	id, err := tenant.Parse(entraTenantID)
	if err != nil {
		t.Fatal(err)
	}
	for state, want := range map[string]bool{entraTenantID + ".abc": true, entraTenantID: false, ".abc": false,
		"zz.abc": false, "00000000-0000-0000-0000-000000000000.abc": false, "": false} {
		got, ok := connections.StateTenant(state)
		if ok != want || (ok && got != id) {
			t.Fatalf("%q: %v %v", state, got, ok)
		}
	}
}
