package syslog

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ports authenticates one principal and allows ManagePermission only when allow is set, as the RBAC
// port does for a caller without the SIEM-admin permission.
type ports struct {
	p     apihost.Principal
	allow bool
}

func (x ports) Authenticate(*http.Request) (apihost.Principal, error) { return x.p, nil }
func (ports) CheckCSRF(*http.Request, apihost.Principal) error        { return nil }
func (x ports) Allow(_ context.Context, _ apihost.Principal, perm, _ string) (bool, error) {
	return x.allow && perm == ManagePermission, nil
}
func (ports) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

func newAPI(t *testing.T, s *Store, ten tenant.ID, allow bool) http.Handler {
	t.Helper()
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	px := ports{p: apihost.Principal{ID: "admin", Tenant: ten.String(), Kind: apihost.KindSession, SessionID: "s"}, allow: allow}
	srv, err := apihost.Build(doc, []apihost.TagHandlers{Handlers{Store: s}.Bind()}, pol, apihost.Permissions{ManagePermission, "connections.takeover.attest"},
		apihost.Ports{Authn: px, Authz: px, Limits: px, StepUp: px})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func call(h http.Handler, method, path, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v1"+path, bytes.NewReader([]byte(body)))
	r.RemoteAddr = "203.0.113.7:4444"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func destCount(t *testing.T, s *Store, ten tenant.ID) int {
	t.Helper()
	vs, err := s.List(context.Background(), ten)
	if err != nil {
		t.Fatal(err)
	}
	return len(vs)
}

// Acceptance 1: the contract has create, update, get and list; a response carries the View and nothing
// a client could take for a secret. Acceptance 3: there is no delete route.
func TestRoutesAndViewShape(t *testing.T) {
	each(t, func(t *testing.T, s *Store, ten tenant.ID, snk *sink, _ *store.DB) {
		h := newAPI(t, s, ten, true)
		w := call(h, "POST", "/notify/siem-destinations", "req-000001", `{"host":"siem.example.com"}`)
		if w.Code != 201 {
			t.Fatalf("create: %d %s", w.Code, w.Body)
		}
		var v map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		if len(v) != 6 || v["transport"] != "tls" || v["tlsVerified"] != true || v["port"] != float64(6514) || v["plaintextOptIn"] != false {
			t.Fatalf("view = %v", v)
		}
		id := v["id"].(string)
		if w := call(h, "GET", "/notify/siem-destinations/"+id, "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), id) {
			t.Fatalf("get: %d %s", w.Code, w.Body)
		}
		if w := call(h, "GET", "/notify/siem-destinations", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"items"`) {
			t.Fatalf("list: %d %s", w.Code, w.Body)
		}
		w = call(h, "PUT", "/notify/siem-destinations/"+id, "req-000002", `{"host":"siem2.example.com","transport":"tcp","plaintextOptIn":true}`)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"warning"`) || !strings.Contains(w.Body.String(), `"tlsVerified":false`) {
			t.Fatalf("update: %d %s", w.Code, w.Body)
		}
		if w := call(h, "DELETE", "/notify/siem-destinations/"+id, "req-000003", ""); w.Code != 404 && w.Code != 405 {
			t.Fatalf("delete answered %d: there must be no delete route", w.Code)
		}
		if destCount(t, s, ten) != 1 {
			t.Fatal("delete removed or duplicated a destination")
		}
		// The request ID reached the store as the audit key, with the caller's chain.
		var seen bool
		for _, ev := range snk.evs {
			if strings.HasSuffix(ev.ID, ".req-000002") && ev.Actor.Requester.ID == "admin" {
				seen = true
			}
		}
		if !seen {
			t.Fatalf("no audit event keyed by the Idempotency-Key: %v", snk.evs)
		}
	})
}

// Acceptance 2: without the permission every route answers 403 and nothing is written.
func TestWithoutPermissionEveryRouteIs403AndWritesNothing(t *testing.T) {
	each(t, func(t *testing.T, s *Store, ten tenant.ID, snk *sink, _ *store.DB) {
		v, err := s.Create(context.Background(), ten, Spec{Host: "keep.example.com"}, human, "seed-0001")
		if err != nil {
			t.Fatal(err)
		}
		before := len(snk.evs)
		h := newAPI(t, s, ten, false)
		for _, c := range []struct{ m, p, k, b string }{
			{"GET", "/notify/siem-destinations", "", ""},
			{"POST", "/notify/siem-destinations", "req-000001", `{"host":"evil.example.com"}`},
			{"GET", "/notify/siem-destinations/" + v.ID, "", ""},
			{"PUT", "/notify/siem-destinations/" + v.ID, "req-000002", `{"host":"evil.example.com"}`},
		} {
			if w := call(h, c.m, c.p, c.k, c.b); w.Code != 403 {
				t.Fatalf("%s %s: %d %s", c.m, c.p, w.Code, w.Body)
			}
		}
		got, err := s.Get(context.Background(), ten, v.ID)
		if err != nil || got.Host != "keep.example.com" || destCount(t, s, ten) != 1 || len(snk.evs) != before {
			t.Fatalf("a refused call changed state: %+v %v events %d→%d", got, err, before, len(snk.evs))
		}
	})
}

// Acceptance 4: a retried create with the same request ID leaves one destination and one created event.
func TestRetriedCreateIsIdempotent(t *testing.T) {
	each(t, func(t *testing.T, s *Store, ten tenant.ID, snk *sink, _ *store.DB) {
		h := newAPI(t, s, ten, true)
		a := call(h, "POST", "/notify/siem-destinations", "req-retry-1", `{"host":"siem.example.com"}`)
		b := call(h, "POST", "/notify/siem-destinations", "req-retry-1", `{"host":"siem.example.com"}`)
		if a.Code != 201 || b.Code != 201 || a.Body.String() != b.Body.String() {
			t.Fatalf("first %d %s, retry %d %s", a.Code, a.Body, b.Code, b.Body)
		}
		if n := destCount(t, s, ten); n != 1 || len(snk.evs) != 1 {
			t.Fatalf("destinations %d, events %d: want 1 and 1", n, len(snk.evs))
		}
		// Same key, different body: refused, nothing changes.
		c := call(h, "POST", "/notify/siem-destinations", "req-retry-1", `{"host":"other.example.com"}`)
		if c.Code != 422 || destCount(t, s, ten) != 1 {
			t.Fatalf("reuse with another body: %d %s", c.Code, c.Body)
		}
		// A different key makes a second destination.
		if d := call(h, "POST", "/notify/siem-destinations", "req-retry-2", `{"host":"siem.example.com"}`); d.Code != 201 || destCount(t, s, ten) != 2 {
			t.Fatalf("new key: %d", d.Code)
		}
	})
}

// Refusals are problems without store text; another tenant's destination is a 404.
func TestRefusalsAndTenantIsolation(t *testing.T) {
	each(t, func(t *testing.T, s *Store, ten tenant.ID, _ *sink, _ *store.DB) {
		h := newAPI(t, s, ten, true)
		if w := call(h, "POST", "/notify/siem-destinations", "req-000001", `{"host":"a.example.com","transport":"tcp"}`); w.Code != 400 {
			t.Fatalf("plaintext without opt-in: %d %s", w.Code, w.Body)
		}
		if w := call(h, "POST", "/notify/siem-destinations", "req-000001", `{"host":"ldap://x"}`); w.Code != 400 {
			t.Fatalf("bad host: %d", w.Code)
		}
		if w := call(h, "POST", "/notify/siem-destinations", "", `{"host":"a.example.com"}`); w.Code != 400 {
			t.Fatalf("missing key: %d", w.Code)
		}
		if w := call(h, "POST", "/notify/siem-destinations", "req-000001", `{"host":"a.example.com","password":"x"}`); w.Code != 400 {
			t.Fatalf("unknown member: %d", w.Code)
		}
		v, err := s.Create(context.Background(), other, Spec{Host: "theirs.example.com"}, human, "seed-0002")
		if err != nil {
			t.Fatal(err)
		}
		if w := call(h, "GET", "/notify/siem-destinations/"+v.ID, "", ""); w.Code != 404 {
			t.Fatalf("cross-tenant get: %d", w.Code)
		}
		if w := call(h, "PUT", "/notify/siem-destinations/"+v.ID, "req-000009", `{"host":"x.example.com"}`); w.Code != 404 {
			t.Fatalf("cross-tenant put: %d", w.Code)
		}
	})
}
