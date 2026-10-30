package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/httpx/authnhttp"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const csrfPath = "/api/v1/auth/csrf"

// getCSRF is GET /auth/csrf with the given cookies and no CSRF header (a GET needs none).
func getCSRF(h http.Handler, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, csrfPath, nil)
	r.RemoteAddr = "203.0.113.7:1"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// post is a mutation on the cookie session with exactly the given CSRF header values.
func (e *chainEnv) post(h http.Handler, tok authn.Token, path string, csrf ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r.AddCookie(authnhttp.SessionCookie(tok, time.Hour))
	for _, v := range csrf {
		r.Header.Add(authnhttp.CSRFHeader, v)
	}
	r.RemoteAddr = "203.0.113.7:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// T-0854 AC1 and AC5: the value GET /auth/csrf hands the console is the one the chain accepts on a
// mutation from the same session, and the answer is never cached.
func TestGetCSRFTokenThroughTheMountedRoutes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := chainSetup(t, s)
		h := e.build(t, e.grant(chainPerm))
		now := time.Now().UTC()
		tok := e.signIn(t, &now)
		start := "/api/v1/connections/" + string(e.conn.ID) + "/takeover-attestation"

		w := getCSRF(h, authnhttp.SessionCookie(tok, time.Hour))
		if w.Code != http.StatusOK {
			t.Fatalf("GET /auth/csrf: %d %s", w.Code, w.Body)
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", cc)
		}
		var out struct{ Header, Value string }
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Header != "X-CSRF-Token" || out.Value == "" {
			t.Fatalf("body = %s", w.Body)
		}
		if strings.Contains(w.Body.String(), tok.Reveal()[37:]) || strings.Contains(w.Header().Get("Set-Cookie"), "adiq") {
			t.Errorf("the response carries the session secret: %s %v", w.Body, w.Header())
		}

		if w := e.post(h, tok, start, out.Value); w.Code != http.StatusOK {
			t.Errorf("POST with the served value: %d %s", w.Code, w.Body)
		}
		if w := e.post(h, tok, start); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "csrf") {
			t.Errorf("POST without the value: %d %s", w.Code, w.Body)
		}
	})
}

// T-0854 AC2: no cookie, a pending-sign-in cookie, a tampered session cookie and a revoked session are
// the same 401, and none of them is given a value.
func TestGetCSRFTokenRefusesWithoutSession(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := chainSetup(t, s)
		h := e.build(t, e.grant(chainPerm))
		now := time.Now().UTC()
		live := e.signIn(t, &now)

		tampered := []byte(live.Reveal())
		if tampered[40] == 'A' {
			tampered[40] = 'B'
		} else {
			tampered[40] = 'A'
		}
		bad, err := authn.ParseToken(string(tampered))
		if err != nil {
			t.Fatal(err)
		}

		gone := e.signIn(t, &now)
		if err := e.sess.Logout(t.Context(), gone); err != nil {
			t.Fatal(err)
		}

		pending := &http.Cookie{Name: authn.PendingCookieName, Value: live.Reveal(), Path: "/"}
		for name, cookies := range map[string][]*http.Cookie{
			"no cookie":       nil,
			"pending cookie":  {pending},
			"tampered":        {authnhttp.SessionCookie(bad, time.Hour)},
			"revoked session": {authnhttp.SessionCookie(gone, time.Hour)},
		} {
			w := getCSRF(h, cookies...)
			if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "/problems/unauthenticated") || strings.Contains(w.Body.String(), `"value"`) {
				t.Errorf("%s: %d %s", name, w.Code, w.Body)
			}
		}
	})
}

// T-0854 AC3: the value of one session is no good with another session's cookie.
func TestCSRFValueIsBoundToTheSession(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := chainSetup(t, s)
		h := e.build(t, e.grant(chainPerm))
		now := time.Now().UTC()
		a, b := e.signIn(t, &now), e.signIn(t, &now)
		start := "/api/v1/connections/" + string(e.conn.ID) + "/takeover-attestation"

		var va, vb struct{ Value string }
		for tok, into := range map[authn.Token]*struct{ Value string }{a: &va, b: &vb} {
			w := getCSRF(h, authnhttp.SessionCookie(tok, time.Hour))
			if w.Code != http.StatusOK {
				t.Fatalf("GET /auth/csrf: %d %s", w.Code, w.Body)
			}
			if err := json.Unmarshal(w.Body.Bytes(), into); err != nil {
				t.Fatal(err)
			}
		}
		if va.Value == vb.Value {
			t.Fatal("two sessions share one CSRF value")
		}
		if w := e.post(h, b, start, va.Value); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "csrf-failed") {
			t.Errorf("A's value with B's cookie: %d %s", w.Code, w.Body)
		}
		if w := e.post(h, b, start, vb.Value); w.Code != http.StatusOK {
			t.Errorf("B's own value: %d %s", w.Code, w.Body)
		}
	})
}
