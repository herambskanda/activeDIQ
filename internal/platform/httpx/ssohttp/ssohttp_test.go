package ssohttp_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso/signin"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/signin/signintest"
	"github.com/skenzeriq/activediq/internal/platform/httpx/ssohttp"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var instanceRE = regexp.MustCompile(`"instance":"[^"]*",?`)

func mux(r *signintest.Rig) *http.ServeMux {
	h := &ssohttp.Handler{
		Service:  r.Service,
		Tenant:   func(*http.Request) (tenant.ID, bool) { return signintest.Tenant, true },
		ClientIP: func(*http.Request) netip.Addr { return netip.MustParseAddr("192.0.2.7") },
		NextPath: "/signin/second-factor",
	}
	m := http.NewServeMux()
	m.Handle(ssohttp.StartPattern, h.Start())
	m.Handle(ssohttp.CallbackGet, h.Callback())
	m.Handle(ssohttp.CallbackPost, h.Callback())
	return m
}

func do(m http.Handler, method, target, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	return rec
}

func setCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func start(t *testing.T, m http.Handler) *http.Cookie {
	t.Helper()
	rec := do(m, "GET", "/auth/sso/idp1/start?return=/users", "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	c := setCookie(rec, signin.CookieName)
	if c == nil {
		t.Fatal("no binding cookie")
	}
	return c
}

func TestStartSetsHostCookieAndRedirectsToIdP(t *testing.T) {
	r := signintest.NewRig()
	rec := do(mux(r), "GET", "/auth/sso/idp1/start", "")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "https://idp.example/") {
		t.Fatalf("code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	c := setCookie(rec, signin.CookieName)
	if c == nil || !c.HttpOnly || !c.Secure || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 300 {
		t.Fatalf("cookie = %+v", c)
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Fatalf("cookie name %q", c.Name)
	}
	if strings.Contains(rec.Body.String(), c.Value) || strings.Contains(rec.Header().Get("Location"), c.Value) {
		t.Fatal("the handle appears in the body or the redirect")
	}
}

func TestCallbackPendingGoesToSecondFactor(t *testing.T) {
	r := signintest.NewRig()
	m := mux(r)
	c := start(t, m)
	rec := do(m, "GET", "/auth/sso/idp1/callback?code=c&state=s", "", c)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `/signin/second-factor`) {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	if len(r.Sessions.Created) != 0 || len(r.Pending.Begun) != 1 {
		t.Fatal("a non-MFA IdP must leave only a pending sign-in")
	}
	if setCookie(rec, "__Host-adq-session") != nil && setCookie(rec, "__Host-adq-session").MaxAge > 0 {
		t.Fatal("a session cookie was set for a pending sign-in")
	}
	if cl := setCookie(rec, signin.CookieName); cl == nil || cl.MaxAge >= 0 {
		t.Fatalf("binding cookie not cleared: %+v", cl)
	}
}

func TestCallbackSessionHandsOffToReturnPath(t *testing.T) {
	r := signintest.NewRig()
	r.SetMFA()
	r.Verifier.Out.MFAAsserted = true
	m := mux(r)
	c := start(t, m)
	rec := do(m, "GET", "/auth/sso/idp1/callback?code=c&state=s", "", c)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/users") || len(r.Sessions.Created) != 1 {
		t.Fatalf("code=%d body=%s sessions=%d", rec.Code, rec.Body, len(r.Sessions.Created))
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("a redirect would drop the Strict session cookie; the hand-off page must be used")
	}
}

func TestSAMLPostFormIsTheResponseAndQueryIsIgnored(t *testing.T) {
	r := signintest.NewRig()
	m := mux(r)
	c := start(t, m)
	form := url.Values{"SAMLResponse": {"abc"}, "RelayState": {"x"}}
	rec := do(m, "POST", "/auth/sso/idp1/callback?SAMLResponse=evil", form.Encode(), c)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
}

// SSO-1 over HTTP: no cookie (another browser), a repeated cookie, and the same callback twice all give
// the one generic 401, and none can be told apart from the response.
func TestCallbackRefusalsAreIdentical(t *testing.T) {
	r := signintest.NewRig()
	m := mux(r)
	c := start(t, m)
	good := do(m, "GET", "/auth/sso/idp1/callback?code=c&state=s", "", c)
	if good.Code != http.StatusOK {
		t.Fatalf("first callback = %d", good.Code)
	}
	cases := map[string]*httptest.ResponseRecorder{
		"replay":      do(m, "GET", "/auth/sso/idp1/callback?code=c&state=s", "", c),
		"no cookie":   do(m, "GET", "/auth/sso/idp1/callback?code=c&state=s", ""),
		"two cookies": do(m, "GET", "/auth/sso/idp1/callback?code=c&state=s", "", c, c),
		"unknown idp": do(m, "GET", "/auth/sso/nope/callback?code=c&state=s", "", c),
	}
	var ref string
	for name, rec := range cases {
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: code %d", name, rec.Code)
		}
		if cl := setCookie(rec, signin.CookieName); cl == nil || cl.MaxAge >= 0 {
			t.Fatalf("%s: binding cookie not cleared", name)
		}
		body := rec.Body.String()
		body = instanceRE.ReplaceAllString(body, "") // the instance echoes the request path
		if ref == "" {
			ref = body
		} else if body != ref {
			t.Fatalf("%s: body differs from the others:\n%s\n%s", name, body, ref)
		}
		if strings.Contains(rec.Body.String(), "sso.") {
			t.Fatalf("%s: a reason leaks: %s", name, rec.Body)
		}
	}
}

func TestStartMethodAndIdP(t *testing.T) {
	r := signintest.NewRig()
	m := mux(r)
	if rec := do(m, "GET", "/auth/sso/unknown/start", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown idp start = %d", rec.Code)
	}
	if rec := do(m, "POST", "/auth/sso/idp1/start", "a=b"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST start = %d", rec.Code)
	}
}
