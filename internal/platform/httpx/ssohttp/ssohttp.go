// Package ssohttp is the HTTP binding of AN-3, GET /auth/sso/{idpId}/start and GET|POST
// /auth/sso/{idpId}/callback (console-sso.md section 3). These are nonApiRoutes rows: redirects and form
// posts, not JSON. The binding reads the path's idpId, the browser-binding cookie and the IdP's return,
// hands them to signin.Service, and turns the outcome into cookies and a same-origin hand-off page.
//
// Every refusal is the same 401 problem with the same status and body shape, so no reason can be read
// from the response (X-13). A refusal also clears the binding cookie.
package ssohttp

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/signin"
	"github.com/skenzeriq/activediq/internal/platform/httpx/authnhttp"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Route patterns, for the mux that serves them (Go 1.22 patterns; the idpId is r.PathValue("idpId")).
const (
	StartPattern    = "GET /auth/sso/{idpId}/start"
	CallbackGet     = "GET /auth/sso/{idpId}/callback"
	CallbackPost    = "POST /auth/sso/{idpId}/callback"
	idpPathValue    = "idpId"
	maxFormBytes    = 320 << 10 // a SAML response field is capped at 256 KiB by the verifier; this is the wire bound
	maxIdPIDLen     = 256
	returnQueryName = "return"
)

// Handler serves AN-3. All fields are required except Log and ClientIP.
type Handler struct {
	Service *signin.Service
	// Tenant resolves the tenant from the request (the console hostname binding). false is the generic failure.
	Tenant func(*http.Request) (tenant.ID, bool)
	// ClientIP is the client address as apihost computes it; the zero Addr when unknown.
	ClientIP func(*http.Request) netip.Addr
	// NextPath is where a pending sign-in goes: the second-factor page.
	NextPath string
	Log      *slog.Logger
}

// Start returns the handler for StartPattern.
func (h *Handler) Start() http.Handler { return apihost.ServeNonAPI(h.Log, h.start) }

// Callback returns the handler for CallbackGet and CallbackPost.
func (h *Handler) Callback() http.Handler { return apihost.ServeNonAPI(h.Log, h.callback) }

func failed(clear bool) apihost.NonAPIResult {
	res := apihost.NonAPIResult{Problem: apitypes.SignInFailed("")}
	if clear {
		res.Cookies = []*http.Cookie{clearCookie()}
	}
	return res
}

func internal() apihost.NonAPIResult { return apihost.NonAPIResult{Problem: apitypes.Internal("")} }

func (h *Handler) ip(r *http.Request) netip.Addr {
	if h.ClientIP != nil {
		return h.ClientIP(r)
	}
	return netip.Addr{}
}

func idpID(r *http.Request) (string, bool) {
	id := r.PathValue(idpPathValue)
	return id, id != "" && len(id) <= maxIdPIDLen
}

func (h *Handler) start(r *http.Request) apihost.NonAPIResult {
	if r.Method != http.MethodGet {
		return apihost.NonAPIResult{Status: http.StatusMethodNotAllowed, Allow: http.MethodGet}
	}
	id, ok := idpID(r)
	t, tok := h.Tenant(r)
	if !ok || !tok {
		return failed(false)
	}
	// The return path comes from the start request only, and the service reduces anything that is not a
	// console route to the root. Several values are treated as none.
	ret := ""
	if v := r.URL.Query()[returnQueryName]; len(v) == 1 {
		ret = v[0]
	}
	res, err := h.Service.Start(r.Context(), signin.StartRequest{Tenant: t, IdPID: id, ReturnPath: ret, ClientIP: h.ip(r)})
	switch {
	case err == nil:
		return apihost.NonAPIResult{Cookies: []*http.Cookie{bindingCookie(res)}, Redirect: res.Redirect.String()}
	case errors.Is(err, signin.ErrSignInFailed):
		return failed(false)
	default:
		h.logErr(r, err)
		return internal()
	}
}

func (h *Handler) callback(r *http.Request) apihost.NonAPIResult {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return apihost.NonAPIResult{Status: http.StatusMethodNotAllowed, Allow: "GET, POST"}
	}
	id, ok := idpID(r)
	t, tok := h.Tenant(r)
	if !ok || !tok {
		return failed(true)
	}
	cb := sso.Callback{IdPID: id}
	if r.Method == http.MethodGet {
		cb.Query = r.URL.Query()
	} else {
		r.Body = http.MaxBytesReader(nil, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			return failed(true)
		}
		cb.Form = r.PostForm // the body only; a query string on the POST is not part of the response
	}
	res, err := h.Service.Callback(r.Context(), signin.CallbackRequest{
		Tenant: t, IdPID: id, Cookie: cookieValue(r), Callback: cb, ClientIP: h.ip(r)})
	switch {
	case err == nil:
	case errors.Is(err, signin.ErrSignInFailed):
		return failed(true)
	default:
		h.logErr(r, err)
		res := internal()
		res.Cookies = []*http.Cookie{clearCookie()}
		return res
	}
	switch res.Kind {
	case signin.ResultSession:
		return apihost.NonAPIResult{
			Cookies: []*http.Cookie{
				authnhttp.SessionCookie(res.Session.Token, time.Until(res.Session.Session.AbsoluteExpiry)),
				authnhttp.ClearPendingCookie(), clearCookie()},
			Handoff: res.ReturnPath,
		}
	case signin.ResultPending:
		return apihost.NonAPIResult{
			Cookies: []*http.Cookie{authnhttp.PendingCookie(res.Pending), clearCookie()},
			Handoff: h.NextPath,
		}
	}
	return internal()
}

func (h *Handler) logErr(r *http.Request, err error) {
	if h.Log != nil {
		h.Log.ErrorContext(r.Context(), "sso route failed", "path", r.URL.Path, "trace_id", apihost.TraceID(r.Context()), "error", err)
	}
}

// cookieValue returns the one binding cookie's value, or "" when it is absent or repeated: with several,
// which one the browser meant is not knowable.
func cookieValue(r *http.Request) string {
	var found *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name != signin.CookieName {
			continue
		}
		if found != nil {
			return ""
		}
		found = c
	}
	if found == nil {
		return ""
	}
	return found.Value
}

// bindingCookie hands the Transaction handle to the browser: __Host-, HttpOnly, Secure, Path=/, no
// Domain, five minutes. SameSite is Lax for OIDC (the return is a top-level GET) and None for SAML (the
// ACS is a cross-site POST, which a Lax or Strict cookie does not reach). It authorises one Complete only.
func bindingCookie(r signin.StartResult) *http.Cookie {
	ss := http.SameSiteLaxMode
	if r.Protocol == sso.ProtocolSAML {
		ss = http.SameSiteNoneMode
	}
	return &http.Cookie{Name: signin.CookieName, Value: r.Handle.Reveal(), Path: "/",
		MaxAge: int(signin.TransactionTTL / time.Second), Secure: true, HttpOnly: true, SameSite: ss}
}

// clearCookie drops the binding cookie. SameSite=None so the browser accepts the deletion on a response
// to a cross-site POST whichever mode the cookie was set with.
func clearCookie() *http.Cookie {
	return &http.Cookie{Name: signin.CookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode}
}
