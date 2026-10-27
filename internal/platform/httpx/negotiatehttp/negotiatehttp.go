// Package negotiatehttp is the HTTP binding of AN-9, GET /auth/negotiate (threat model §7.6, RFC 4559).
// It is not JSON and not in the OpenAPI document; it is a nonApiRoutes row. It reads one Authorization
// header, caps it (rule 6: 64 KiB decoded, 431 above), hands the token to negotiate.Service and, on
// success, sets the pending-sign-in cookie and redirects to the second-factor page. It never creates a
// session.
//
// Every failure after a token was offered is the same 401 with the same body and headers. A request with
// no Authorization header gets the Negotiate challenge, so the browser retries with a ticket; a failure
// does not repeat the challenge, so a browser that cannot do Kerberos falls back to the sign-in page
// instead of looping (NEG-5).
package negotiatehttp

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/negotiate"
	"github.com/skenzeriq/activediq/internal/platform/httpx/authnhttp"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Path is the route.
const Path = "/auth/negotiate"

// maxHeaderBytes bounds the raw Authorization value: "Negotiate " plus the base64 of MaxTokenBytes.
const maxHeaderBytes = len("Negotiate ") + (negotiate.MaxTokenBytes+2)/3*4

// Handler serves AN-9. All fields are required except Log and ClientIP.
type Handler struct {
	Service *negotiate.Service
	// Tenant resolves the tenant from the request (the console hostname binding). false is the generic
	// failure.
	Tenant func(*http.Request) (tenant.ID, bool)
	// ClientIP is the client address as apihost computes it; the zero Addr when unknown.
	ClientIP func(*http.Request) netip.Addr
	// NextPath is where a successful first factor sends the browser: the second-factor page.
	NextPath string
	Log      *slog.Logger
}

// HTTPHandler returns the handler to mount at Path. apihost writes the response (A11).
func (h *Handler) HTTPHandler() http.Handler { return apihost.ServeNonAPI(h.Log, h.decide) }

func failed() apihost.NonAPIResult { return apihost.NonAPIResult{Problem: apitypes.SignInFailed("")} }

func (h *Handler) decide(r *http.Request) apihost.NonAPIResult {
	if r.Method != http.MethodGet {
		return apihost.NonAPIResult{Status: http.StatusMethodNotAllowed, Allow: http.MethodGet}
	}
	vals := r.Header.Values("Authorization")
	if len(vals) == 0 {
		// First leg: ask the browser for a ticket.
		return apihost.NonAPIResult{Problem: apitypes.SignInFailed(""), Challenge: "Negotiate"}
	}
	if len(vals) != 1 {
		return failed()
	}
	v := vals[0]
	if len(v) > maxHeaderBytes {
		return apihost.NonAPIResult{Status: http.StatusRequestHeaderFieldsTooLarge}
	}
	scheme, b64, ok := strings.Cut(v, " ")
	if !ok || !strings.EqualFold(scheme, "Negotiate") {
		return failed() // NTLM, Basic, or anything else: no fallback
	}
	token, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return failed()
	}
	if len(token) > negotiate.MaxTokenBytes {
		return apihost.NonAPIResult{Status: http.StatusRequestHeaderFieldsTooLarge}
	}
	t, ok := h.Tenant(r)
	if !ok {
		return failed()
	}
	var ip netip.Addr
	if h.ClientIP != nil {
		ip = h.ClientIP(r)
	}
	handle, err := h.Service.SignIn(r.Context(), negotiate.Request{Tenant: t, Token: token, ClientIP: ip})
	switch {
	case err == nil:
		return apihost.NonAPIResult{Cookies: []*http.Cookie{authnhttp.PendingCookie(handle)}, Redirect: h.NextPath}
	case errors.Is(err, negotiate.ErrSignInFailed):
		return failed()
	default:
		return apihost.NonAPIResult{Problem: apitypes.Internal("")}
	}
}
