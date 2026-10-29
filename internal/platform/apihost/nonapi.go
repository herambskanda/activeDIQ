package apihost

import (
	"html"
	"log/slog"
	"net/http"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// NonAPIResult is what a route outside the OpenAPI document (a nonApiRoutes row: AN-3 callbacks, AN-9
// negotiate) decides. Only apihost writes status codes and errors (ADR-0004 rule 8, A11), so such a
// route returns this and ServeNonAPI renders it.
type NonAPIResult struct {
	// Problem, when set, is rendered as application/problem+json with its own status.
	Problem *apitypes.Problem
	// Challenge replaces the default "WWW-Authenticate: Bearer" on a 401 problem (HTTP Negotiate).
	Challenge string
	// Redirect, when set and Problem is nil, answers 303 See Other to this location: a relative path, or
	// the absolute IdP URL of an SSO start.
	Redirect string
	// Handoff, when set and Problem and Redirect are nil, answers a small same-origin page that navigates
	// to this relative path with a meta refresh (no script, CSP unchanged). A cookie set on the response
	// to a cross-site request (the SAML ACS POST, the OIDC return) is not sent with a redirect that
	// follows it, because the chain began cross-site; the navigation the page makes is same-site, so the
	// SameSite=Strict session cookie goes with it (console-sso.md section 3).
	Handoff string
	// Status, with no Problem and no Redirect, answers a bodyless status (for example 431).
	Status int
	// Cookies are added as Set-Cookie lines.
	Cookies []*http.Cookie
	// Allow is the Allow header of a 405.
	Allow string
}

// ServeNonAPI adapts a decision function to an http.Handler. fn must not write to the response.
func ServeNonAPI(log *slog.Logger, fn func(*http.Request) NonAPIResult) http.Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := fn(r)
		for _, c := range res.Cookies {
			http.SetCookie(w, c)
		}
		switch {
		case res.Problem != nil:
			ch := res.Challenge
			if ch == "" {
				ch = "Bearer"
			}
			writeProblemChallenge(w, r, res.Problem, log, ch)
		case res.Redirect != "":
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, res.Redirect, http.StatusSeeOther)
		case res.Handoff != "":
			writeHandoff(w, res.Handoff)
		default:
			w.Header().Set("Cache-Control", "no-store")
			if res.Allow != "" {
				w.Header().Set("Allow", res.Allow)
			}
			w.WriteHeader(res.Status)
		}
	})
}

// writeHandoff writes the navigation page. to is a relative console path chosen by the server; it is
// escaped for the attribute all the same.
func writeHandoff(w http.ResponseWriter, to string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url=" +
		html.EscapeString(to) + "\"><title>Signing in</title></head><body><p>Signing in&hellip;</p></body></html>"))
}
