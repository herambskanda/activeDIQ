package apihost

import (
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
	// Redirect, when set and Problem is nil, answers 303 See Other to this relative path.
	Redirect string
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
		default:
			w.Header().Set("Cache-Control", "no-store")
			if res.Allow != "" {
				w.Header().Set("Allow", res.Allow)
			}
			w.WriteHeader(res.Status)
		}
	})
}
