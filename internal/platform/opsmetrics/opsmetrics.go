// Package opsmetrics serves the operator metrics endpoint (T-0533).
//
// The series list every tenant ID and per-tenant activity, so in SaaS they are cross-tenant
// information. The endpoint therefore lives on its own ops listener, never on the API listener, and
// accepts exactly one credential: the operator bearer token configured for that listener. A tenant
// session cookie or a tenant API key is a different credential and gets 401; there is no code path
// from the tenant authenticators to this handler.
package opsmetrics

import (
	"bytes"
	"io"
	"net/http"

	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// Path is the only route of the ops listener.
const Path = "/metrics"

// MinTokenBytes is the shortest accepted operator token (256 bits when generated from a CSPRNG).
const MinTokenBytes = 32

// Source writes the metrics in Prometheus text exposition format.
type Source func(w io.Writer) error

// Handler returns the ops listener's handler. token is the operator credential, compared in constant
// time; an empty token makes every request fail (an unset credential never authenticates).
func Handler(token secret.Secret, src Source) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Path, func(w http.ResponseWriter, r *http.Request) {
		if !authorised(token, r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="activediq-ops"`)
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		// Render fully first so a failing source yields a clean 500, not a truncated 200.
		var buf bytes.Buffer
		if err := src(&buf); err != nil {
			http.Error(w, "metrics unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(buf.Bytes())
	})
	return mux
}

func authorised(token secret.Secret, r *http.Request) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return false
	}
	got := secret.FromBytes([]byte(h[len(prefix):]))
	defer got.Destroy()
	return token.Equal(got)
}
