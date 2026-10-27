package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Unconfigured, the attestation is not offered: no tag, so its routes answer a problem.
func Test_attestation_unmounted_without_config(t *testing.T) {
	tags, err := buildAttestation(config.Config{}, nil, nil, nil)
	if err != nil || len(tags) != 0 {
		t.Fatalf("tags %d err %v", len(tags), err)
	}
}

// Mounted, the callback is reachable without a session (it is the one anonymous route) and the two
// authenticated routes stay behind the fail-closed ports.
func Test_attestation_routes_with_fail_closed_ports(t *testing.T) {
	cfg := config.Config{APIBodyBudget: config.DefaultAPIBodyBudget, AttestClientID: "app", PublicURL: "https://diq.example.com/"}
	tags, err := buildAttestation(cfg, nil, nopSink{}, nil)
	if err != nil || len(tags) != 1 {
		t.Fatalf("tags %d err %v", len(tags), err)
	}
	h, err := buildAPI(cfg, testLimiter(t), tags...)
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]int{
		"POST /api/v1/connections/850bdd5e-ceb9-4b22-8cd6-084a2b7d906a/takeover-attestation":        401,
		"PUT /api/v1/connections/850bdd5e-ceb9-4b22-8cd6-084a2b7d906a/takeover-attestation/max-age": 401,
	} {
		method, path, _ := splitOnce(target)
		w := httptest.NewRecorder()
		var body io.Reader
		if method == "PUT" {
			body = strings.NewReader(`{"maxAgeSeconds":3600}`)
		}
		r := httptest.NewRequest(method, path, body)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		r.RemoteAddr = "203.0.113.7:1"
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s: %d want %d", target, w.Code, want)
		}
	}
	// A callback with an unusable state is the fixed failure redirect, never an error page. It needs a
	// database for a real state, so only the stateless refusal is driven here.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/connections/takeover-attestation/callback?state=nonsense&code=x", nil)
	r.RemoteAddr = "203.0.113.7:1"
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") == "" {
		t.Fatalf("callback: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func splitOnce(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

type nopSink struct{}

func (nopSink) Append(context.Context, store.Tx, audit.Event) error { return nil }
