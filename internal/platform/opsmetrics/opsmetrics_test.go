package opsmetrics_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/opsmetrics"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const opsToken = "ops-token-0123456789abcdef0123456789abcdef"

func serve(t *testing.T, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	h := opsmetrics.Handler(secret.FromBytes([]byte(opsToken)), keys.WriteMetrics)
	r := httptest.NewRequest(http.MethodGet, opsmetrics.Path, nil)
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// T-0533 AC1: a tenant session or tenant API key (anything but the ops credential) gets 401.
func TestTenantCredentialsRefused(t *testing.T) {
	cases := map[string]func(*http.Request){
		"no credential":  nil,
		"tenant session": func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "diq_session", Value: "sess-abc"}) },
		"tenant api key": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer diq_tenantkey_0123456789abcdef0123456789")
		},
		"api key header":    func(r *http.Request) { r.Header.Set("X-API-Key", opsToken) },
		"basic with token":  func(r *http.Request) { r.Header.Set("Authorization", "Basic "+opsToken) },
		"empty bearer":      func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"token prefix only": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+opsToken[:10]) },
		"token plus suffix": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+opsToken+"x") },
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			w := serve(t, m)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			if strings.Contains(w.Body.String(), "activediq_") {
				t.Fatal("metrics leaked to an unauthenticated caller")
			}
		})
	}
}

func TestEmptyTokenNeverAuthenticates(t *testing.T) {
	h := opsmetrics.Handler(secret.Secret{}, keys.WriteMetrics)
	r := httptest.NewRequest(http.MethodGet, opsmetrics.Path, nil)
	r.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestOnlyGetMetricsRoute(t *testing.T) {
	h := opsmetrics.Handler(secret.FromBytes([]byte(opsToken)), keys.WriteMetrics)
	for _, c := range []struct{ method, path string }{{"POST", "/metrics"}, {"GET", "/api/v1/users"}, {"GET", "/health/live"}} {
		r := httptest.NewRequest(c.method, c.path, nil)
		r.Header.Set("Authorization", "Bearer "+opsToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusOK {
			t.Fatalf("%s %s served 200", c.method, c.path)
		}
	}
}

// T-0533 AC2: with the ops credential the unwrap counter is present with tenant and outcome labels only.
func TestOpsScrapeHasUnwrapCounter(t *testing.T) {
	p := keystest.New("key-1")
	ta := tenant.New()
	dek, _ := keys.NewDEK(2)
	wrapped, ref, err := keys.WrapDEK(p, ta, dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.UnwrapDEK(p, ta, 2, ref, wrapped); err != nil {
		t.Fatal(err)
	}
	w := serve(t, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+opsToken) })
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	want := `activediq_keys_dek_unwraps_total{tenant="` + ta.String() + `",outcome="success"}`
	if !strings.Contains(w.Body.String(), want) {
		t.Fatalf("missing %s in:\n%s", want, w.Body)
	}
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if strings.HasPrefix(line, keys.UnwrapMetricName+"{") {
			labels := line[strings.Index(line, "{")+1 : strings.Index(line, "}")]
			if strings.Count(labels, "=") != 2 || !strings.HasPrefix(labels, "tenant=") || !strings.Contains(labels, ",outcome=") {
				t.Fatalf("labels beyond tenant and outcome: %s", line)
			}
		}
	}
	if strings.Contains(w.Body.String(), ref.KeyID) {
		t.Fatal("key id leaked")
	}
}

func TestFailingSourceIs500NoPartialBody(t *testing.T) {
	h := opsmetrics.Handler(secret.FromBytes([]byte(opsToken)), func(w io.Writer) error {
		_, _ = w.Write([]byte("partial"))
		return errors.New("boom secret-detail")
	})
	r := httptest.NewRequest(http.MethodGet, opsmetrics.Path, nil)
	r.Header.Set("Authorization", "Bearer "+opsToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "partial") || strings.Contains(w.Body.String(), "secret-detail") {
		t.Fatalf("status %d body %q", w.Code, w.Body)
	}
}
