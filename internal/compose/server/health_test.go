package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

type stubPinger struct{ err error }

func (s stubPinger) Ping(context.Context) error { return s.err }

// get serves one anonymous GET through the composed API handler (apihost over the embedded contract).
func getHealth(t *testing.T, p pinger, log *slog.Logger, path string) *httptest.ResponseRecorder {
	t.Helper()
	h, err := buildAPI(config.Config{APIBodyBudget: config.DefaultAPIBodyBudget}, testLimiter(t), buildHealth(p, log))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// T-0994 AC1: the composed server answers both probes anonymously with {"status":"ok"}.
func TestHealthProbesAreServedAnonymously(t *testing.T) {
	for _, path := range []string{"/api/v1/health/live", "/api/v1/health/ready"} {
		rec := getHealth(t, stubPinger{}, nil, path)
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"status":"ok"}` {
			t.Errorf("%s = %d %q; want 200 {\"status\":\"ok\"}", path, rec.Code, rec.Body.String())
		}
	}
}

// T-0994 AC1: a failing store makes readiness a detail-free 503 problem; the reason is in the log only,
// and liveness does not depend on the store.
func TestHealthReadyFailsWithoutDetailAndLivenessStaysUp(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	failing := stubPinger{errors.New("dial tcp 10.0.0.5:5432: connection refused")}

	rec := getHealth(t, failing, log, "/api/v1/health/ready")
	body := rec.Body.String()
	if rec.Code != http.StatusServiceUnavailable || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatalf("ready = %d %v %q; want a 503 problem", rec.Code, rec.Header(), body)
	}
	if strings.Contains(body, "detail") || strings.Contains(body, "10.0.0.5") || strings.Contains(body, "refused") {
		t.Errorf("the not-ready body leaks detail: %q", body)
	}
	if !strings.Contains(logs.String(), "connection refused") {
		t.Errorf("the failure reason did not reach the log: %q", logs.String())
	}
	if rec := getHealth(t, failing, log, "/api/v1/health/live"); rec.Code != http.StatusOK {
		t.Errorf("live = %d with the store down; want 200", rec.Code)
	}
}

// T-0994: against a real database readiness is 200, and a closed store is not ready.
func TestHealthReadyFollowsTheRealStore(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		if rec := getHealth(t, db, nil, "/api/v1/health/ready"); rec.Code != http.StatusOK {
			t.Fatalf("ready with a live store = %d %q", rec.Code, rec.Body.String())
		}
		db.Close()
		if rec := getHealth(t, db, nil, "/api/v1/health/ready"); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("ready with a closed store = %d %q; want 503", rec.Code, rec.Body.String())
		}
	})
}
