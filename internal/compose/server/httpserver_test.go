package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

func TestAPIServerTimeoutsAreSet(t *testing.T) {
	s := newAPIServer("127.0.0.1:0", http.NotFoundHandler())
	for name, d := range map[string]int64{
		"ReadHeaderTimeout": int64(s.ReadHeaderTimeout), "ReadTimeout": int64(s.ReadTimeout),
		"IdleTimeout": int64(s.IdleTimeout), "MaxHeaderBytes": int64(s.MaxHeaderBytes),
	} {
		if d <= 0 {
			t.Errorf("%s is %d; a zero value means no limit", name, d)
		}
	}
	if s.ReadHeaderTimeout > s.ReadTimeout {
		t.Errorf("ReadHeaderTimeout %v exceeds ReadTimeout %v", s.ReadHeaderTimeout, s.ReadTimeout)
	}
	if s.MaxHeaderBytes >= http.DefaultMaxHeaderBytes*2 {
		t.Errorf("MaxHeaderBytes %d is not a considered cap", s.MaxHeaderBytes)
	}
}

func TestBuildAPIServesApihostBehindNewAPIServer(t *testing.T) {
	h, err := buildAPI(config.Config{APIBodyBudget: config.DefaultAPIBodyBudget})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.(*apihost.Server); !ok {
		t.Fatalf("handler is %T, want *apihost.Server", h)
	}
	srv := newAPIServer("127.0.0.1:0", h)
	if srv.Handler != h || srv.ReadHeaderTimeout <= 0 {
		t.Fatal("the listener must be newAPIServer around apihost's handler")
	}
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/nothing", nil))
	if rec.Code != http.StatusNotFound || rec.Header().Get("X-Trace-Id") == "" ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatalf("got %d %v; want an apihost problem with a trace id", rec.Code, rec.Header())
	}
}

func TestBuildAPIRejectsNonPositiveBodyBudget(t *testing.T) {
	for _, n := range []int64{0, -1} {
		if _, err := buildAPI(config.Config{APIBodyBudget: n}); err == nil {
			t.Errorf("budget %d must fail startup", n)
		}
		err := Run(context.Background(), config.Config{DatabaseDSN: "postgres://unused", APIBodyBudget: n})
		if err == nil || errors.Is(err, ErrNoDatabase) {
			t.Errorf("Run with budget %d = %v; want a build failure before the database is touched", n, err)
		}
	}
}
