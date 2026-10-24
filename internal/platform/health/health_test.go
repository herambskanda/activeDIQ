package health_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/health"
	"github.com/skenzeriq/activediq/internal/platform/health/api"
)

type ports struct{}

func (ports) Authenticate(*http.Request) (apihost.Principal, error) {
	return apihost.Principal{}, apihost.ErrUnauthenticated
}
func (ports) CheckCSRF(*http.Request, apihost.Principal) error { return nil }
func (ports) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return false, nil
}
func (ports) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true, RetryAfter: time.Second}, nil
}
func (ports) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) Fresh(context.Context, apihost.Principal) (bool, error) { return false, nil }

func serve(t *testing.T, logbuf *bytes.Buffer, checks ...health.NamedCheck) *apihost.Server {
	t.Helper()
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(logbuf, nil))
	return build(t, doc, policy, log, api.Handlers(health.New(log, checks...)))
}

func build(t *testing.T, doc apihost.Document, policy apihost.Policy, log *slog.Logger, h api.Handlers) *apihost.Server {
	t.Helper()
	s, err := apihost.Build(doc, []apihost.TagHandlers{api.Bind(h)}, policy, apihost.Permissions{}, apihost.Ports{Authn: ports{}, Authz: ports{}, Limits: ports{}, StepUp: ports{}}, apihost.WithLogger(log))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return s
}

func call(s *apihost.Server, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/api/v1"+path, nil)
	r.RemoteAddr = "192.0.2.7:4000"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	return rec
}

func members(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, rec.Body)
	}
	return m
}

func TestHealthProblemsCarryNoDetail(t *testing.T) {
	const host, version = "dc01.corp.example.net:636", "PostgreSQL 16.4.2"
	var logs bytes.Buffer
	failing := health.NamedCheck{Name: "database", Check: func(context.Context) error {
		return errors.New("dial " + host + ": connection refused (server " + version + ")")
	}}

	t.Run("200 body is exactly status ok", func(t *testing.T) {
		s := serve(t, &logs)
		for _, p := range []string{"/health/live", "/health/ready"} {
			rec := call(s, p)
			if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"status":"ok"}` {
				t.Fatalf("%s = %d %q", p, rec.Code, rec.Body)
			}
		}
	})

	t.Run("failing dependency is a 503 without detail", func(t *testing.T) {
		logs.Reset()
		rec := call(serve(t, &logs, failing), "/health/ready")
		if rec.Code != 503 {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
		}
		m := members(t, rec)
		if _, has := m["detail"]; has {
			t.Fatalf("problem carries a detail: %s", rec.Body)
		}
		if m["type"] != "/problems/not-ready" {
			t.Fatalf("type = %v", m["type"])
		}
		for _, leak := range []string{host, version, "dc01", "database", "refused", "dial"} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Fatalf("body leaks %q: %s", leak, rec.Body)
			}
		}
		for k, v := range rec.Header() {
			if strings.Contains(strings.Join(v, ","), "dc01") {
				t.Fatalf("header %s leaks the host", k)
			}
		}
		if !strings.Contains(logs.String(), host) {
			t.Fatalf("the failure cause did not reach the log: %s", logs.String())
		}
	})

	t.Run("a panicking check is a 500 without detail", func(t *testing.T) {
		logs.Reset()
		boom := health.NamedCheck{Name: "database", Check: func(context.Context) error { panic("secret " + host + " " + version) }}
		for _, p := range []string{"/health/ready"} {
			rec := call(serve(t, &logs, boom), p)
			if rec.Code != 500 {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
			}
			m := members(t, rec)
			if _, has := m["detail"]; has || m["type"] != "/problems/internal" {
				t.Fatalf("problem = %s", rec.Body)
			}
			if strings.Contains(rec.Body.String(), host) || strings.Contains(rec.Body.String(), version) || strings.Contains(rec.Body.String(), "secret") {
				t.Fatalf("body leaks: %s", rec.Body)
			}
		}
	})
}

// erroring is a Handlers whose every operation fails with an error full of internals.
type erroring struct{ err error }

func (e erroring) GetLiveness(context.Context, api.GetLivenessInput) (api.GetLivenessOutput, error) {
	return nil, e.err
}
func (e erroring) GetReadiness(context.Context, api.GetReadinessInput) (api.GetReadinessOutput, error) {
	return nil, e.err
}

func TestHealthInternalErrorCarriesNoDetail(t *testing.T) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	s := build(t, doc, policy, log, erroring{errors.New("ldap bind to dc01.corp.example.net failed, server 16.4.2")})
	for _, p := range []string{"/health/live", "/health/ready"} {
		rec := call(s, p)
		m := members(t, rec)
		if _, has := m["detail"]; has || rec.Code != 500 || m["type"] != "/problems/internal" {
			t.Fatalf("%s = %d %s", p, rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "dc01") || strings.Contains(rec.Body.String(), "16.4.2") {
			t.Fatalf("%s leaks: %s", p, rec.Body)
		}
	}
}
