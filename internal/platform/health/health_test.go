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
	"sync"
	"sync/atomic"
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
	return build(t, doc, policy, log, api.Handlers(health.New(log, checks)))
}

// catalogueOf names every permission the document uses, so the test builds the whole document
// and does not break when another tag adds an operation.
func catalogueOf(doc apihost.Document) apihost.Permissions {
	var out apihost.Permissions
	for _, o := range doc.Operations() {
		if o.Permission != "" && o.Permission != "anonymous" && o.Permission != "authenticated" {
			out = append(out, o.Permission)
		}
	}
	return out
}

func build(t *testing.T, doc apihost.Document, policy apihost.Policy, log *slog.Logger, h api.Handlers) *apihost.Server {
	t.Helper()
	s, err := apihost.Build(doc, []apihost.TagHandlers{api.Bind(h)}, policy, catalogueOf(doc), apihost.Ports{Authn: ports{}, Authz: ports{}, Limits: ports{}, StepUp: ports{}}, apihost.WithLogger(log))
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

// redacted returns the response body and each header value with the server-generated trace ID
// removed. The trace ID is 32 random hex characters and can by chance spell "dc01" (hex-only), so
// it must not be scanned for leak canaries; it is itself asserted to be well-formed, and the body
// must carry the same ID as the X-Trace-Id header.
func redacted(t *testing.T, rec *httptest.ResponseRecorder) (body string, headers map[string]string) {
	t.Helper()
	id := rec.Header().Get("X-Trace-Id")
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		t.Fatalf("X-Trace-Id = %q, want 32 lowercase hex characters", id)
	}
	body = strings.ReplaceAll(rec.Body.String(), id, "TRACE")
	headers = map[string]string{}
	for k, v := range rec.Header() {
		headers[k] = strings.ReplaceAll(strings.Join(v, ","), id, "TRACE")
	}
	return body, headers
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
		body, headers := redacted(t, rec)
		for _, leak := range []string{host, version, "dc01", "database", "refused", "dial"} {
			if strings.Contains(body, leak) {
				t.Fatalf("body leaks %q: %s", leak, rec.Body)
			}
		}
		for k, v := range headers {
			if strings.Contains(v, "dc01") {
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
		body, _ := redacted(t, rec)
		if strings.Contains(body, "dc01") || strings.Contains(body, "16.4.2") {
			t.Fatalf("%s leaks: %s", p, rec.Body)
		}
	}
}

func TestReadinessHangingCheckTimesOut(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	release := make(chan struct{})
	defer close(release)
	hang := health.NamedCheck{Name: "database", Check: func(context.Context) error { <-release; return nil }} // ignores ctx
	s := build(t, mustDoc(t), mustPolicy(t), log, health.New(log, []health.NamedCheck{hang}, health.WithCheckTimeout(50*time.Millisecond)))
	start := time.Now()
	rec := call(s, "/health/ready")
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
	if rec.Code != 503 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if m := members(t, rec); m["detail"] != nil || m["type"] == nil || !strings.HasSuffix(m["type"].(string), "/problems/not-ready") {
		t.Fatalf("problem: %v", m)
	}
	if !strings.Contains(logs.String(), "timed out") {
		t.Fatalf("log lacks timeout: %s", logs.String())
	}
}

func TestReadinessSingleFlight(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	var calls, concurrent, maxConcurrent atomic.Int32
	gate := make(chan struct{})
	chk := health.NamedCheck{Name: "database", Check: func(context.Context) error {
		calls.Add(1)
		n := concurrent.Add(1)
		for {
			m := maxConcurrent.Load()
			if n <= m || maxConcurrent.CompareAndSwap(m, n) {
				break
			}
		}
		<-gate
		concurrent.Add(-1)
		return nil
	}}
	s := build(t, mustDoc(t), mustPolicy(t), log, health.New(log, []health.NamedCheck{chk}, health.WithResultTTL(time.Minute)))
	const n = 50
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- call(s, "/health/ready").Code }()
	}
	time.Sleep(100 * time.Millisecond) // let callers pile onto the one round
	close(gate)
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 200 {
			t.Fatalf("status %d", c)
		}
	}
	if call(s, "/health/ready").Code != 200 {
		t.Fatal("cached call failed")
	}
	if calls.Load() != 1 || maxConcurrent.Load() != 1 {
		t.Fatalf("probes run = %d, max concurrent = %d; want 1, 1", calls.Load(), maxConcurrent.Load())
	}
}

func TestReadinessDoesNotStackProbesOfAHungCheck(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	var calls atomic.Int32
	release := make(chan struct{})
	defer close(release)
	hang := health.NamedCheck{Name: "database", Check: func(context.Context) error { calls.Add(1); <-release; return nil }}
	s := build(t, mustDoc(t), mustPolicy(t), log, health.New(log, []health.NamedCheck{hang}, health.WithCheckTimeout(20*time.Millisecond), health.WithResultTTL(0)))
	for i := 0; i < 5; i++ {
		if c := call(s, "/health/ready").Code; c != 503 {
			t.Fatalf("status %d", c)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("hung check started %d times, want 1", calls.Load())
	}
}

func TestCheckErrorSecretsNotLogged(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	for _, msg := range []string{
		`dial postgres://svc:hunter2pw@db01:5432/activediq: refused`,
		`failed host=db01 user=svc password=hunter2pw dbname=x`,
		`bad Password: "hunter2pw" for svc`,
		`auth token=hunter2pw rejected`,
		`env PGPASSWORD=hunter2pw`,
		`db_password=hunter2pw`,
		`client_secret=hunter2pw`,
		`cfg {"password":"hunter2pw"}`,
		`cfg {"db_password": "hunter2pw"}`,
		`key=hunter2pw`,
		`dial postgres://svc:hunter2pw/ss@db01/x`,
		`dial postgres://svc:hunter2pw@ssw0rd@db01/x`,
		`dial postgres://svc:p@hunter2pw@db01/x`,
	} {
		logs.Reset()
		c := health.NamedCheck{Name: "database", Check: func(context.Context) error { return errors.New(msg) }}
		s := build(t, mustDoc(t), mustPolicy(t), log, health.New(log, []health.NamedCheck{c}, health.WithResultTTL(0)))
		if rec := call(s, "/health/ready"); rec.Code != 503 {
			t.Fatalf("status %d", rec.Code)
		}
		if strings.Contains(logs.String(), "hunter2pw") {
			t.Errorf("secret logged for %q: %s", msg, logs.String())
		}
		if !strings.Contains(logs.String(), "readiness check failed") {
			t.Errorf("failure not logged: %s", logs.String())
		}
	}
}

func mustDoc(t *testing.T) apihost.Document {
	t.Helper()
	d, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mustPolicy(t *testing.T) apihost.Policy {
	t.Helper()
	p, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadinessCallerHangupIsNotAnErrorLog(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	release := make(chan struct{})
	defer close(release)
	hang := health.NamedCheck{Name: "database", Check: func(context.Context) error { <-release; return nil }}
	s := build(t, mustDoc(t), mustPolicy(t), log, health.New(log, []health.NamedCheck{hang}, health.WithCheckTimeout(time.Minute)))
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("GET", "/api/v1/health/ready", nil).WithContext(ctx)
	r.RemoteAddr = "192.0.2.7:4000"
	rec := httptest.NewRecorder()
	time.AfterFunc(50*time.Millisecond, cancel)
	s.ServeHTTP(rec, r)
	if rec.Code != 503 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("hang-up logged an error: %s", logs.String())
	}
}
