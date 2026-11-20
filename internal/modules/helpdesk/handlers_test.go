package helpdesk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
	"github.com/skenzeriq/activediq/internal/platform/limiter"
)

const tenantText = "00000000-0000-4000-8000-000000000001"

// webPorts is a console session whose CSRF check is the real rule: the header must equal the session's value.
type webPorts struct {
	kind   apihost.PrincipalKind
	tenant string
}

func (w webPorts) Authenticate(r *http.Request) (apihost.Principal, error) {
	return apihost.Principal{ID: tech, Tenant: w.tenant, Kind: w.kind, SessionID: "sess-" + r.Header.Get("X-Test-Session"), CSRF: "csrf-ok"}, nil
}
func (webPorts) CheckCSRF(r *http.Request, p apihost.Principal) error {
	if r.Header.Get("X-CSRF-Token") != p.CSRF {
		return apihost.ErrCSRF
	}
	return nil
}
func (webPorts) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (webPorts) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (webPorts) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (webPorts) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

type stubSvc struct {
	mu       sync.Mutex
	issues   int
	verifies int
	issueErr error
	verErr   error
	lastCode string
}

func (s *stubSvc) IssueOnce(_ context.Context, _ string, in IssueInput) (Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issues++
	if s.issueErr != nil {
		return Challenge{}, s.issueErr
	}
	return Challenge{ID: "8a1d6f40-2b7e-4c93-a5d1-7e0b9c3f2a64", Factor: in.Factor, Masked: "j***@example.com", ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}
func (s *stubSvc) VerifyOnce(_ context.Context, _ string, in VerifyInput) (Verified, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifies++
	s.lastCode = in.Code
	if s.verErr != nil {
		return Verified{}, s.verErr
	}
	return Verified{ChallengeID: in.ChallengeID, Until: time.Now().Add(5 * time.Minute)}, nil
}

type rig struct {
	srv   *apihost.Server
	sleep []time.Duration
	logs  *bytes.Buffer
}

func newRig(t *testing.T, svc Service, kind apihost.PrincipalKind) *rig {
	t.Helper()
	return newRigWith(t, svc, kind, limiter.NewMemoryStore(time.Now))
}

func newRigWith(t *testing.T, svc Service, kind apihost.PrincipalKind, th limiter.PrincipalStore, tenants ...string) *rig {
	t.Helper()
	r := &rig{logs: &bytes.Buffer{}}
	h := Handlers{Service: svc, Throttle: th, Log: slog.New(slog.NewTextHandler(r.logs, nil)),
		Now:   func() time.Time { return time.Unix(1_800_000_000, 0) }, // frozen: no time passes inside a request
		Sleep: func(_ context.Context, d time.Duration) { r.sleep = append(r.sleep, d) }}
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	p := webPorts{kind: kind, tenant: tenantText}
	if len(tenants) > 0 {
		p.tenant = tenants[0]
	}
	r.srv, err = apihost.Build(doc, []apihost.TagHandlers{h.Bind()}, pol, apitest.Catalogue(doc), apihost.Ports{Authn: p, Authz: p, Limits: p, StepUp: p})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) do(method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.7:4444"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, req)
	return w
}

var traceRe = regexp.MustCompile(`"traceId":"[0-9a-f]+"`)

// noTrace drops the per-request trace ID, the one field that legitimately differs between two identical refusals.
func noTrace(s string) string { return traceRe.ReplaceAllString(s, `"traceId":"-"`) }

const (
	issuePath  = "/api/v1/helpdesk/caller-verifications"
	verifyPath = "/api/v1/helpdesk/caller-verifications/8a1d6f40-2b7e-4c93-a5d1-7e0b9c3f2a64/verify"
	issueBody  = `{"connectionId":"` + conn + `","objectGuid":"` + user + `","factor":"email_otp"}`
)

func ok(extra map[string]string) map[string]string {
	h := map[string]string{"X-CSRF-Token": "csrf-ok", "Idempotency-Key": "key-0000001", "X-Test-Session": "a"}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

// Acceptance 1: both routes are POST only and never act on a GET (T-0719 C1), whatever the headers.
func Test_routes_are_post_only(t *testing.T) {
	svc := &stubSvc{}
	r := newRig(t, svc, apihost.KindSession)
	for _, path := range []string{issuePath, verifyPath} {
		for _, m := range []string{"GET", "HEAD", "PUT", "PATCH", "DELETE"} {
			w := r.do(m, path+"?code=123456", "", ok(nil))
			if w.Code != 405 && w.Code != 404 {
				t.Errorf("%s %s = %d, want 405/404", m, path, w.Code)
			}
		}
	}
	if svc.issues != 0 || svc.verifies != 0 {
		t.Fatalf("a non-POST request reached the engine: issues=%d verifies=%d", svc.issues, svc.verifies)
	}
}

// Acceptance 1: a cookie session's POST without the CSRF header is refused before the engine; a token principal is
// refused by the handler (the verifier is a human at the console), so no route is reachable without the CSRF proof.
func Test_post_needs_csrf_and_a_human_session(t *testing.T) {
	svc := &stubSvc{}
	r := newRig(t, svc, apihost.KindSession)
	h := ok(nil)
	delete(h, "X-CSRF-Token")
	for path, body := range map[string]string{issuePath: issueBody, verifyPath: `{"code":"123456"}`} {
		w := r.do("POST", path, body, h)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "csrf") {
			t.Errorf("%s without CSRF = %d %s", path, w.Code, w.Body)
		}
	}
	if svc.issues+svc.verifies != 0 {
		t.Fatal("the engine ran without a CSRF token")
	}
	if w := r.do("POST", issuePath, issueBody, ok(nil)); w.Code != 200 || !strings.Contains(w.Body.String(), `"destinationMasked":"j***@example.com"`) || strings.Contains(w.Body.String(), "code") {
		t.Fatalf("issue = %d %s", w.Code, w.Body)
	}
	tok := newRig(t, svc, apihost.KindToken)
	if w := tok.do("POST", issuePath, issueBody, ok(nil)); w.Code != 403 {
		t.Fatalf("token issue = %d", w.Code)
	}
	if w := tok.do("POST", verifyPath, `{"code":"123456"}`, ok(nil)); w.Code != 403 {
		t.Fatalf("token verify = %d", w.Code)
	}
}

// Acceptance 2: every verify refusal is byte-identical and costs at least the floor.
func Test_verify_refusal_is_uniform_and_padded(t *testing.T) {
	var bodies []string
	for _, e := range []error{ErrRefused, fmt.Errorf("attempts: %w", ErrRefused)} {
		svc := &stubSvc{verErr: e}
		r := newRig(t, svc, apihost.KindSession)
		w := r.do("POST", verifyPath, `{"code":"123456"}`, ok(nil))
		if w.Code != 422 {
			t.Fatalf("refusal = %d %s", w.Code, w.Body)
		}
		bodies = append(bodies, noTrace(w.Body.String()))
		if len(r.sleep) != 1 || r.sleep[0] != RefusalFloor {
			t.Fatalf("refusal padding = %v, want one wait of %v", r.sleep, RefusalFloor)
		}
	}
	if bodies[0] != bodies[1] || !strings.Contains(bodies[0], "caller-verification-refused") {
		t.Fatalf("bodies differ: %q vs %q", bodies[0], bodies[1])
	}
}

// AC-OTP-12: the issue refusal is one answer for an unauthorised and a destination-less target, padded alike.
func Test_issue_ineligible_targets_answer_alike(t *testing.T) {
	var bodies []string
	for _, e := range []error{ErrNotAuthorised, ErrNoDestination} {
		r := newRig(t, &stubSvc{issueErr: e}, apihost.KindSession)
		w := r.do("POST", issuePath, issueBody, ok(nil))
		bodies = append(bodies, fmt.Sprint(w.Code, noTrace(w.Body.String())))
		if len(r.sleep) != 1 || r.sleep[0] != RefusalFloor {
			t.Fatalf("padding = %v", r.sleep)
		}
	}
	if bodies[0] != bodies[1] || !strings.HasPrefix(bodies[0], "422") {
		t.Fatalf("answers differ: %q vs %q", bodies[0], bodies[1])
	}
}

func Test_issue_limits_delivery_and_idempotency_map_to_problems(t *testing.T) {
	cases := []struct {
		err  error
		code int
		want string
	}{
		{ErrQuota, 429, `"code":"quota"`}, {ErrPaused, 429, `"code":"paused"`}, {ErrDelivery, 502, "delivery-failed"},
		{ErrKeyReuse, 422, "idempotency-key-reuse"}, {ErrKeyInFlight, 409, "conflict"}, {errors.New("pq: secret detail 123456"), 500, "internal"},
	}
	for _, c := range cases {
		r := newRig(t, &stubSvc{issueErr: c.err}, apihost.KindSession)
		w := r.do("POST", issuePath, issueBody, ok(nil))
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.want) || strings.Contains(w.Body.String(), "secret detail") {
			t.Errorf("%v = %d %s", c.err, w.Code, w.Body)
		}
	}
}

// Acceptance 3: the code is in no URL, log line or error body, on a pass, a refusal, a bad shape and an engine fault.
func Test_code_never_appears_in_logs_or_error_bodies(t *testing.T) {
	const code = "918273"
	for name, svc := range map[string]*stubSvc{"pass": {}, "refused": {verErr: ErrRefused}, "fault": {verErr: errors.New("db: bad value " + code)}} {
		r := newRig(t, svc, apihost.KindSession)
		w := r.do("POST", verifyPath, `{"code":"`+code+`"}`, ok(nil))
		if strings.Contains(w.Body.String(), code) || strings.Contains(r.logs.String(), code) || strings.Contains(verifyPath, code) {
			t.Errorf("%s: code leaked: body=%s logs=%s", name, w.Body, r.logs)
		}
	}
	r := newRig(t, &stubSvc{}, apihost.KindSession)
	w := r.do("POST", verifyPath, `{"code":"91a273"}`, ok(nil))
	if w.Code != 400 || strings.Contains(w.Body.String(), "91a273") || strings.Contains(r.logs.String(), "91a273") {
		t.Fatalf("bad shape = %d %s logs=%s", w.Code, w.Body, r.logs)
	}
	// A code in the query string is never read: the engine gets the body's code only.
	svc := &stubSvc{}
	r = newRig(t, svc, apihost.KindSession)
	r.do("POST", verifyPath+"?code=000000", `{"code":"`+code+`"}`, ok(nil))
	if svc.lastCode != code {
		t.Fatalf("engine got %q, want the body's code", svc.lastCode)
	}
}

// Acceptance 4: the per-session and the per-IP limits each refuse on their own, in addition to the engine's caps.
func Test_per_session_and_per_ip_rate_limits(t *testing.T) {
	r := newRig(t, &stubSvc{}, apihost.KindSession)
	n := 0
	for i := 0; i < 20; i++ {
		w := r.do("POST", verifyPath, `{"code":"123456"}`, ok(nil))
		if w.Code == 429 {
			break
		}
		n++
	}
	if n != sessionVerifyLimit.Burst {
		t.Fatalf("one session got %d verifies, want its burst of %d", n, sessionVerifyLimit.Burst)
	}
	// A second session from the same source address has its own budget until the address's budget is gone.
	r2 := newRig(t, &stubSvc{}, apihost.KindSession)
	got := 0
	for i := 0; i < 100; i++ {
		w := r2.do("POST", verifyPath, `{"code":"123456"}`, ok(map[string]string{"X-Test-Session": fmt.Sprint("s", i)}))
		if w.Code == 429 {
			break
		}
		got++
	}
	if got != ipVerifyLimit.Burst {
		t.Fatalf("one address got %d verifies across sessions, want its burst of %d", got, ipVerifyLimit.Burst)
	}
	// A limit that cannot be counted refuses.
	svc := &stubSvc{}
	if w := newRigWith(t, svc, apihost.KindSession, nil).do("POST", verifyPath, `{"code":"123456"}`, ok(nil)); w.Code != 503 || svc.verifies != 0 {
		t.Fatalf("no throttle store: %d, engine calls %d; it must refuse, not skip the limit", w.Code, svc.verifies)
	}
}
