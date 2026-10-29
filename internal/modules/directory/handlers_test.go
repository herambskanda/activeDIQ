package directory_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const tenantText = "00000000-0000-4000-8000-000000000001"

type ports struct{}

func (ports) Authenticate(*http.Request) (apihost.Principal, error) {
	return apihost.Principal{ID: "admin", Tenant: tenantText, Kind: apihost.KindSession, SessionID: "s"}, nil
}
func (ports) CheckCSRF(*http.Request, apihost.Principal) error { return nil }
func (ports) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (ports) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

type conns struct {
	list []connection.Connection
	hl   connection.Health
}

func (c conns) List(context.Context, tenant.ID, bool) ([]connection.Connection, error) {
	return c.list, nil
}
func (c conns) Health(context.Context, tenant.ID, connection.ID, bool, time.Time) (connection.Health, error) {
	return c.hl, nil
}

type searcher struct {
	res   client.UserSearchResult
	err   error
	calls int
	text  string
	limit int
	tid   tenant.ID
	conn  connection.ID
}

func (s *searcher) Users(_ context.Context, tid tenant.ID, id connection.ID, text string, limit int) (client.UserSearchResult, error) {
	s.calls++
	s.tid, s.conn = tid, id
	s.text, s.limit = text, limit
	return s.res, s.err
}

func active() []connection.Connection {
	return []connection.Connection{{ID: "c1", Kind: connection.KindADForest, State: connection.StateActive}}
}

func passing() connection.Health {
	now := time.Now()
	return connection.Health{Verdict: connection.VerdictPass, RightsCheckedAt: &now}
}

func serve(t *testing.T, c conns, s *searcher, logs *bytes.Buffer, target string) *httptest.ResponseRecorder {
	t.Helper()
	return serveWith(t, directory.Handlers{Connections: c, Search: s, Log: slog.New(slog.NewTextHandler(logs, nil))}, target)
}

func serveWith(t *testing.T, h directory.Handlers, target string) *httptest.ResponseRecorder {
	t.Helper()
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := apihost.Build(doc, []apihost.TagHandlers{h.Bind()}, pol, apihost.Permissions{string(directory.ReadPermission), "connections.takeover.attest", "siem.destination.manage", "siem.destination.read"}, apihost.Ports{Authn: ports{}, Authz: ports{}, Limits: ports{}, StepUp: ports{}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", target, nil)
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

func TestSearchReturnsOnlyAllowedFields(t *testing.T) {
	s := &searcher{res: client.UserSearchResult{Users: []client.FoundUser{{ObjectGUID: "aaaaaaaa-0000-4000-8000-00000000000a",
		DisplayName: "Ann Lab", SAMAccountName: "lab-user-01", UserPrincipalName: "lab-user-01@lab.test", Enabled: true}}}}
	var logs bytes.Buffer
	w := serve(t, conns{active(), passing()}, s, &logs, "/api/v1/directory/users?q=lab-user-01")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{`"objectGuid"`, `"displayName"`, `"samAccountName"`, `"userPrincipalName"`, `"enabled":true`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in %s", want, body)
		}
	}
	if s.text != "lab-user-01" || s.limit != directory.DefaultLimit {
		t.Fatalf("search args: %q %d", s.text, s.limit)
	}
}

func TestTier0AndUnverifiedConnectionsAreRefusedWithTheReason(t *testing.T) {
	stale := passing()
	stale.RightsStale = true
	never := passing()
	never.RightsCheckedAt = nil
	failed := passing()
	failed.Verdict = connection.VerdictFailed
	t0 := passing()
	t0.Excessive = []connection.Finding{{Kind: "tier0_group_membership", Severity: connection.SeverityBlock}}
	inst := passing()
	inst.Tier0Installation = true
	cases := map[string]struct {
		hl   connection.Health
		want string
	}{
		"tier0 group":        {t0, "Tier-0 group"},
		"tier0 installation": {inst, "Tier-0 group"},
		"failed verdict":     {failed, "not been verified"},
		"stale check":        {stale, "not been verified"},
		"never checked":      {never, "not been verified"},
	}
	for name, c := range cases {
		s := &searcher{}
		var logs bytes.Buffer
		w := serve(t, conns{active(), c.hl}, s, &logs, "/api/v1/directory/users?q=x")
		if w.Code != 503 || !strings.Contains(w.Body.String(), c.want) || s.calls != 0 {
			t.Errorf("%s: %d %s calls=%d", name, w.Code, w.Body, s.calls)
		}
	}
}

func TestNoActiveConnectionIsUnavailable(t *testing.T) {
	var logs bytes.Buffer
	s := &searcher{}
	draft := []connection.Connection{{ID: "c1", Kind: connection.KindADForest, State: connection.StateDraft}}
	w := serve(t, conns{draft, passing()}, s, &logs, "/api/v1/directory/users?q=x")
	if w.Code != 503 || s.calls != 0 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestConnectorErrorsBecomeProblemsWithoutDetail(t *testing.T) {
	secret := "svc-activediq password=Hunter2 ldaps://dc1.lab.test"
	cases := map[string]struct {
		err  error
		code int
	}{
		"connection":  {client.ErrSearchConnection, 503},
		"remote":      {&client.RemoteError{Err: &connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS}}, 503},
		"unavailable": {status.Error(codes.Unavailable, secret), 503},
		"deadline":    {context.DeadlineExceeded, 503},
		"text":        {client.ErrSearchTextInvalid, 400},
		"other":       {errors.New(secret), 500},
	}
	for name, c := range cases {
		var logs bytes.Buffer
		w := serve(t, conns{active(), passing()}, &searcher{err: c.err}, &logs, "/api/v1/directory/users?q=x")
		if w.Code != c.code {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		if !strings.Contains(w.Header().Get("Content-Type"), "problem+json") {
			t.Errorf("%s: content type %q", name, w.Header().Get("Content-Type"))
		}
		for _, leak := range []string{"Hunter2", "dc1.lab.test", "svc-activediq"} {
			if strings.Contains(w.Body.String(), leak) || strings.Contains(logs.String(), leak) {
				t.Errorf("%s: %q leaked (body=%s logs=%s)", name, leak, w.Body, logs.String())
			}
		}
	}
}

// Acceptance 1: the search runs for the tenant of the authenticated principal, on that tenant's active
// connection, and nothing in the request can name another tenant.
func TestSearchIsScopedToThePrincipalsTenant(t *testing.T) {
	s := &searcher{}
	var logs bytes.Buffer
	w := serve(t, conns{active(), passing()}, s, &logs, "/api/v1/directory/users?q=ann&tenant="+"00000000-0000-4000-8000-0000000000ff")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if s.tid.String() != tenantText || s.conn != "c1" {
		t.Fatalf("searched tenant %s connection %s", s.tid, s.conn)
	}
}

// Acceptance 4: a hybrid-synced user carries its TM-D17 classification in the response; a user the
// classifier could not check is never reported as not hybrid.
func TestSearchCarriesTheHybridClassification(t *testing.T) {
	s := &searcher{res: client.UserSearchResult{Users: []client.FoundUser{{ObjectGUID: "aaaaaaaa-0000-4000-8000-00000000000a", DisplayName: "Ann"}}}}
	var logs bytes.Buffer
	ad := []connection.Connection{{ID: adConn, Kind: connection.KindADForest, State: connection.StateActive}}
	h := directory.Handlers{Connections: conns{ad, passing()}, Search: s, Log: slog.New(slog.NewTextHandler(&logs, nil)),
		Hybrid: directory.Classifier{Corr: corrFake{cs: matchedLinks()}, Takeovers: takeFake{state: connection.TakeoverAttested}}}
	w := serveWith(t, h, "/api/v1/directory/users?q=ann")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"hybrid":{"carriesAuthority":true,"state":"matched"}`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	h.Hybrid = directory.Classifier{}
	w = serveWith(t, h, "/api/v1/directory/users?q=ann")
	if !strings.Contains(w.Body.String(), `"state":"unknown"`) || strings.Contains(w.Body.String(), `"carriesAuthority":true`) {
		t.Fatalf("an unchecked user must be unknown with no authority: %s", w.Body)
	}
}
