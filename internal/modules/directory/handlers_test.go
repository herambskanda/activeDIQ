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
	"github.com/skenzeriq/activediq/internal/directory/client/clienttest"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
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
	scope authz.ReadScope
}

func (s *searcher) Users(_ context.Context, tid tenant.ID, id connection.ID, text string, limit int, scope authz.ReadScope) (client.UserSearchResult, error) {
	s.calls++
	s.tid, s.conn = tid, id
	s.text, s.limit = text, limit
	s.scope = scope
	return s.res, s.err
}

func active() []connection.Connection {
	return []connection.Connection{{ID: "c1", Kind: connection.KindADForest, State: connection.StateActive}}
}

func passing() connection.Health {
	now := time.Now()
	return connection.Health{Verdict: connection.VerdictPass, RightsCheckedAt: &now}
}

// scopes is a fixed ReadScopes producer: it records what it was asked and answers a scope or an error.
type scopes struct {
	scope authz.ReadScope
	err   error
	calls int
	chain authority.Chain
	perm  authz.Permission
	tid   tenant.ID
}

func (s *scopes) ReadScope(_ context.Context, tid tenant.ID, chain authority.Chain, perm authz.Permission) (authz.ReadScope, error) {
	s.calls++
	s.tid, s.chain, s.perm = tid, chain, perm
	return s.scope, s.err
}

func wholeDomain() *scopes {
	return &scopes{scope: authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: authz.ObjectID{15: 1}, Root: authz.ObjectID{15: 2}}}})}
}

func serve(t *testing.T, c conns, s *searcher, logs *bytes.Buffer, target string) *httptest.ResponseRecorder {
	t.Helper()
	return serveWith(t, directory.Handlers{Connections: c, Search: s, Scopes: wholeDomain(), Log: slog.New(slog.NewTextHandler(logs, nil))}, target)
}

func serveWith(t *testing.T, h directory.Handlers, target string) *httptest.ResponseRecorder {
	t.Helper()
	return serveAs(t, h, target, ports{})
}

type tokenPorts struct{ ports }

func (tokenPorts) Authenticate(*http.Request) (apihost.Principal, error) {
	return apihost.Principal{ID: "admin", Tenant: tenantText, Kind: apihost.KindToken}, nil
}

func serveAs(t *testing.T, h directory.Handlers, target string, authn apihost.Authenticator) *httptest.ResponseRecorder {
	t.Helper()
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := apihost.Build(doc, []apihost.TagHandlers{h.Bind()}, pol, apihost.Permissions{string(directory.ReadPermission), "connections.takeover.attest", "siem.destination.manage", "siem.destination.read"}, apihost.Ports{Authn: authn, Authz: ports{}, Limits: ports{}, StepUp: ports{}})
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
	h := directory.Handlers{Connections: conns{ad, passing()}, Search: s, Scopes: wholeDomain(), Log: slog.New(slog.NewTextHandler(&logs, nil)),
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

// T-0875: search is trimmed to the principal's directory.read ReadScope, which the handler gets from
// the one producer and hands to the search unchanged.
func TestSearchHandsThePrincipalsReadScopeToTheSearch(t *testing.T) {
	s := &searcher{}
	sc := wholeDomain()
	var logs bytes.Buffer
	h := directory.Handlers{Connections: conns{active(), passing()}, Search: s, Scopes: sc, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	if w := serveWith(t, h, "/api/v1/directory/users?q=ann"); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if sc.calls != 1 || sc.perm != directory.ReadPermission || sc.tid.String() != tenantText ||
		sc.chain.Requester.ID != "admin" || sc.chain.Requester.Kind != authority.Human || len(sc.chain.Via) != 0 {
		t.Fatalf("producer asked %+v for %q in %s", sc.chain, sc.perm, sc.tid)
	}
	if s.calls != 1 || s.scope.Fingerprint() != sc.scope.Fingerprint() {
		t.Fatalf("search got a different scope than the producer's (calls %d)", s.calls)
	}
}

// Nothing is searched when the scope cannot be had: no producer, a dead owner, a refused token and an
// unsupported chain are all 403 and never an unscoped search; a store fault is a 500.
func TestSearchRefusedWhenTheScopeCannotBeProduced(t *testing.T) {
	cases := []struct {
		name   string
		scopes directory.ReadScopes
		want   int
	}{
		{"no producer", nil, 403},
		{"owner dead", &scopes{err: authz.ErrOwnerDead}, 403},
		{"token refused", &scopes{err: authz.ErrTokenRefused}, 403},
		{"unsupported chain", &scopes{err: rbac.ErrUnsupportedChain}, 403},
		{"denied", &scopes{err: rbac.ErrDenied}, 403},
		{"store fault", &scopes{err: errors.New("db down")}, 500},
	}
	for _, c := range cases {
		s := &searcher{res: client.UserSearchResult{Users: []client.FoundUser{{ObjectGUID: "aaaaaaaa-0000-4000-8000-00000000000a"}}}}
		var logs bytes.Buffer
		w := serveWith(t, directory.Handlers{Connections: conns{active(), passing()}, Search: s, Scopes: c.scopes, Log: slog.New(slog.NewTextHandler(&logs, nil))}, "/api/v1/directory/users?q=ann")
		if w.Code != c.want || s.calls != 0 || strings.Contains(w.Body.String(), "aaaaaaaa") {
			t.Errorf("%s: %d %s (search calls %d), want %d and no search", c.name, w.Code, w.Body, s.calls, c.want)
		}
	}
}

// A token principal cannot be turned into a chain here (the principal does not carry the token), so
// it is refused rather than read with its owner's wider scope.
func TestSearchRefusesATokenPrincipal(t *testing.T) {
	s := &searcher{}
	sc := wholeDomain()
	var logs bytes.Buffer
	w := serveAs(t, directory.Handlers{Connections: conns{active(), passing()}, Search: s, Scopes: sc, Log: slog.New(slog.NewTextHandler(&logs, nil))},
		"/api/v1/directory/users?q=ann", tokenPorts{})
	if w.Code != 403 || s.calls != 0 || sc.calls != 0 {
		t.Fatalf("%d %s (search %d, producer %d)", w.Code, w.Body, s.calls, sc.calls)
	}
}

// The scope trimming a connector cannot do (ancestry unreadable) is a 503, not an answer.
func TestSearchScopeResolutionFailureIsUnavailable(t *testing.T) {
	s := &searcher{err: client.ErrSearchScope}
	var logs bytes.Buffer
	w := serve(t, conns{active(), passing()}, s, &logs, "/api/v1/directory/users?q=ann")
	if w.Code != 503 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

type adConns struct{}

func (adConns) Get(context.Context, tenant.ID, connection.ID) (connection.Connection, error) {
	return connection.Connection{ID: adConnUUID, Kind: connection.KindADForest, State: connection.StateActive, DirectoryIdentity: nc}, nil
}

const (
	adConnUUID = "c0c0c0c0-0000-4000-8000-000000000001"
	nc         = "11111111-0000-4000-8000-000000000001"
	ouA        = "11111111-0000-4000-8000-00000000000a"
	ouB        = "11111111-0000-4000-8000-00000000000b"
)

// T-0875 acceptance 1, through the whole request path (apihost pipeline, handler, the real
// client.UserSearch, an in-memory directory): a technician scoped to OU A searches for a user who
// lives in OU B and gets an empty list, with no field of the body that counts or hints at the user.
func TestScopedTechnicianCannotSeeAUserInAnotherOU(t *testing.T) {
	dir := clienttest.New(
		clienttest.Node{GUID: nc}, clienttest.Node{GUID: ouA, Parent: nc}, clienttest.Node{GUID: ouB, Parent: nc},
		clienttest.Node{GUID: "22222222-0000-4000-8000-00000000000a", Parent: ouA, User: true, Display: "Ann Inside", Sam: "ann.inside"},
		clienttest.Node{GUID: "22222222-0000-4000-8000-00000000000b", Parent: ouB, User: true, Display: "Ann Outside", Sam: "ann.outside"},
	)
	id := func(s string) authz.ObjectID {
		o, err := authz.ParseObjectID(s)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	scoped := &scopes{scope: authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: id(adConnUUID), Root: id(ouA)}}})}
	us, err := client.NewUserSearch(adConns{}, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	h := directory.Handlers{Connections: conns{[]connection.Connection{{ID: adConnUUID, Kind: connection.KindADForest, State: connection.StateActive}}, passing()},
		Search: us, Scopes: scoped, Log: slog.New(slog.NewTextHandler(&logs, nil))}

	w := serveWith(t, h, "/api/v1/directory/users?q=outside")
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"items":[]}` {
		t.Fatalf("scoped to OU A, searching for a user in OU B answered %d %s, want 200 and an empty list", w.Code, w.Body)
	}
	w = serveWith(t, h, "/api/v1/directory/users?q=ann")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "ann.inside") || strings.Contains(w.Body.String(), "outside") {
		t.Fatalf("scoped to OU A, searching for ann answered %d %s, want only the user in OU A", w.Code, w.Body)
	}
}
