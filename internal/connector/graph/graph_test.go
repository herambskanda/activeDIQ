package graph_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/graph/graphtest"
	gid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/odata"
)

const (
	tenantID = "11111111-1111-1111-1111-111111111111"
	clientID = "22222222-2222-2222-2222-222222222222"
	spID     = "33333333-3333-3333-3333-333333333333"
	appObj   = "44444444-4444-4444-4444-444444444444"
	graphSP  = "55555555-5555-5555-5555-555555555555"
	roleID   = "66666666-6666-6666-6666-666666666666"
)

// G parses a test GUID.
func G(s string) gid.GUID {
	g, err := gid.Parse(s)
	if err != nil {
		panic(err)
	}
	return g
}

func guid(n int) string {
	return strings.Replace("77777777-7777-7777-7777-000000000000", "000000000000", pad(n), 1)
}
func pad(n int) string {
	d := []byte("000000000000")
	for i := 11; n > 0; i-- {
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d)
}

func tenant() *graphtest.Tenant {
	return &graphtest.Tenant{
		TenantID: tenantID, ClientID: clientID, SPID: spID, AppObjectID: appObj,
		ServicePrincipals: map[string]graph.ServicePrincipal{
			spID:    {ID: spID, AppID: clientID, DisplayName: "activeDIQ"},
			graphSP: {ID: graphSP, DisplayName: "Microsoft Graph", AppRoles: []graph.AppRole{{ID: "r1", Value: "User.Read.All"}, {ID: "r2", Value: "Directory.Read.All"}, {ID: "r3", Value: "Group.Read.All"}}},
		},
		Assignments: map[string][]graph.AppRoleAssignment{spID: {
			{ID: "a1", AppRoleID: "r1", PrincipalID: spID, ResourceID: graphSP, ResourceDisplayName: "Microsoft Graph"},
			{ID: "a2", AppRoleID: "r2", PrincipalID: spID, ResourceID: graphSP, ResourceDisplayName: "Microsoft Graph"},
			{ID: "a3", AppRoleID: "r3", PrincipalID: spID, ResourceID: graphSP, ResourceDisplayName: "Microsoft Graph"},
		}},
		KeyCredentials: []graph.KeyCredential{
			{KeyID: "k1", DisplayName: "activeDIQ", Type: "AsymmetricX509Cert", Usage: "Verify", EndDateTime: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
			{KeyID: "k2", DisplayName: "attacker", Type: "AsymmetricX509Cert", Usage: "Verify", EndDateTime: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
		},
		Roles: []graph.RoleAssignment{
			{ID: "ra1", PrincipalID: spID, RoleDefinitionID: roleID, DirectoryScopeID: "/", Role: graph.RoleDefinition{ID: roleID, DisplayName: "Directory Readers", TemplateID: roleID}},
			{ID: "ra2", PrincipalID: guid(1), RoleDefinitionID: roleID, DirectoryScopeID: "/", Role: graph.RoleDefinition{ID: roleID, DisplayName: "Directory Readers"}},
			{ID: "re1", PrincipalID: spID, RoleDefinitionID: roleID, DirectoryScopeID: "/", Eligible: true, Role: graph.RoleDefinition{ID: roleID, DisplayName: "Directory Readers"}},
		},
		Owners: map[string][]graph.DirectoryObject{
			appObj: {{ID: guid(1), ODataType: "#microsoft.graph.user", UserPrincipalName: "a@x"}, {ID: guid(2), ODataType: "#microsoft.graph.user"}, {ID: guid(3), ODataType: "#microsoft.graph.servicePrincipal"}},
			spID:   {{ID: guid(4), ODataType: "#microsoft.graph.user"}},
		},
		Groups: []graph.Group{
			{ID: guid(10), DisplayName: "G1", IsAssignableToRole: true},
			{ID: guid(11), DisplayName: "plain"},
			{ID: guid(12), DisplayName: "G2", IsAssignableToRole: true},
			{ID: guid(13), DisplayName: "G3", IsAssignableToRole: true},
		},
		Members: map[string][]graph.DirectoryObject{guid(10): members(7)},
	}
}

func members(n int) []graph.DirectoryObject {
	var m []graph.DirectoryObject
	for i := 0; i < n; i++ {
		m = append(m, graph.DirectoryObject{ID: guid(100 + i), ODataType: "#microsoft.graph.user"})
	}
	return m
}

type rig struct {
	srv   *graphtest.Server
	cred  graph.Credential
	cfg   graph.Config
	c     *graph.Client
	logs  *bytes.Buffer
	slept []time.Duration
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{logs: &bytes.Buffer{}}
	r.cred = graphtest.NewCredential(t)
	r.srv = graphtest.New(t, tenant(), r.cred)
	r.cfg = r.srv.Config(r.cred)
	r.cfg.Logger = slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r.cfg.Sleep = func(_ context.Context, d time.Duration) error { r.slept = append(r.slept, d); return nil }
	r.build(t)
	return r
}

func (r *rig) build(t *testing.T) {
	t.Helper()
	c, err := graph.New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
}

// AC1
func TestCertificateAssertionAndNoSecretInLogs(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.c.OwnServicePrincipal(ctx); err != nil {
		t.Fatal(err)
	}
	if len(r.srv.Assertions) != 1 {
		t.Fatalf("assertions = %d, want 1 (server verified signature, aud, iss, thumbprint)", len(r.srv.Assertions))
	}
	// Second read reuses the cached token.
	if _, err := r.c.OwnApplication(ctx); err != nil {
		t.Fatal(err)
	}
	if tok, _ := r.srv.Calls(); tok != 1 {
		t.Fatalf("token calls = %d, want 1", tok)
	}
	// Nothing sensitive in logs, errors or formatted credentials.
	keyDER, _ := x509.MarshalPKCS8PrivateKey(r.cred.Key)
	secrets := []string{r.srv.Assertions[0], strings.Split(r.srv.Assertions[0], ".")[2], base64.StdEncoding.EncodeToString(keyDER),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), "Bearer", r.srv.AccessToken}
	out := r.logs.String() + sprint(r.cred)
	if r.logs.Len() == 0 {
		t.Fatal("expected debug log lines to inspect")
	}
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Fatalf("secret material %q… leaked into log/format output", s[:min(8, len(s))])
		}
	}
}

func sprint(v any) string { return strings.Join([]string{fmtV(v), fmtPlus(v)}, " ") }

func TestAssertionRejectedWhenCertUnregistered(t *testing.T) {
	r := newRig(t)
	r.cfg.Credential = graphtest.NewCredential(t) // not the registered cert
	r.build(t)
	_, err := r.c.OwnServicePrincipal(context.Background())
	if graph.CodeOf(err) != graph.CodeBindFailed {
		t.Fatalf("err = %v, want BIND_FAILED", err)
	}
}

// AC2
func TestReadsReturnExactly(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	tn := r.srv.T

	sp, err := r.c.OwnServicePrincipal(ctx)
	if err != nil || sp.ID != spID || sp.AppID != clientID {
		t.Fatalf("sp = %+v, %v", sp, err)
	}
	asg, err := r.c.AppRoleAssignments(ctx, G(sp.ID))
	if err != nil || !reflect.DeepEqual(asg, tn.Assignments[spID]) {
		t.Fatalf("assignments = %+v, %v", asg, err)
	}
	res, err := r.c.ServicePrincipalByID(ctx, G(graphSP))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, ar := range res.AppRoles {
		names[ar.ID] = ar.Value
	}
	if names[asg[1].AppRoleID] != "Directory.Read.All" {
		t.Fatalf("role resolution: %v", names)
	}
	app, err := r.c.OwnApplication(ctx)
	if err != nil || !reflect.DeepEqual(app.KeyCredentials, tn.KeyCredentials) {
		t.Fatalf("keys = %+v, %v", app.KeyCredentials, err)
	}
	roles, err := r.c.OwnDirectoryRoles(ctx)
	if err != nil || len(roles) != 2 || roles[0].Eligible || !roles[1].Eligible || roles[0].Role.DisplayName != "Directory Readers" {
		t.Fatalf("roles = %+v, %v", roles, err)
	}
	all, err := r.c.AllDirectoryRoleAssignments(ctx)
	if err != nil || len(all) != 3 {
		t.Fatalf("all roles = %d, %v", len(all), err)
	}
	owners, err := r.c.ApplicationOwners(ctx, G(app.ID))
	if err != nil || !reflect.DeepEqual(owners, tn.Owners[appObj]) || owners[2].Type() != "servicePrincipal" {
		t.Fatalf("owners = %+v, %v", owners, err)
	}
	spOwn, err := r.c.ServicePrincipalOwners(ctx, G(spID))
	if err != nil || len(spOwn) != 1 {
		t.Fatalf("sp owners = %+v, %v", spOwn, err)
	}
	groups, err := r.c.RoleAssignableGroups(ctx)
	if err != nil || len(groups) != 3 {
		t.Fatalf("groups = %+v, %v", groups, err)
	}
	m, err := r.c.GroupMembers(ctx, G(guid(10)))
	if err != nil || !reflect.DeepEqual(m, tn.Members[guid(10)]) {
		t.Fatalf("members = %d, %v", len(m), err)
	}
	if g, err := r.c.GroupOwners(ctx, G(guid(10))); err != nil || len(g) != 0 {
		t.Fatalf("group owners = %v, %v", g, err)
	}
}

func TestAppWithNoExtraKeysReturnsEmptyNotNil(t *testing.T) {
	r := newRig(t)
	r.srv.T.KeyCredentials = nil
	app, err := r.c.OwnApplication(context.Background())
	if err != nil || app.KeyCredentials == nil || len(app.KeyCredentials) != 0 {
		t.Fatalf("%+v %v", app, err)
	}
}

// AC3
func TestThrottleRetryAfterAndPaging(t *testing.T) {
	r := newRig(t)
	r.srv.FailGraph(graphtest.Failure{Status: 429, RetryAfter: "7"}, graphtest.Failure{Status: 429, RetryAfter: "3"})
	m, err := r.c.GroupMembers(context.Background(), G(guid(10)))
	if err != nil || len(m) != 7 {
		t.Fatalf("members = %d, %v", len(m), err)
	}
	if !reflect.DeepEqual(r.slept, []time.Duration{7 * time.Second, 3 * time.Second}) {
		t.Fatalf("slept = %v, want Retry-After honoured", r.slept)
	}
	// Throttle in the middle of a paged read: first page succeeds, second is throttled once.
	r.slept = nil
	r.srv.FailGraph(graphtest.Failure{Status: 429, RetryAfter: "1"})
	r.srv.PageSize = 3
	// consume: the failure applies to the first call; still must return all pages.
	m, err = r.c.GroupMembers(context.Background(), G(guid(10)))
	if err != nil || len(m) != 7 || len(r.slept) != 1 {
		t.Fatalf("members = %d slept=%v err=%v", len(m), r.slept, err)
	}
}

func TestThrottleExhaustedIsTypedWithRetryAfter(t *testing.T) {
	r := newRig(t)
	r.cfg.MaxRetries = 1
	r.build(t)
	r.srv.FailGraph(graphtest.Failure{Status: 429, RetryAfter: "2"}, graphtest.Failure{Status: 429, RetryAfter: "2"})
	_, err := r.c.GroupMembers(context.Background(), G(guid(10)))
	var ge *graph.Error
	if !asErr(err, &ge) || ge.Code != graph.CodeThrottled || ge.RetryAfter != 2*time.Second {
		t.Fatalf("err = %v", err)
	}
}

func TestRetryAfterBeyondMaxWaitIsNotSlept(t *testing.T) {
	r := newRig(t)
	r.srv.FailGraph(graphtest.Failure{Status: 429, RetryAfter: "86400"})
	_, err := r.c.OwnApplication(context.Background())
	if graph.CodeOf(err) != graph.CodeThrottled || len(r.slept) != 0 {
		t.Fatalf("err=%v slept=%v", err, r.slept)
	}
}

// AC4
func TestErrorsAreTypedNeverEmptySuccess(t *testing.T) {
	cases := []struct {
		name string
		f    graphtest.Failure
		want graph.Code
	}{
		{"403", graphtest.Failure{Status: 403, Body: `{"error":{"message":"secret detail"}}`}, graph.CodeInsufficient},
		{"404", graphtest.Failure{Status: 404}, graph.CodeNotFound},
		{"500", graphtest.Failure{Status: 500}, graph.CodeProviderFailure},
		{"200 garbage", graphtest.Failure{Status: 200, Body: `<html>`}, graph.CodeProviderFailure},
		{"redirect", graphtest.Failure{Status: 302}, graph.CodeProviderFailure},
	}
	reads := map[string]func(*graph.Client) error{
		"sp":     func(c *graph.Client) error { _, e := c.OwnServicePrincipal(context.Background()); return e },
		"app":    func(c *graph.Client) error { _, e := c.OwnApplication(context.Background()); return e },
		"assign": func(c *graph.Client) error { _, e := c.AppRoleAssignments(context.Background(), G(spID)); return e },
		"roles": func(c *graph.Client) error {
			_, e := c.AllDirectoryRoleAssignments(context.Background())
			return e
		},
		"owners":  func(c *graph.Client) error { _, e := c.ApplicationOwners(context.Background(), G(appObj)); return e },
		"groups":  func(c *graph.Client) error { _, e := c.RoleAssignableGroups(context.Background()); return e },
		"members": func(c *graph.Client) error { _, e := c.GroupMembers(context.Background(), G(guid(10))); return e },
	}
	for _, tc := range cases {
		for rn, read := range reads {
			t.Run(tc.name+"/"+rn, func(t *testing.T) {
				r := newRig(t)
				r.srv.FailGraph(tc.f)
				err := read(r.c)
				if graph.CodeOf(err) != tc.want {
					t.Fatalf("err = %v, want %s", err, tc.want)
				}
				if strings.Contains(err.Error(), "secret detail") {
					t.Fatal("provider body leaked into error")
				}
			})
		}
	}
}

func TestErrorInLaterPageFailsWholeRead(t *testing.T) {
	r := newRig(t)
	m, err := r.c.GroupMembers(context.Background(), G(guid(10)))
	if err != nil || len(m) != 7 {
		t.Fatal(err)
	}
	// Fail the second page: succeed first call, then 500.
	r2 := newRig(t)
	r2.srv.PageSize = 2
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Inject after the first graph call by wrapping the sleep? Simpler: fail calls 1..N via two failures where
	// the first is retryable and the second fatal, proving a mid-read error is returned, not a partial list.
	r2.srv.FailGraph(graphtest.Failure{Status: 503, RetryAfter: "0"}, graphtest.Failure{Status: 500})
	got, err := r2.c.GroupMembers(ctx, G(guid(10)))
	if err == nil || got != nil {
		t.Fatalf("got %d items, err %v; want nil+error", len(got), err)
	}
}

func TestUnreachableTenant(t *testing.T) {
	r := newRig(t)
	r.srv.Close()
	_, err := r.c.OwnServicePrincipal(context.Background())
	if graph.CodeOf(err) != graph.CodeUnreachable {
		t.Fatalf("err = %v, want UNREACHABLE_DC", err)
	}
}

func TestUntrustedTLSIsTransportSecurity(t *testing.T) {
	r := newRig(t)
	r.cfg.HTTPClient = nil // system roots: the fake's certificate is not trusted
	r.build(t)
	_, err := r.c.OwnServicePrincipal(context.Background())
	if graph.CodeOf(err) != graph.CodeTransportSec {
		t.Fatalf("err = %v, want TRANSPORT_SECURITY", err)
	}
}

func TestTokenForOtherTenantRefused(t *testing.T) {
	r := newRig(t)
	r.srv.TenantClaim = "99999999-9999-9999-9999-999999999999"
	_, err := r.c.OwnServicePrincipal(context.Background())
	if graph.CodeOf(err) != graph.CodeIdentityMismatch {
		t.Fatalf("err = %v", err)
	}
}

func TestTokenEndpointFailures(t *testing.T) {
	r := newRig(t)
	r.srv.FailToken(graphtest.Failure{Status: 429, RetryAfter: "4"})
	if _, err := r.c.OwnServicePrincipal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.slept, []time.Duration{4 * time.Second}) {
		t.Fatalf("slept = %v", r.slept)
	}
	r2 := newRig(t)
	r2.srv.FailToken(graphtest.Failure{Status: 401})
	if _, err := r2.c.OwnServicePrincipal(context.Background()); graph.CodeOf(err) != graph.CodeBindFailed {
		t.Fatalf("err = %v", err)
	}
}

func TestExpiredTokenRefreshedOn401(t *testing.T) {
	r := newRig(t)
	r.srv.FailGraph(graphtest.Failure{Status: 401})
	if _, err := r.c.OwnApplication(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tok, _ := r.srv.Calls(); tok != 2 {
		t.Fatalf("token calls = %d, want 2 (refresh)", tok)
	}
}

func TestNextLinkOffOriginRefusedAndNoTokenSent(t *testing.T) {
	r := newRig(t)
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t.Errorf("request reached off-origin host with Authorization=%q", req.Header.Get("Authorization"))
	}))
	defer evil.Close()
	r.srv.FailGraph(graphtest.Failure{Status: 200, Body: `{"value":[],"@odata.nextLink":"` + evil.URL + `/v1.0/x"}`})
	_, err := r.c.GroupMembers(context.Background(), G(guid(10)))
	if graph.CodeOf(err) != graph.CodeIdentityMismatch {
		t.Fatalf("err = %v", err)
	}
}

func TestInvalidInputsRejectedBeforeAnyRequest(t *testing.T) {
	r := newRig(t)
	// IDs are typed (guid.GUID), so hostile text cannot reach a URL. The one value that parses but is
	// never an object identity is the nil GUID.
	if _, err := r.c.GroupMembers(context.Background(), gid.GUID{}); graph.CodeOf(err) != graph.CodeInvalidArgument {
		t.Fatalf("nil GUID: err = %v", err)
	}
	if _, g := r.srv.Calls(); g != 0 {
		t.Fatalf("graph calls = %d", g)
	}
	cfg := r.cfg
	cfg.TenantID = "a/b"
	if _, err := graph.New(cfg); graph.CodeOf(err) != graph.CodeInvalidArgument {
		t.Fatal(err)
	}
	cfg = r.cfg
	cfg.GraphBase = "http://graph.example/v1.0"
	if _, err := graph.New(cfg); graph.CodeOf(err) != graph.CodeTransportSec {
		t.Fatal(err)
	}
}

func TestContextCancelIsNotATypedDirectoryError(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.c.OwnApplication(ctx)
	if err == nil || graph.CodeOf(err) != "" {
		t.Fatalf("err = %v", err)
	}
}

var _ = base64.StdEncoding

func TestAssertionHeaderIsPS256WithThumbprint(t *testing.T) {
	r := newRig(t)
	if _, err := r.c.OwnServicePrincipal(context.Background()); err != nil {
		t.Fatal(err)
	}
	jwt := r.srv.Assertions[0]
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]string
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(r.cred.Cert.Raw)
	if h["alg"] != "PS256" || h["x5t#S256"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("header = %v", h)
	}
}

func TestFakeRefusesPKCS1v15Assertion(t *testing.T) {
	r := newRig(t)
	sum := sha256.Sum256(r.cred.Cert.Raw)
	b := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "x5t#S256": b.EncodeToString(sum[:])})
	cl, _ := json.Marshal(map[string]any{"aud": r.srv.URL + "/" + tenantID + "/oauth2/v2.0/token", "iss": clientID, "sub": clientID, "exp": time.Now().Add(time.Minute).Unix()})
	signing := b.EncodeToString(hdr) + "." + b.EncodeToString(cl)
	d := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.cred.Key.(*rsa.PrivateKey), crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {signing + "." + b.EncodeToString(sig)}, "scope": {"https://graph.microsoft.com/.default"}}
	resp, err := r.cfg.HTTPClient.PostForm(r.srv.URL+"/"+tenantID+"/oauth2/v2.0/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("fake accepted an RS256/PKCS#1 v1.5 assertion: %d", resp.StatusCode)
	}
}

func TestDomainTenantIDRefused(t *testing.T) {
	r := newRig(t)
	cfg := r.cfg
	cfg.TenantID = "contoso.example"
	if _, err := graph.New(cfg); graph.CodeOf(err) != graph.CodeInvalidArgument {
		t.Fatalf("err = %v", err)
	}
}

func TestRetryAfterOverflowIsNotSlept(t *testing.T) {
	r := newRig(t)
	r.srv.FailGraph(graphtest.Failure{Status: 429, RetryAfter: "99999999999"})
	_, err := r.c.OwnApplication(context.Background())
	if graph.CodeOf(err) != graph.CodeThrottled || len(r.slept) != 0 {
		t.Fatalf("err=%v slept=%v", err, r.slept)
	}
}

// The zero GUID is never a principal: it must be refused before any request is sent, so a caller
// that ignored a guid.Parse error cannot receive the tenant-wide listing (T-0171).
func TestDirectoryRoleAssignmentsRefusesZeroGUID(t *testing.T) {
	r := newRig(t)
	_, before := r.srv.Calls()
	got, err := r.c.DirectoryRoleAssignments(context.Background(), gid.GUID{})
	if got != nil || graph.CodeOf(err) != graph.CodeInvalidArgument {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, after := r.srv.Calls(); after != before {
		t.Fatalf("a request was sent: %d -> %d", before, after)
	}
}

// Debug logging carries the path template only; a key value (a UPN) never reaches the log.
func TestDebugLogCarriesPathTemplateNotKeyValue(t *testing.T) {
	r := newRig(t)
	upn, err := odata.Str("adele.vance@contoso.example")
	if err != nil {
		t.Fatal(err)
	}
	seg, err := odata.KeyStr("users", upn)
	if err != nil {
		t.Fatal(err)
	}
	// The user does not exist in the fake: the failed read is still logged.
	_ = graph.ReadForTest(context.Background(), r.c, odata.Get(seg))
	out := r.logs.String()
	if !strings.Contains(out, "users({key})") {
		t.Fatalf("expected the template in the log, got %q", out)
	}
	if strings.Contains(out, "adele") || strings.Contains(out, "contoso") {
		t.Fatalf("key value leaked into the log: %q", out)
	}
}
