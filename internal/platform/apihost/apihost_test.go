package apihost_test

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// ---- fakes ------------------------------------------------------------------------------------

type fakePorts struct {
	principal                        apihost.Principal
	authnErr, csrfErr, authzErr      error
	allow, stepFresh                 bool
	ipDeny, principalDeny            bool
	mu                               sync.Mutex
	calls                            []string
	lastPerm, lastScope, lastIPClass string
}

func (f *fakePorts) record(c string) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
}

func newPorts() *fakePorts {
	return &fakePorts{principal: apihost.Principal{ID: "p1", Kind: apihost.KindToken}, allow: true, stepFresh: true}
}

func (f *fakePorts) Authenticate(*http.Request) (apihost.Principal, error) {
	f.record("authn")
	return f.principal, f.authnErr
}
func (f *fakePorts) CheckCSRF(*http.Request, apihost.Principal) error {
	f.record("csrf")
	return f.csrfErr
}
func (f *fakePorts) Allow(_ context.Context, _ apihost.Principal, perm, scope string) (bool, error) {
	f.record("authz")
	f.mu.Lock()
	f.lastPerm, f.lastScope = perm, scope
	f.mu.Unlock()
	return f.allow, f.authzErr
}
func (f *fakePorts) AllowIP(_ context.Context, class, _ string) (apihost.Decision, error) {
	f.record("ip")
	f.mu.Lock()
	f.lastIPClass = class
	f.mu.Unlock()
	return apihost.Decision{Allowed: !f.ipDeny, RetryAfter: 1500 * time.Millisecond}, nil
}
func (f *fakePorts) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	f.record("limit")
	return apihost.Decision{Allowed: !f.principalDeny, RetryAfter: time.Second}, nil
}
func (f *fakePorts) Fresh(context.Context, apihost.Principal) (bool, error) {
	f.record("stepup")
	return f.stepFresh, nil
}
func (f *fakePorts) ports() apihost.Ports {
	return apihost.Ports{Authn: f, Authz: f, Limits: f, StepUp: f}
}

// secretBytes aliases the request buffer, like the real Secret, so a test can see the buffer zeroed.
type secretBytes struct {
	b         []byte
	destroyed bool
}

func (s *secretBytes) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	v, err := d.ReadValue()
	if err != nil {
		return err
	}
	s.b = v[1 : len(v)-1]
	return nil
}
func (s *secretBytes) Destroy() { clear(s.b); s.destroyed = true }

type body struct {
	Name   string       `json:"name"`
	Secret *secretBytes `json:"secret,omitzero"`
}

type input struct {
	body     body
	hasBody  bool
	upload   apihost.Upload
	failBind bool
	invalid  bool
}

func (i *input) BindRequest(r *apihost.Request, errs *apitypes.Errors) {
	i.upload = r.Upload
	if i.failBind {
		errs.Add(apitypes.InQuery, "limit", apitypes.CodeType, "bad")
	}
}
func (i *input) BodyTarget() any {
	if !i.hasBody {
		return nil
	}
	return &i.body
}
func (i *input) Validate(errs *apitypes.Errors) {
	if i.invalid {
		errs.AddBody("/name", apitypes.CodeRequired, "missing")
	}
}
func (i *input) DestroySecrets() {
	if i.body.Secret != nil {
		i.body.Secret.Destroy()
	}
}

type resp struct {
	status int
	body   any
	hdr    map[string]string
}

func (r resp) StatusCode() int                    { return r.status }
func (r resp) ResponseBody() any                  { return r.body }
func (r resp) ResponseHeaders() map[string]string { return r.hdr }

type row struct {
	meta apihost.RouteMeta
	call func(context.Context, apihost.Input) (apihost.Response, error)
	in   *input
	mu   sync.Mutex
}

func (r *row) route() apihost.Route {
	return apihost.NewRoute(r.meta, func() apihost.Input {
		in := &input{hasBody: r.meta.Body == apihost.BodyJSON || r.meta.Body == apihost.BodyMergePatch}
		r.mu.Lock()
		r.in = in
		r.mu.Unlock()
		return in
	}, func(ctx context.Context, in apihost.Input) (apihost.Response, error) {
		if r.call == nil {
			return resp{status: 200, body: map[string]string{"ok": "yes"}}, nil
		}
		return r.call(ctx, in)
	})
}

func meta(id, method, path, perm string) apihost.RouteMeta {
	return apihost.RouteMeta{OperationID: id, Tag: "widgets", Method: method, Path: path, Permission: perm, Scope: "tenant",
		Class: "read", MaxBody: 1 << 10, Body: apihost.BodyNone}
}

func docJSON(ops ...[4]string) []byte { // id, method, path, permission
	var sb strings.Builder
	sb.WriteString(`{"openapi":"3.1.0","info":{"title":"t","version":"0"},"paths":{`)
	byPath := map[string][][4]string{}
	var order []string
	for _, o := range ops {
		if _, ok := byPath[o[2]]; !ok {
			order = append(order, o[2])
		}
		byPath[o[2]] = append(byPath[o[2]], o)
	}
	for i, p := range order {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "%q:{", p)
		for j, o := range byPath[p] {
			if j > 0 {
				sb.WriteString(",")
			}
			perm := ""
			if o[3] != "" {
				perm = fmt.Sprintf(`,"x-permission":%q`, o[3])
			}
			class := "read"
			switch {
			case o[3] == "anonymous":
				class = "anonymous"
			case o[1] != "GET":
				class = "write"
			}
			fmt.Fprintf(&sb, `%q:{"operationId":%q,"tags":["widgets"],"x-activediq-limits":{"class":%q}%s}`, strings.ToLower(o[1]), o[0], class, perm)
		}
		sb.WriteString("}")
	}
	sb.WriteString("}}")
	return []byte(sb.String())
}

var catalogue = apihost.Permissions{"widgets.read", "widgets.write"}

// serve builds a one-route server and runs a request through it.
func serve(t *testing.T, r *row, fp *fakePorts, policy apihost.Policy, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	m := r.meta
	raw := docJSON([4]string{m.OperationID, m.Method, m.Path, m.Permission})
	raw = bytes.Replace(raw, []byte(`"class":"write"`), []byte(`"class":"`+m.Class+`"`), 1) // the document carries the row's class
	doc, err := apihost.ParseDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	s, err := apihost.Build(doc, []apihost.TagHandlers{apihost.NewTagHandlers("widgets", r.route())}, policy, catalogue, fp.ports())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func problemOf(t *testing.T, rec *httptest.ResponseRecorder, status int, typ string) *apitypes.Problem {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type = %q", ct)
	}
	var p apitypes.Problem
	if err := p.UnmarshalJSONFrom(jsontext.NewDecoder(strings.NewReader(rec.Body.String()))); err != nil {
		t.Fatalf("problem does not parse: %v: %s", err, rec.Body)
	}
	if p.Type != typ || int(p.Status) != status || p.TraceID == nil || *p.TraceID == "" {
		t.Fatalf("problem = %+v, want type %s", p, typ)
	}
	return &p
}

func get(path string) *http.Request {
	r := httptest.NewRequest("GET", "/api/v1"+path, nil)
	r.RemoteAddr = "192.0.2.7:4000"
	return r
}

func post(path, ct, b string) *http.Request {
	r := httptest.NewRequest("POST", "/api/v1"+path, strings.NewReader(b))
	r.RemoteAddr = "192.0.2.7:4000"
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	return r
}

func jsonRow() *row {
	m := meta("createWidget", "POST", "/widgets", "widgets.write")
	m.Body, m.MediaType, m.Class = apihost.BodyJSON, "application/json", "write"
	return &row{meta: m}
}

// ---- Build (AC 1) -----------------------------------------------------------------------------

func buildErr(t *testing.T, doc []byte, tags []apihost.TagHandlers, policy apihost.Policy) error {
	t.Helper()
	d, err := apihost.ParseDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, err = apihost.Build(d, tags, policy, catalogue, newPorts().ports())
	return err
}

func tag(rows ...*row) apihost.TagHandlers {
	var rs []apihost.Route
	for _, r := range rows {
		rs = append(rs, r.route())
	}
	return apihost.NewTagHandlers("widgets", rs...)
}

func TestBuildRoutesAreExactlyTheDocument(t *testing.T) {
	list := &row{meta: meta("listWidgets", "GET", "/widgets", "widgets.read")}
	get1 := &row{meta: meta("getWidget", "GET", "/widgets/{id}", "widgets.read")}
	doc := docJSON([4]string{"listWidgets", "GET", "/widgets", "widgets.read"}, [4]string{"getWidget", "GET", "/widgets/{id}", "widgets.read"})
	d, _ := apihost.ParseDocument(doc)
	s, err := apihost.Build(d, []apihost.TagHandlers{tag(list, get1)}, apihost.Policy{}, catalogue, newPorts().ports())
	if err != nil {
		t.Fatal(err)
	}
	if rs := s.Routes(); len(rs) != 2 || rs[0].OperationID != "getWidget" || rs[0].Path != "/api/v1/widgets/{id}" {
		t.Fatalf("routes = %+v", rs)
	}
}

func TestBuildRefusals(t *testing.T) {
	ok := [4]string{"listWidgets", "GET", "/widgets", "widgets.read"}
	listRow := func() *row { return &row{meta: meta("listWidgets", "GET", "/widgets", "widgets.read")} }
	otherTag := apihost.NewTagHandlers("gadgets", listRow().route())
	badMethod := listRow()
	badMethod.meta.Method = "POST"
	badPerm := listRow()
	badPerm.meta.Permission = "widgets.write"
	badScope := listRow()
	badScope.meta.Scope = "platform"
	badClass := listRow()
	badClass.meta.Class = "bulk"
	ghost := &row{meta: meta("ghost", "GET", "/ghost", "widgets.read")}
	clash := &row{meta: meta("a", "GET", "/widgets/{id}", "widgets.read")}
	clash2 := &row{meta: meta("b", "GET", "/widgets/{name}", "widgets.read")}

	cases := []struct {
		name   string
		doc    []byte
		tags   []apihost.TagHandlers
		policy apihost.Policy
		want   string
	}{
		{"handler not in the document", docJSON(ok), []apihost.TagHandlers{tag(listRow(), ghost)}, apihost.Policy{}, "not in the document"},
		{"operation without x-permission", docJSON([4]string{"listWidgets", "GET", "/widgets", ""}), []apihost.TagHandlers{tag(listRow())}, apihost.Policy{}, "no x-permission"},
		{"permission not in catalogue", docJSON([4]string{"listWidgets", "GET", "/widgets", "widgets.nope"}), []apihost.TagHandlers{tag(listRow())}, apihost.Policy{}, "not in the permission catalogue"},
		{"anonymous without a row", docJSON([4]string{"listWidgets", "GET", "/widgets", "anonymous"}), []apihost.TagHandlers{tag(listRow())}, apihost.Policy{}, "no policy.anonymous row"},
		{"authenticated without a row", docJSON([4]string{"listWidgets", "GET", "/widgets", "authenticated"}), []apihost.TagHandlers{tag(listRow())}, apihost.Policy{}, "no policy.authenticated row"},
		{"operation without a handler", docJSON(ok, [4]string{"getWidget", "GET", "/widgets/{id}", "widgets.read"}), []apihost.TagHandlers{tag(listRow())}, apihost.Policy{}, "getWidget (tag widgets) has no handler"},
		{"wrong tag", docJSON(ok), []apihost.TagHandlers{otherTag}, apihost.Policy{}, "tag gadgets"},
		{"method mismatch", docJSON(ok), []apihost.TagHandlers{tag(badMethod)}, apihost.Policy{}, "does not match the document"},
		{"permission mismatch", docJSON(ok), []apihost.TagHandlers{tag(badPerm)}, apihost.Policy{}, "permission"},
		{"scope mismatch", docJSON(ok), []apihost.TagHandlers{tag(badScope)}, apihost.Policy{}, "scope/class"},
		{"class mismatch", docJSON(ok), []apihost.TagHandlers{tag(badClass)}, apihost.Policy{}, "scope/class"},
		{"duplicate contribution", docJSON(ok), []apihost.TagHandlers{tag(listRow(), listRow())}, apihost.Policy{}, "contributed twice"},
		{"pattern conflict", docJSON([4]string{"a", "GET", "/widgets/{id}", "widgets.read"}, [4]string{"b", "GET", "/widgets/{name}", "widgets.read"}),
			[]apihost.TagHandlers{tag(clash, clash2)}, apihost.Policy{}, "conflicts"},
		{"unknown host binding", docJSON([4]string{"listWidgets", "GET", "/widgets", "anonymous"}), []apihost.TagHandlers{tag(listRow())},
			apihost.Policy{Anonymous: []apihost.AnonymousRow{{Operation: "listWidgets", Host: "nope"}}}, "unknown host binding"},
		{"host binding without hostname", docJSON([4]string{"listWidgets", "GET", "/widgets", "anonymous"}), []apihost.TagHandlers{tag(listRow())},
			apihost.Policy{Anonymous: []apihost.AnonymousRow{{Operation: "listWidgets", Host: "sspr"}}}, "no hostname configured"},
	}
	for _, c := range cases {
		err := buildErr(t, c.doc, c.tags, c.policy)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to contain %q", c.name, err, c.want)
		}
	}
	if _, err := apihost.Build(apihost.Document{}, nil, apihost.Policy{}, catalogue, apihost.Ports{}); err == nil {
		t.Error("missing ports must be refused")
	}
}

func TestBuildUnmountedTags(t *testing.T) {
	doc, _ := apihost.ParseDocument(docJSON([4]string{"listWidgets", "GET", "/widgets", "widgets.read"}))
	s, err := apihost.Build(doc, nil, apihost.Policy{}, catalogue, newPorts().ports())
	if err != nil {
		t.Fatal(err)
	}
	if u := s.Unmounted(); len(u) != 1 || u[0] != "widgets" {
		t.Fatalf("unmounted = %v", u)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, get("/widgets"))
	problemOf(t, rec, 404, apitypes.ProblemTypeNotFound)
}

func TestEmbeddedDocumentLoads(t *testing.T) {
	if _, err := apihost.LoadDocument(); err != nil {
		t.Fatal(err)
	}
}

func TestHostBindingTable(t *testing.T) {
	if len(apihost.HostBindings) == 0 {
		t.Fatal("the binding table is empty")
	}
	for _, b := range apihost.HostBindings {
		if got, ok := apihost.LookupHostBinding(b.Name); !ok || got != b || b.Ref == "" {
			t.Errorf("binding %+v", b)
		}
	}
	if _, ok := apihost.LookupHostBinding("nope"); ok {
		t.Error("an unknown binding was found")
	}
}

// ---- the chain, one test per step (AC 2) ------------------------------------------------------

func TestChainOrder(t *testing.T) {
	fp := newPorts()
	r := &row{meta: meta("stepWidget", "GET", "/widgets", "widgets.read")}
	fp.principal.Kind = apihost.KindSession
	req := get("/widgets")
	req.Method = "GET"
	serve(t, r, fp, apihost.Policy{StepUp: []string{"widgets.read"}}, req)
	if got := strings.Join(fp.calls, ","); got != "ip,authn,limit,stepup,authz" {
		t.Fatalf("order = %s", got)
	}
	// An unsafe method with a cookie session adds the CSRF check right after authn.
	fp = newPorts()
	fp.principal.Kind = apihost.KindSession
	serve(t, jsonRow(), fp, apihost.Policy{}, post("/widgets", "application/json", `{"name":"a"}`))
	if got := strings.Join(fp.calls, ","); got != "ip,authn,csrf,limit,authz" {
		t.Fatalf("order = %s", got)
	}
}

func TestIPRateLimitBeforeAuthentication(t *testing.T) {
	fp := newPorts()
	fp.ipDeny = true
	rec := serve(t, &row{meta: meta("l", "GET", "/widgets", "widgets.read")}, fp, apihost.Policy{}, get("/widgets"))
	problemOf(t, rec, 429, apitypes.ProblemTypeRateLimited)
	if rec.Header().Get("Retry-After") != "2" || strings.Join(fp.calls, ",") != "ip" || fp.lastIPClass != "read" {
		t.Fatalf("retry-after %q calls %v class %q", rec.Header().Get("Retry-After"), fp.calls, fp.lastIPClass)
	}
}

func TestHostBinding(t *testing.T) {
	m := meta("enrol", "GET", "/widgets", "anonymous")
	m.Class = "anonymous"
	pol := apihost.Policy{Anonymous: []apihost.AnonymousRow{{Operation: "enrol", Host: "totp-enrolment"}}, Hosts: map[string]string{"totp-enrolment": "enrol.example.test"}}
	fp := newPorts()
	req := get("/widgets")
	req.Host = "console.example.test"
	problemOf(t, serve(t, &row{meta: m}, fp, pol, req), 404, apitypes.ProblemTypeNotFound)
	req = get("/widgets")
	req.Host = "ENROL.example.test:8443"
	if rec := serve(t, &row{meta: m}, newPorts(), pol, req); rec.Code != 200 {
		t.Fatalf("bound host: %d %s", rec.Code, rec.Body)
	}
}

func TestQueryCredentialRefused(t *testing.T) {
	for _, q := range []string{"?token=x", "?Password=x", "?api_key=1", "?limit=5&access_token=z",
		"?password=hunter2;x", "?access_token=abc;", "?token=%zz"} {
		rec := serve(t, &row{meta: meta("l", "GET", "/widgets", "widgets.read")}, newPorts(), apihost.Policy{}, get("/widgets"+q))
		problemOf(t, rec, 400, apitypes.ProblemTypeMalformedRequest)
	}
	if rec := serve(t, &row{meta: meta("l", "GET", "/widgets", "widgets.read")}, newPorts(), apihost.Policy{}, get("/widgets?cursor=abc&tokenGroups=1")); rec.Code != 200 {
		t.Fatalf("a non-credential name was refused: %d", rec.Code)
	}
}

func TestBodyCap(t *testing.T) {
	big := `{"name":"` + strings.Repeat("a", 2000) + `"}`
	problemOf(t, serve(t, jsonRow(), newPorts(), apihost.Policy{}, post("/widgets", "application/json", big)), 413, apitypes.ProblemTypePayloadTooLarge)
	// No Content-Length: the read detects the overflow.
	req := post("/widgets", "application/json", big)
	req.ContentLength = -1
	problemOf(t, serve(t, jsonRow(), newPorts(), apihost.Policy{}, req), 413, apitypes.ProblemTypePayloadTooLarge)
	// Declared length but the client sent less: malformed.
	req = post("/widgets", "application/json", `{"name":"a"}`)
	req.ContentLength = 50
	problemOf(t, serve(t, jsonRow(), newPorts(), apihost.Policy{}, req), 400, apitypes.ProblemTypeMalformedRequest)
}

func TestContentType(t *testing.T) {
	for _, ct := range []string{"", "text/plain", "application/json; charset=latin1", "application/merge-patch+json"} {
		rec := serve(t, jsonRow(), newPorts(), apihost.Policy{}, post("/widgets", ct, `{"name":"a"}`))
		problemOf(t, rec, 415, apitypes.ProblemTypeUnsupportedMediaType)
	}
	for _, ct := range []string{"application/json", "application/json; charset=utf-8"} {
		if rec := serve(t, jsonRow(), newPorts(), apihost.Policy{}, post("/widgets", ct, `{"name":"a"}`)); rec.Code != 200 {
			t.Fatalf("%q: %d %s", ct, rec.Code, rec.Body)
		}
	}
}

func TestAuthentication(t *testing.T) {
	fp := newPorts()
	fp.authnErr = apihost.ErrUnauthenticated
	rec := serve(t, &row{meta: meta("l", "GET", "/widgets", "widgets.read")}, fp, apihost.Policy{}, get("/widgets"))
	problemOf(t, rec, 401, apitypes.ProblemTypeUnauthenticated)
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("a 401 needs WWW-Authenticate")
	}
	fp = newPorts()
	fp.authnErr = errors.New("db down: password=hunter2")
	rec = serve(t, &row{meta: meta("l", "GET", "/widgets", "widgets.read")}, fp, apihost.Policy{}, get("/widgets"))
	problemOf(t, rec, 500, apitypes.ProblemTypeInternal)
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatal("an internal error leaked")
	}
}

func TestAnonymousSkipsAuthentication(t *testing.T) {
	m := meta("setup", "GET", "/widgets", "anonymous")
	m.Class = "anonymous"
	fp := newPorts()
	fp.authnErr = apihost.ErrUnauthenticated
	rec := serve(t, &row{meta: m}, fp, apihost.Policy{Anonymous: []apihost.AnonymousRow{{Operation: "setup"}}}, get("/widgets"))
	if rec.Code != 200 || strings.Join(fp.calls, ",") != "ip" {
		t.Fatalf("%d calls %v", rec.Code, fp.calls)
	}
}

func TestCSRF(t *testing.T) {
	fp := newPorts()
	fp.principal.Kind = apihost.KindSession
	fp.csrfErr = apihost.ErrCSRF
	problemOf(t, serve(t, jsonRow(), fp, apihost.Policy{}, post("/widgets", "application/json", `{"name":"a"}`)), 403, apitypes.ProblemTypeCSRFFailed)
	// A safe method with a cookie session is not checked.
	fp = newPorts()
	fp.principal.Kind = apihost.KindSession
	fp.csrfErr = apihost.ErrCSRF
	if rec := serve(t, &row{meta: meta("l", "GET", "/widgets", "widgets.read")}, fp, apihost.Policy{}, get("/widgets")); rec.Code != 200 {
		t.Fatalf("GET with a session: %d", rec.Code)
	}
	// A bearer token is exempt.
	fp = newPorts()
	fp.csrfErr = apihost.ErrCSRF
	if rec := serve(t, jsonRow(), fp, apihost.Policy{}, post("/widgets", "application/json", `{"name":"a"}`)); rec.Code != 200 {
		t.Fatalf("bearer POST: %d %s", rec.Code, rec.Body)
	}
}

func TestCSRFFailsClosed(t *testing.T) {
	for name, p := range map[string]apihost.Principal{
		"unknown kind": {ID: "p1", Kind: "weird"}, "empty kind": {ID: "p1"}, "zero principal": {}, "empty id": {Kind: apihost.KindToken},
	} {
		fp := newPorts()
		fp.principal = p
		fp.csrfErr = apihost.ErrCSRF
		rec := serve(t, jsonRow(), fp, apihost.Policy{}, post("/widgets", "application/json", `{"name":"a"}`))
		if rec.Code != 500 {
			t.Errorf("%s: status %d, want 500", name, rec.Code)
		}
		problemOf(t, rec, 500, apitypes.ProblemTypeInternal)
	}
	fp := newPorts()
	fp.principal.Kind = apihost.KindSession
	fp.csrfErr = apihost.ErrCSRF
	problemOf(t, serve(t, jsonRow(), fp, apihost.Policy{}, post("/widgets", "application/json", `{"name":"a"}`)), 403, apitypes.ProblemTypeCSRFFailed)
}

func TestNonCanonicalPathsAreProblems(t *testing.T) {
	for _, p := range []string{"/widgets/", "//widgets", "/x/../widgets", "/./widgets"} {
		rec := serve(t, &row{meta: meta("l", "GET", "/widgets", "widgets.read")}, newPorts(), apihost.Policy{}, httptest.NewRequest("GET", "/api/v1"+p, nil))
		problemOf(t, rec, 404, apitypes.ProblemTypeNotFound)
		if rec.Header().Get("Location") != "" {
			t.Errorf("%s: redirect issued", p)
		}
	}
}

func TestPrincipalRateLimit(t *testing.T) {
	fp := newPorts()
	fp.principalDeny = true
	rec := serve(t, &row{meta: meta("l", "GET", "/widgets", "widgets.read")}, fp, apihost.Policy{}, get("/widgets"))
	problemOf(t, rec, 429, apitypes.ProblemTypeRateLimited)
	if rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
}

func TestStepUp(t *testing.T) {
	fp := newPorts()
	fp.stepFresh = false
	r := &row{meta: meta("l", "GET", "/widgets", "widgets.read")}
	problemOf(t, serve(t, r, fp, apihost.Policy{StepUp: []string{"widgets.read"}}, get("/widgets")), 401, apitypes.ProblemTypeStepUpRequired)
	if rec := serve(t, r, fp, apihost.Policy{}, get("/widgets")); rec.Code != 200 {
		t.Fatalf("no step-up row: %d", rec.Code)
	}
}

func TestPermission(t *testing.T) {
	fp := newPorts()
	fp.allow = false
	problemOf(t, serve(t, &row{meta: meta("l", "GET", "/widgets", "widgets.read")}, fp, apihost.Policy{}, get("/widgets")), 403, apitypes.ProblemTypeForbidden)
	if fp.lastPerm != "widgets.read" || fp.lastScope != "tenant" {
		t.Fatalf("authz asked %q %q", fp.lastPerm, fp.lastScope)
	}
	// "authenticated" passes any authenticated principal without asking authz.
	fp = newPorts()
	fp.allow = false
	rec := serve(t, &row{meta: meta("me", "GET", "/widgets", "authenticated")}, fp, apihost.Policy{Authenticated: []string{"me"}}, get("/widgets"))
	if rec.Code != 200 || strings.Contains(strings.Join(fp.calls, ","), "authz") {
		t.Fatalf("%d %v", rec.Code, fp.calls)
	}
}

type failingBody struct{ read bool }

func (f *failingBody) Read([]byte) (int, error) { f.read = true; return 0, io.ErrUnexpectedEOF }

func TestUnauthorisedBodyIsNeverRead(t *testing.T) {
	for _, mod := range []func(*fakePorts){
		func(f *fakePorts) { f.authnErr = apihost.ErrUnauthenticated },
		func(f *fakePorts) { f.allow = false },
	} {
		fp := newPorts()
		mod(fp)
		fb := &failingBody{}
		req := post("/widgets", "application/json", "")
		req.Body, req.ContentLength = io.NopCloser(fb), 10
		if rec := serve(t, jsonRow(), fp, apihost.Policy{}, req); rec.Code != 401 && rec.Code != 403 {
			t.Fatalf("status %d", rec.Code)
		}
		if fb.read {
			t.Fatal("the body was read before the request was authorised")
		}
	}
}

func TestStrictDecode(t *testing.T) {
	deep := strings.Repeat("[", 40) + strings.Repeat("]", 40)
	many := "[" + strings.Repeat("1,", 10001) + "1]"
	cases := []struct{ name, body string }{
		{"empty", ``},
		{"truncated", `{"name":`},
		{"duplicate name", `{"name":"a","name":"b"}`},
		{"trailing data", `{"name":"a"} {}`},
		{"trailing garbage", `{"name":"a"}x`},
		{"invalid utf-8", "{\"name\":\"\xff\"}"},
		{"lone surrogate escape", `{"name":"\ud800"}`},
		{"NUL escape in value", `{"name":"a\u0000b"}`},
		{"NUL escape in name", `{"na\u0000me":"a"}`},
		{"too deep", deep},
		{"too many values", many},
	}
	for _, c := range cases {
		m := jsonRow()
		m.meta.MaxBody = 1 << 20
		problemOf(t, serve(t, m, newPorts(), apihost.Policy{}, post("/widgets", "application/json", c.body)), 400, apitypes.ProblemTypeMalformedRequest)
	}
	// The same body is accepted where it is legal text, and the bulk class lifts the value limit.
	m := jsonRow()
	if rec := serve(t, m, newPorts(), apihost.Policy{}, post("/widgets", "application/json", `{"name":"a\\u0000b"}`)); rec.Code != 200 {
		t.Fatalf("an escaped backslash before u0000 is legal: %d %s", rec.Code, rec.Body)
	}
	b := jsonRow()
	b.meta.Class, b.meta.MaxBody = "bulk", 1<<20
	b.call = nil
	rec := serve(t, b, newPorts(), apihost.Policy{}, post("/widgets", "application/json", many))
	problemOf(t, rec, 400, apitypes.ProblemTypeValidation) // past the value limit, rejected by the schema instead
}

func TestSchemaViolationsAreCollected(t *testing.T) {
	r := jsonRow()
	rec := serve(t, r, newPorts(), apihost.Policy{}, post("/widgets", "application/json", `{"name":"a","extra":1}`))
	p := problemOf(t, rec, 400, apitypes.ProblemTypeValidation)
	if len(p.Errors) == 0 || strings.Contains(rec.Body.String(), "extra") && !strings.Contains(rec.Body.String(), "pointer") {
		t.Fatalf("errors = %+v", p.Errors)
	}
	// A wrong-case member is unknown, not matched.
	rec = serve(t, jsonRow(), newPorts(), apihost.Policy{}, post("/widgets", "application/json", `{"Name":"a"}`))
	problemOf(t, rec, 400, apitypes.ProblemTypeValidation)
	// A wrong type reports a type violation without v2's text.
	rec = serve(t, jsonRow(), newPorts(), apihost.Policy{}, post("/widgets", "application/json", `{"name":5}`))
	p = problemOf(t, rec, 400, apitypes.ProblemTypeValidation)
	if len(p.Errors) != 1 || p.Errors[0].Code != apitypes.CodeType || p.Errors[0].Pointer != "/name" {
		t.Fatalf("errors = %+v", p.Errors)
	}
	// Parameter and Validate violations are merged: nothing stops at the first.
	r = jsonRow()
	var in *input
	r2 := apihost.NewRoute(r.meta, func() apihost.Input { in = &input{hasBody: true, failBind: true, invalid: true}; return in },
		func(context.Context, apihost.Input) (apihost.Response, error) {
			t.Fatal("handler must not run")
			return nil, nil
		})
	doc, _ := apihost.ParseDocument(docJSON([4]string{"createWidget", "POST", "/widgets", "widgets.write"}))
	s, err := apihost.Build(doc, []apihost.TagHandlers{apihost.NewTagHandlers("widgets", r2)}, apihost.Policy{}, catalogue, newPorts().ports())
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, post("/widgets", "application/json", `{"name":"a"}`))
	if p := problemOf(t, rec, 400, apitypes.ProblemTypeValidation); len(p.Errors) != 2 {
		t.Fatalf("want a param and a body violation, got %+v", p.Errors)
	}
}

func TestSecretIsDestroyedAndBufferZeroed(t *testing.T) {
	r := jsonRow()
	r.meta.Secret = true
	var alias []byte
	r.call = func(_ context.Context, in apihost.Input) (apihost.Response, error) {
		sec := in.(*input).body.Secret
		alias = sec.b
		if string(alias) != "hunter2" {
			t.Errorf("the handler saw %q", alias)
		}
		return resp{status: 200}, nil
	}
	rec := serve(t, r, newPorts(), apihost.Policy{}, post("/widgets", "application/json", `{"name":"a","secret":"hunter2"}`))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if !r.in.body.Secret.destroyed {
		t.Error("DestroySecrets did not run")
	}
	for _, b := range alias {
		if b != 0 {
			t.Fatalf("the request buffer was not zeroed: %q", alias)
		}
	}
	// And after a handler error and a handler panic.
	for _, mode := range []string{"error", "panic"} {
		r = jsonRow()
		r.call = func(context.Context, apihost.Input) (apihost.Response, error) {
			if mode == "panic" {
				panic("boom hunter2")
			}
			return nil, errors.New("fail hunter2")
		}
		rec = serve(t, r, newPorts(), apihost.Policy{}, post("/widgets", "application/json", `{"name":"a","secret":"hunter2"}`))
		problemOf(t, rec, 500, apitypes.ProblemTypeInternal)
		if !r.in.body.Secret.destroyed || strings.Contains(rec.Body.String(), "hunter2") {
			t.Fatalf("%s: destroyed=%v body=%s", mode, r.in.body.Secret.destroyed, rec.Body)
		}
	}
}

func TestBinaryUploadIsCapped(t *testing.T) {
	m := meta("importWidgets", "POST", "/widgets", "widgets.write")
	m.Body, m.MediaType, m.MaxBody, m.Class = apihost.BodyBinary, "text/csv", 8, "write"
	r := &row{meta: m}
	r.call = func(_ context.Context, in apihost.Input) (apihost.Response, error) {
		_, err := io.ReadAll(in.(*input).upload)
		if err == nil {
			return resp{status: 204}, nil
		}
		return nil, apitypes.PayloadTooLarge("")
	}
	if rec := serve(t, r, newPorts(), apihost.Policy{}, post("/widgets", "text/csv", "a,b\n")); rec.Code != 204 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	req := post("/widgets", "text/csv", "0123456789abcdef")
	req.ContentLength = -1
	problemOf(t, serve(t, r, newPorts(), apihost.Policy{}, req), 413, apitypes.ProblemTypePayloadTooLarge)
}

// ---- problems and responses (AC 3) ------------------------------------------------------------

func TestHandlerErrorsRenderAsProblems(t *testing.T) {
	r := &row{meta: meta("l", "GET", "/widgets", "widgets.read")}
	r.call = func(context.Context, apihost.Input) (apihost.Response, error) {
		return nil, fmt.Errorf("wrap: %w", apitypes.Conflict("a widget with that name exists"))
	}
	p := problemOf(t, serve(t, r, newPorts(), apihost.Policy{}, get("/widgets")), 409, apitypes.ProblemTypeConflict)
	if p.Detail == nil || *p.Detail != "a widget with that name exists" || p.Instance == nil || *p.Instance != "/api/v1/widgets" {
		t.Fatalf("problem = %+v", p)
	}
	r.call = func(context.Context, apihost.Input) (apihost.Response, error) {
		return nil, errors.New("pq: relation \"secrets\" does not exist at /srv/app.go:42")
	}
	rec := serve(t, r, newPorts(), apihost.Policy{}, get("/widgets"))
	p = problemOf(t, rec, 500, apitypes.ProblemTypeInternal)
	if p.Detail != nil || strings.Contains(rec.Body.String(), "relation") {
		t.Fatalf("internal error leaked: %s", rec.Body)
	}
}

func TestUnknownRouteAndMethodAreProblems(t *testing.T) {
	doc, _ := apihost.ParseDocument(docJSON([4]string{"l", "GET", "/widgets", "widgets.read"}))
	s, err := apihost.Build(doc, []apihost.TagHandlers{tag(&row{meta: meta("l", "GET", "/widgets", "widgets.read")})}, apihost.Policy{}, catalogue, newPorts().ports())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, get("/nothing"))
	problemOf(t, rec, 404, apitypes.ProblemTypeNotFound)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/index.html", nil))
	problemOf(t, rec, 404, apitypes.ProblemTypeNotFound)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, post("/widgets", "application/json", "{}"))
	problemOf(t, rec, 405, apitypes.ProblemTypeMethodNotAllowed)
	if !strings.Contains(rec.Header().Get("Allow"), "GET") {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}
}

func TestSuccessResponse(t *testing.T) {
	r := &row{meta: meta("l", "GET", "/widgets", "widgets.read")}
	r.meta.Deprecated, r.meta.Sunset = true, "2027-01-02"
	r.call = func(context.Context, apihost.Input) (apihost.Response, error) {
		return resp{status: 201, body: map[string]string{"id": "w1"}, hdr: map[string]string{"Location": "/api/v1/widgets/w1"}}, nil
	}
	rec := serve(t, r, newPorts(), apihost.Policy{}, get("/widgets"))
	if rec.Code != 201 || rec.Header().Get("Content-Type") != "application/json" || rec.Body.String() != `{"id":"w1"}` ||
		rec.Header().Get("Location") == "" || rec.Header().Get("Deprecation") != "true" ||
		rec.Header().Get("Sunset") != "Sat, 02 Jan 2027 00:00:00 GMT" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	r.call = func(context.Context, apihost.Input) (apihost.Response, error) { return resp{status: 204}, nil }
	if rec := serve(t, r, newPorts(), apihost.Policy{}, get("/widgets")); rec.Code != 204 || rec.Body.Len() != 0 {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
	r.call = func(context.Context, apihost.Input) (apihost.Response, error) {
		return resp{status: 200, body: apihost.Stream{Reader: strings.NewReader("a,b\n"), ContentType: "text/csv", Filename: "w.csv"}}, nil
	}
	rec = serve(t, r, newPorts(), apihost.Policy{}, get("/widgets"))
	if rec.Body.String() != "a,b\n" || rec.Header().Get("Content-Type") != "text/csv" || rec.Header().Get("Content-Disposition") != "" {
		t.Fatalf("%v %q", rec.Header(), rec.Body)
	}
	// An unencodable body is a problem, never a half-written 200.
	r.call = func(context.Context, apihost.Input) (apihost.Response, error) {
		return resp{status: 200, body: make(chan int)}, nil
	}
	problemOf(t, serve(t, r, newPorts(), apihost.Policy{}, get("/widgets")), 500, apitypes.ProblemTypeInternal)
}

func TestHandlerSeesPrincipalAndTrace(t *testing.T) {
	r := &row{meta: meta("l", "GET", "/widgets", "widgets.read")}
	r.call = func(ctx context.Context, _ apihost.Input) (apihost.Response, error) {
		p, ok := apihost.PrincipalFrom(ctx)
		if !ok || p.ID != "p1" || apihost.TraceID(ctx) == "" {
			t.Errorf("ctx principal %+v %v trace %q", p, ok, apihost.TraceID(ctx))
		}
		return resp{status: 204}, nil
	}
	rec := serve(t, r, newPorts(), apihost.Policy{}, get("/widgets"))
	if rec.Code != 204 || rec.Header().Get("X-Trace-Id") == "" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
}
