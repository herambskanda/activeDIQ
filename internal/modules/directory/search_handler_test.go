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

	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/modules/search"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Handler tests of searchDirectory (T-1096, ADR-0011): the authentication and permission edge, the mapping of
// the service's answers and refusals to the contract, and that the text of a query is neither echoed nor logged.

type fakeSearch struct {
	calls int
	got   search.Call
	res   search.Result
	err   error
}

func (f *fakeSearch) Search(_ context.Context, c search.Call) (search.Result, error) {
	f.calls++
	f.got = c
	return f.res, f.err
}

// denyAll is an Authorizer that refuses every permission; failAuthn an Authenticator that cannot identify.
type denyAll struct{ ports }

func (denyAll) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return false, nil
}

type failAuthn struct{ ports }

func (failAuthn) Authenticate(*http.Request) (apihost.Principal, error) {
	return apihost.Principal{}, apihost.ErrUnauthenticated
}

func postSearch(t *testing.T, h directory.Handlers, authn apihost.Authenticator, authzr apihost.Authorizer, body string) *httptest.ResponseRecorder {
	t.Helper()
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := apihost.Build(doc, []apihost.TagHandlers{h.Bind()}, pol, apitest.Catalogue(doc), apihost.Ports{Authn: authn, Authz: authzr, Limits: ports{}, StepUp: ports{}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/v1/directory/search", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

func problemType(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("content type = %q, body %s", ct, w.Body)
	}
	var p struct {
		Type string `json:"type"`
	}
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p.Type
}

// AC6: unauthenticated is 401, a caller without directory.read is 403 (the shared Problem), a token and a
// missing service are 403 — and the service is never reached in any of them.
func TestSearchDirectoryRefusesBeforeTheServiceIsReached(t *testing.T) {
	cases := map[string]struct {
		h      func(*fakeSearch) directory.Handlers
		authn  apihost.Authenticator
		authz  apihost.Authorizer
		status int
		typ    string
	}{
		"unauthenticated":   {func(f *fakeSearch) directory.Handlers { return directory.Handlers{Searcher: f} }, failAuthn{}, ports{}, 401, "/problems/unauthenticated"},
		"no directory.read": {func(f *fakeSearch) directory.Handlers { return directory.Handlers{Searcher: f} }, ports{}, denyAll{}, 403, "/problems/forbidden"},
		"token principal":   {func(f *fakeSearch) directory.Handlers { return directory.Handlers{Searcher: f} }, tokenPorts{}, ports{}, 403, "/problems/forbidden"},
		"no search service": {func(*fakeSearch) directory.Handlers { return directory.Handlers{} }, ports{}, ports{}, 403, "/problems/forbidden"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeSearch{}
			w := postSearch(t, c.h(f), c.authn, c.authz, `{"q":"priya raman"}`)
			if w.Code != c.status {
				t.Fatalf("status = %d, body %s", w.Code, w.Body)
			}
			if got := problemType(t, w); !strings.HasSuffix(got, c.typ) {
				t.Errorf("problem type = %q, want …%s", got, c.typ)
			}
			if f.calls != 0 {
				t.Errorf("service reached %d times", f.calls)
			}
			if strings.Contains(w.Body.String(), "priya") {
				t.Error("the problem repeats the query")
			}
		})
	}
}

// AC6: the call carries the authenticated tenant and the human behind the session, and a read is not an
// audited change: the handler has no audit dependency and the operation is class read.
func TestSearchDirectoryPassesTheSessionAndAppendsNothing(t *testing.T) {
	f := &fakeSearch{}
	w := postSearch(t, directory.Handlers{Searcher: f}, ports{}, ports{}, `{"q":"priya raman","type":"users","groupLimit":7}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if f.calls != 1 || f.got.Text != "priya raman" || f.got.Limit != 7 || f.got.Type != reportsql.TypeUser {
		t.Errorf("call = %+v (%d)", f.got, f.calls)
	}
	if f.got.Tenant.String() != tenantText || f.got.Chain.Requester.ID != "admin" || f.got.Chain.Requester.Kind != authority.Human {
		t.Errorf("identity = %v %+v", f.got.Tenant, f.got.Chain)
	}
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range doc.Operations() {
		if op.ID == "searchDirectory" && op.Class != "read" {
			t.Errorf("class = %q", op.Class)
		}
	}
}

// AC5: a recovery-password-shaped query (ASCII or full-width digits) is a 400 with a code, no digits in the
// response, none in the log, and the index is never asked. Run through the real service.
func TestSearchDirectoryRefusesARecoveryPasswordWithoutEchoOrLog(t *testing.T) {
	groups := []string{"123456", "234567", "345678", "456789", "567890", "678901", "789012", "890123"}
	ascii := strings.Join(groups, "-")
	fullWidth := strings.NewReplacer("0", "０", "1", "１", "2", "２", "3", "３", "4", "４", "5", "５", "6", "６", "7", "７", "8", "８", "9", "９").Replace(ascii)
	for name, q := range map[string]string{"ascii": ascii, "full width": fullWidth, "no separators": strings.Join(groups, "")} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			ix := &countingIndex{}
			cur, err := search.NewEphemeralCursors()
			if err != nil {
				t.Fatal(err)
			}
			svc := &search.Service{DB: fakeTenants{}, Scopes: openScopes{}, Index: ix, Cursors: cur, Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
			body, _ := jsonv2.Marshal(map[string]string{"q": q})
			w := postSearch(t, directory.Handlers{Searcher: svc, Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}, ports{}, ports{}, string(body))
			if w.Code != 400 {
				t.Fatalf("status = %d, body %s", w.Code, w.Body)
			}
			if got := problemType(t, w); !strings.HasSuffix(got, "/problems/search-query-invalid") {
				t.Errorf("problem type = %q", got)
			}
			if !strings.Contains(w.Body.String(), `"query_refused"`) {
				t.Errorf("no code in %s", w.Body)
			}
			for _, digits := range append([]string{ascii, fullWidth}, groups...) {
				if strings.Contains(w.Body.String(), digits) || strings.Contains(logs.String(), digits) {
					t.Fatalf("the query digits %q leaked into the response or the log", digits)
				}
			}
			if ix.searches != 0 {
				t.Error("the index was asked")
			}
		})
	}
}

// AC5: a normal query is logged as lengths and classes only, never as text — through the whole handler.
func TestSearchDirectoryLogsANormalQueryWithoutItsText(t *testing.T) {
	var logs bytes.Buffer
	cur, err := search.NewEphemeralCursors()
	if err != nil {
		t.Fatal(err)
	}
	svc := &search.Service{DB: fakeTenants{}, Scopes: openScopes{}, Index: &countingIndex{}, Cursors: cur, Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	const q = "Zebediah Quillfeather"
	w := postSearch(t, directory.Handlers{Searcher: svc}, ports{}, ports{}, `{"q":"`+q+`"}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if strings.Contains(logs.String(), "Zebediah") || strings.Contains(logs.String(), "Quillfeather") || strings.Contains(w.Body.String(), "Zebediah") {
		t.Errorf("the text was logged or echoed:\n%s\n%s", logs.String(), w.Body)
	}
	if logs.Len() == 0 {
		t.Error("nothing was logged: the length and class are expected")
	}
}

// The mapping of the service's refusals to problems; none carries the text.
func TestSearchDirectoryMapsServiceErrors(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		typ    string
		code   string
	}{
		"too short":       {&search.QueryError{Code: search.CodeTooShort}, 400, "/problems/search-query-invalid", search.CodeTooShort},
		"too long":        {&search.QueryError{Code: search.CodeTooLong}, 400, "/problems/search-query-invalid", search.CodeTooLong},
		"cursor":          {search.ErrCursorInvalid, 400, "/problems/search-query-invalid", search.CodeCursor},
		"cursor no type":  {search.ErrCursorRequiresType, 400, "/problems/search-query-invalid", search.CodeCursorTyp},
		"forbidden":       {search.ErrForbidden, 403, "/problems/forbidden", ""},
		"unavailable":     {search.ErrUnavailable, 503, "/problems/search-unavailable", ""},
		"unknown failure": {errors.New("pq: relation secret-table does not exist"), 500, "/problems/internal", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := postSearch(t, directory.Handlers{Searcher: &fakeSearch{err: c.err}}, ports{}, ports{}, `{"q":"anything"}`)
			if w.Code != c.status {
				t.Fatalf("status = %d, body %s", w.Code, w.Body)
			}
			if got := problemType(t, w); !strings.HasSuffix(got, c.typ) {
				t.Errorf("problem type = %q", got)
			}
			if c.code != "" && !strings.Contains(w.Body.String(), `"`+c.code+`"`) {
				t.Errorf("code %s missing in %s", c.code, w.Body)
			}
			if strings.Contains(w.Body.String(), "secret-table") || strings.Contains(w.Body.String(), "anything") {
				t.Errorf("the problem leaks: %s", w.Body)
			}
		})
	}
}

// The 200 mapping: groups in the service's order, status never null, asOf null until a sync has completed,
// and under refine no count, no more and no cursor are sent.
func TestSearchDirectoryMapsTheAnswer(t *testing.T) {
	n := 1
	guid := "aaaaaaaa-0000-4000-8000-00000000000a"
	hit := search.Hit{Type: reportsql.TypeUser, Object: guid, DisplayName: "Priya Raman", Class: reportsql.ClassPrefix,
		Highlights: []search.Highlight{{Field: "displayName", Start: 0, Length: 5}}, DN: "CN=Priya Raman,DC=lab,DC=test", Domain: "lab.test", Status: []search.Chip{{Kind: search.ChipDeleted}}}
	t.Run("normal", func(t *testing.T) {
		f := &fakeSearch{res: search.Result{AsOf: time.Date(2026, 11, 1, 5, 0, 0, 0, time.UTC),
			Groups: []search.Group{{Type: reportsql.TypeUser, Items: []search.Hit{hit}, Count: &n, More: true, NextCursor: "c1"}, {Type: reportsql.TypeGroup}}}}
		w := postSearch(t, directory.Handlers{Searcher: f}, ports{}, ports{}, `{"q":"priya"}`)
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		var got map[string]any
		if err := jsonv2.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		gs := got["groups"].([]any)
		if len(gs) != 2 {
			t.Fatalf("groups = %v", gs)
		}
		u := gs[0].(map[string]any)
		if u["type"] != "users" || u["count"] != float64(1) || u["more"] != true || u["nextCursor"] != "c1" {
			t.Errorf("user group = %v", u)
		}
		item := u["items"].([]any)[0].(map[string]any)
		chips := item["status"].([]any)
		if item["matchClass"] != "prefix" || len(chips) != 1 || chips[0].(map[string]any)["kind"] != "deleted" || item["distinguishedName"] != hit.DN {
			t.Errorf("item = %v", item)
		}
		if got["asOf"] == nil {
			t.Error("asOf missing")
		}
		empty := gs[1].(map[string]any)
		if items, ok := empty["items"].([]any); !ok || len(items) != 0 {
			t.Errorf("an empty group must send items: [] — %v", empty)
		}
	})
	t.Run("refine and no sync yet", func(t *testing.T) {
		f := &fakeSearch{res: search.Result{Refine: true, Groups: []search.Group{{Type: reportsql.TypeUser, Items: []search.Hit{{Type: reportsql.TypeUser, Object: guid, DisplayName: "x"}}, More: true}}}}
		w := postSearch(t, directory.Handlers{Searcher: f}, ports{}, ports{}, `{"q":"pri"}`)
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		var got map[string]any
		if err := jsonv2.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got["refine"] != true {
			t.Errorf("refine = %v", got["refine"])
		}
		if v, present := got["asOf"]; present && v != nil {
			t.Errorf("asOf = %v, want null or absent before any sync", v)
		}
		g := got["groups"].([]any)[0].(map[string]any)
		for _, k := range []string{"count", "more", "nextCursor"} {
			if _, present := g[k]; present {
				t.Errorf("%s sent under refine: %v", k, g)
			}
		}
		if chips, ok := g["items"].([]any)[0].(map[string]any)["status"].([]any); !ok || len(chips) != 0 {
			t.Errorf("status must be an empty array: %v", g["items"])
		}
	})
	t.Run("malformed guid is a fault", func(t *testing.T) {
		bad := hit
		bad.Object = "not-a-guid"
		f := &fakeSearch{res: search.Result{Groups: []search.Group{{Type: reportsql.TypeUser, Items: []search.Hit{bad}}}}}
		w := postSearch(t, directory.Handlers{Searcher: f}, ports{}, ports{}, `{"q":"priya"}`)
		if w.Code != 500 {
			t.Errorf("status = %d", w.Code)
		}
	})
}

// Fakes for the real service in the AC5 tests: an open read scope, a tenant tx that is never used for more than
// a call, and an index that counts.
type openScopes struct{}

func (openScopes) ReadScope(context.Context, tenant.ID, authority.Chain, authz.Permission) (authz.ReadScope, error) {
	return wholeDomain().scope, nil
}

type fakeTenants struct{}

func (fakeTenants) WithTenant(ctx context.Context, _ tenant.ID, fn func(context.Context, store.Tx) error) error {
	return fn(ctx, &storetest.FakeTx{})
}

type countingIndex struct{ searches int }

func (c *countingIndex) Search(context.Context, store.Tx, tenant.ID, reportsql.SearchScopes, inventory.SearchRequest) (inventory.SearchResult, error) {
	c.searches++
	return inventory.SearchResult{}, nil
}

func (*countingIndex) SearchMetadata(context.Context, store.Tx, tenant.ID, authz.ReadScope, time.Time, []reportsql.SearchHit) (map[inventory.SearchRef]inventory.SearchMeta, error) {
	return nil, nil
}

// T-1097 AC4: a hostile DN or title is returned as data, byte for byte, in the contract's fields; chips carry
// their kind, time and days; the disambiguator holds only what was read.
func TestSearchDirectoryReturnsMetadataVerbatim(t *testing.T) {
	guid := "aaaaaaaa-0000-4000-8000-00000000000b"
	long := strings.Repeat("W", 200)
	dn := `CN=<img src=x onerror=alert(1)>\, *)(cn=*,OU=A,DC=corp,DC=example,DC=test`
	days := int64(3)
	at := time.Date(2026, 11, 1, 9, 12, 0, 0, time.UTC)
	hit := search.Hit{Type: reportsql.TypeUser, Object: guid, DisplayName: "Priya Raman", Class: reportsql.ClassExact, DN: dn, Domain: "corp.example.test",
		Title: "<b>Analyst</b>", Department: long,
		Status: []search.Chip{{Kind: search.ChipLocked, At: at}, {Kind: search.ChipPasswordExpiresInDays, Days: &days}, {Kind: search.ChipTier0}}}
	f := &fakeSearch{res: search.Result{Groups: []search.Group{{Type: reportsql.TypeUser, Items: []search.Hit{hit}}}}}
	w := postSearch(t, directory.Handlers{Searcher: f}, ports{}, ports{}, `{"q":"priya"}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	item := got["groups"].([]any)[0].(map[string]any)["items"].([]any)[0].(map[string]any)
	if item["distinguishedName"] != dn || item["domain"] != "corp.example.test" {
		t.Errorf("dn/domain changed: %v / %v", item["distinguishedName"], item["domain"])
	}
	d := item["disambiguator"].(map[string]any)
	if d["title"] != "<b>Analyst</b>" || d["department"] != long || d["office"] != nil {
		t.Errorf("disambiguator = %v", d)
	}
	chips := item["status"].([]any)
	if len(chips) != 3 {
		t.Fatalf("chips = %v", chips)
	}
	c0, c1, c2 := chips[0].(map[string]any), chips[1].(map[string]any), chips[2].(map[string]any)
	if c0["kind"] != "locked" || c0["at"] != "2026-11-01T09:12:00Z" || c1["kind"] != "passwordExpiresInDays" || c1["days"] != float64(3) || c2["kind"] != "tier0" || c2["at"] != nil {
		t.Errorf("chips = %v", chips)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content type %q: a field could be read as markup", ct)
	}
}
