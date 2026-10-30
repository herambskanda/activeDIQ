package apihost_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

func consoleServer(t *testing.T, console *fstest.MapFS) http.Handler {
	t.Helper()
	d, err := apihost.ParseDocument(docJSON([4]string{"listWidgets", "GET", "/widgets", "widgets.read"}))
	if err != nil {
		t.Fatal(err)
	}
	r := &row{meta: meta("listWidgets", "GET", "/widgets", "widgets.read")}
	var opts []apihost.Option
	if console != nil {
		opts = append(opts, apihost.WithConsole(console))
	}
	s, err := apihost.Build(d, []apihost.TagHandlers{tag(r)}, apihost.Policy{}, catalogue, newPorts().ports(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConsoleServing(t *testing.T) {
	h := consoleServer(t, &fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><title>activeDIQ</title>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	})
	get := func(method, p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, p, nil))
		return rec
	}
	for _, p := range []string{"/", "/directory/users", "/directory/users?q=ada"} {
		rec := get("GET", p)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<title>activeDIQ") {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Body.String())
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "script-src 'self' 'unsafe") {
			t.Errorf("%s: csp %q", p, csp)
		}
		if rec.Header().Get("Cache-Control") != "no-cache" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: headers %v", p, rec.Header())
		}
	}
	if rec := get("GET", "/assets/app.js"); rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Errorf("asset: %d %v", rec.Code, rec.Header())
	}
	if rec := get("HEAD", "/directory/users"); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("head: %d %d", rec.Code, rec.Body.Len())
	}
	// A missing file is a 404 problem, not the shell; the API's unknown paths stay problems.
	problemOf(t, get("GET", "/assets/missing.js"), 404, apitypes.ProblemTypeNotFound)
	problemOf(t, get("GET", "/api/v1/nothing"), 404, apitypes.ProblemTypeNotFound)
	problemOf(t, get("GET", "/api"), 404, apitypes.ProblemTypeNotFound)
	// The console is read-only: a POST outside the API is not served the shell.
	problemOf(t, get("POST", "/directory/users"), 404, apitypes.ProblemTypeNotFound)
	// The API route still wins over the shell.
	if rec := get("GET", "/api/v1/widgets"); strings.Contains(rec.Body.String(), "<title>") {
		t.Errorf("api route answered the shell")
	}
}

func TestNoConsoleServesNothing(t *testing.T) {
	h := consoleServer(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	problemOf(t, rec, 404, apitypes.ProblemTypeNotFound)
}
