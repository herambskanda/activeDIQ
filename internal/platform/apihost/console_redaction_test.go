package apihost_test

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// Test_console_search_query_never_reaches_a_log_line is ADR-0011 rule 15 (console) and SE4's
// "Search text" item: a GET of the console's /search route with q (and, should a client ever put
// one there, a cursor) in the query string is answered, and neither value appears in any log line
// at any level, in the response headers or in a problem body, on every route the server has: the
// console shell, a missing console file, a non-GET method, the API and an unknown API path. The
// server records the path only.
func Test_console_search_query_never_reaches_a_log_line(t *testing.T) {
	const secret = "Raman-Priya-SECRET-q"
	const cursor = "eyJTRUNSRVQtY3Vyc29yIjoxfQ"
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	d, err := apihost.ParseDocument(docJSON([4]string{"listWidgets", "GET", "/widgets", "widgets.read"}))
	if err != nil {
		t.Fatal(err)
	}
	r := &row{meta: meta("listWidgets", "GET", "/widgets", "widgets.read")}
	console := &fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>activeDIQ</title>")}}
	h, err := apihost.Build(d, []apihost.TagHandlers{tag(r)}, apihost.Policy{}, catalogue, newPorts().ports(),
		apihost.WithConsole(console), apihost.WithLogger(log))
	if err != nil {
		t.Fatal(err)
	}

	q := url.Values{"q": {secret}, "type": {"user"}, "cursor": {cursor}}.Encode()
	cases := []struct {
		method, path string
		want         int
	}{
		{"GET", "/search?" + q, 200},
		{"HEAD", "/search?" + q, 200},
		{"GET", "/search/missing.js?" + q, 404},
		{"POST", "/search?" + q, 0},
		{"GET", "/api/v1/widgets?" + q, 0},
		{"GET", "/api/v1/nowhere?" + q, 0},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if c.want != 0 && rec.Code != c.want {
			t.Errorf("%s %s: status %d, want %d", c.method, c.path, rec.Code, c.want)
		}
		for name, vals := range rec.Header() {
			for _, v := range vals {
				if strings.Contains(v, secret) || strings.Contains(v, cursor) {
					t.Errorf("%s %s: header %s carries the query: %q", c.method, c.path, name, v)
				}
			}
		}
		if b := rec.Body.String(); strings.Contains(b, secret) || strings.Contains(b, cursor) {
			t.Errorf("%s %s: body carries the query: %q", c.method, c.path, b)
		}
	}
	if s := logs.String(); strings.Contains(s, secret) || strings.Contains(s, cursor) ||
		strings.Contains(s, url.QueryEscape(secret)) {
		t.Errorf("a log line carries the search text or cursor:\n%s", s)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/search?"+q, nil))
	if rp := rec.Header().Get("Referrer-Policy"); rp != "no-referrer" {
		t.Errorf("console Referrer-Policy %q: the /search URL could leave in a Referer header", rp)
	}
}
