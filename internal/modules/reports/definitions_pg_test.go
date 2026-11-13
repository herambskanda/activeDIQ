package reports_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports"
	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	lib "github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
	"github.com/skenzeriq/activediq/internal/platform/export/pdf"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

// defEnv serves the two definition operations over the shipped library through the whole HTTP stack, with
// every response checked against the OpenAPI contract.
type defEnv struct {
	t   *testing.T
	lib *lib.Library
	srv http.Handler
}

func defSetup(t *testing.T, s *storetest.Server, withLibrary bool) *defEnv {
	t.Helper()
	return defSetupExports(t, s, withLibrary, false)
}

// defSetupExports is defSetup with, when withExports, an export service wired in (never called: the
// definition view only asks whether exports exist on this installation).
func defSetupExports(t *testing.T, s *storetest.Server, withLibrary, withExports bool) *defEnv {
	t.Helper()
	ctx := context.Background()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "t")
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var reg *reportsql.Registry
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		sc, err := reportsql.CatalogSchema(ctx, tx)
		if err != nil {
			return err
		}
		reg, err = reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: inventory.SecretKey}, inventory.Datasets()...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	l, err := lib.Load(lib.Shipped(), lib.Options{Datasets: inventory.Datasets(), Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	h := &reports.Handlers{}
	if withLibrary {
		h.Library = l
	}
	if withExports {
		h.Exports = &export.Service{}
	}
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	var rec apitest.Recorder
	perms := apihost.Permissions{"reports.deliver.external", "reports.export", "reports.run", "reports.schedule", "reports.schedule.manage_all",
		"directory.read", "connections.takeover.attest", "siem.destination.manage", "siem.destination.read"}
	srv, err := apihost.Build(doc, apitest.Conform(&rec, h.Bind()), pol, perms, apihost.Ports{Authn: &door{allow: true}, Authz: &door{allow: true}, Limits: &door{}, StepUp: &door{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if v := rec.All(); len(v) > 0 {
			t.Errorf("response conformance: %v", v)
		}
	})
	return &defEnv{t: t, lib: l, srv: srv}
}

func (e *defEnv) get(path string) (int, map[string]any) {
	e.t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("X-Who", alice)
	r.Header.Set("X-Tenant", "00000000-0000-4000-8000-000000000001")
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	var out map[string]any
	_ = jsonv2.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func ids(m map[string]any) []string {
	var out []string
	for _, it := range m["items"].([]any) {
		out = append(out, it.(map[string]any)["id"].(string))
	}
	return out
}

func cursorOf(m map[string]any) string {
	c, _ := m["page"].(map[string]any)["nextCursor"].(string)
	return c
}

func meNames(item any) [][2]string {
	var out [][2]string
	for _, n := range item.(map[string]any)["alsoKnownAs"].([]any) {
		m := n.(map[string]any)
		out = append(out, [2]string{m["meName"].(string), m["presetId"].(string)})
	}
	return out
}

// Acceptance 1: every shipped definition appears once, with id, category, name and the ME names, in the
// order category then name, and a cursor appears when limit is below the count.
func TestListReportDefinitionsEveryShippedDefinitionOnceInStableOrder(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := defSetup(t, s, true)
		code, all := e.get("/api/v1/reports/definitions")
		if code != 200 {
			t.Fatalf("list: %d %v", code, all)
		}
		// The order is the category order, then the title: users (Account expiry, Locked-out users, Logon
		// activity, Users), passwords (Password changes, Password expiry), groups (Group members, Groups,
		// Groups for users, Not in any group), computers (Computer inactivity, Computers), contacts, OUs.
		want := []string{"usr-02", "usr-05", "usr-03", "usr-04", "usr-01", "pwd-02", "pwd-01", "pwd-03", "grp-02", "grp-01", "grp-03", "grp-04", "cmp-02", "cmp-01", "ctc-01", "ou-01"}
		if got := ids(all); !slices.Equal(got, want) {
			t.Fatalf("ids = %v, want %v", got, want)
		}
		if len(e.lib.List()) != len(want) {
			t.Fatalf("the library ships %d definitions, the test knows %d: extend the order above", len(e.lib.List()), len(want))
		}
		if cursorOf(all) != "" {
			t.Errorf("the whole library fits one page but a cursor was returned")
		}
		byID := map[string]lib.Item{}
		for _, it := range e.lib.List() {
			byID[string(it.Def.ID)] = it
		}
		for _, raw := range all["items"].([]any) {
			it := raw.(map[string]any)
			d := byID[it["id"].(string)].Def
			wantCategory := string(d.Category)
			if wantCategory == "ous" { // the API names it in full
				wantCategory = "organizational_units"
			}
			if it["name"] != d.Title || it["category"] != wantCategory || it["version"] != float64(d.Version) || it["dataset"] != string(d.Dataset) ||
				it["description"] != d.Description || it["freshnessKind"] != "nc_watermark" {
				t.Errorf("%s: summary %v does not match its definition", d.ID, it)
			}
			var wantNames [][2]string
			for _, p := range d.Presets {
				for _, n := range p.Names {
					wantNames = append(wantNames, [2]string{n, p.ID})
				}
			}
			if got := meNames(it); !slices.Equal(got, wantNames) {
				t.Errorf("%s: also known as %v, want %v", d.ID, got, wantNames)
			}
		}

		// A page of two, then the next two: the cursor walks the same order, once each.
		code, p1 := e.get("/api/v1/reports/definitions?limit=2")
		if code != 200 || !slices.Equal(ids(p1), want[:2]) || cursorOf(p1) == "" {
			t.Fatalf("page 1: %d %v", code, p1)
		}
		code, p2 := e.get("/api/v1/reports/definitions?limit=2&cursor=" + url.QueryEscape(cursorOf(p1)))
		if code != 200 || !slices.Equal(ids(p2), want[2:4]) || cursorOf(p2) == "" {
			t.Fatalf("page 2: %d %v", code, p2)
		}
		// Page size one visits every report exactly once.
		var seen []string
		cur := ""
		for i := 0; i < 2*len(want); i++ {
			q := "/api/v1/reports/definitions?limit=1"
			if cur != "" {
				q += "&cursor=" + url.QueryEscape(cur)
			}
			_, pg := e.get(q)
			seen = append(seen, ids(pg)...)
			if cur = cursorOf(pg); cur == "" {
				break
			}
		}
		if !slices.Equal(seen, want) {
			t.Errorf("walking by one: %v, want %v", seen, want)
		}
		if code, bad := e.get("/api/v1/reports/definitions?cursor=bm90IGEgY3Vyc29y"); code != 400 || errCode(bad) != "bad_cursor" {
			t.Errorf("a cursor this server did not issue: %d %v", code, bad)
		}
		if code, _ := e.get("/api/v1/reports/definitions?limit=0"); code != 400 {
			t.Errorf("limit 0: %d, want 400", code)
		}
	})
}

// Acceptance 2 (FR-02): an ME name finds the owning report with that name at the head of its alias line; a
// category filter keeps only that category; a query with no match is an empty page.
func TestListReportDefinitionsSearchByMEName(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := defSetup(t, s, true)
		for _, q := range []string{"Inactive Users", "inactive users", "INACTIVE-USERS"} {
			code, got := e.get("/api/v1/reports/definitions?q=" + url.QueryEscape(q))
			if code != 200 {
				t.Fatalf("q=%q: %d %v", q, code, got)
			}
			if g := ids(got); len(g) == 0 || g[0] != "usr-03" {
				t.Fatalf("q=%q: ids %v, want usr-03 first", q, g)
			}
			first := got["items"].([]any)[0]
			if n := meNames(first); n[0] != [2]string{"Inactive Users", "inactive"} {
				t.Errorf("q=%q: matched alias is not first: %v", q, n)
			}
		}

		// "Recently Logged on Users" is the preset "recent" of usr-03 (the alias line is not the preset order).
		_, got := e.get("/api/v1/reports/definitions?q=" + url.QueryEscape("Users Never Logged On"))
		first := got["items"].([]any)[0]
		if ids(got)[0] != "usr-03" || meNames(first)[0] != [2]string{"Users Never Logged On", "never"} {
			t.Errorf("Users Never Logged On: %v", got)
		}

		// A word of the description finds a report that no ME name or title holds.
		_, got = e.get("/api/v1/reports/definitions?q=replicated")
		if g := ids(got); !slices.Contains(g, "usr-03") {
			t.Errorf("description search: %v", g)
		}

		// A name whose preset is not shipped yet (needs the manager attribute, T-1041) finds nothing: it is not answered by a
		// report that does not hold it.
		code, none := e.get("/api/v1/reports/definitions?q=" + url.QueryEscape("Users Without Managers"))
		if code != 200 || len(ids(none)) != 0 || cursorOf(none) != "" {
			t.Errorf("a pending ME name: %d %v", code, none)
		}
		if code, none = e.get("/api/v1/reports/definitions?q=zzzzqq"); code != 200 || none["items"] == nil || len(ids(none)) != 0 {
			t.Errorf("no match must be an empty page: %d %v", code, none)
		}

		code, users := e.get("/api/v1/reports/definitions?category=users")
		if code != 200 || !slices.Equal(ids(users), []string{"usr-02", "usr-05", "usr-03", "usr-04", "usr-01"}) {
			t.Errorf("category users: %d %v", code, ids(users))
		}
		if code, other := e.get("/api/v1/reports/definitions?category=groups"); code != 200 || !slices.Equal(ids(other), []string{"grp-02", "grp-01", "grp-03", "grp-04"}) {
			t.Errorf("category groups: %d %v", code, ids(other))
		}
		if code, _ := e.get("/api/v1/reports/definitions?category=organizational_units"); code != 200 {
			t.Errorf("organizational_units is a category: %d", code)
		}
		if code, _ := e.get("/api/v1/reports/definitions?category=ous"); code != 400 {
			t.Errorf("ous is the engine's name, not the API's: %d, want 400", code)
		}
		// q is plain text: a character of filter syntax is refused by the contract before any handler runs.
		if code, _ := e.get("/api/v1/reports/definitions?q=" + url.QueryEscape("*)(uid=*")); code != 400 {
			t.Errorf("filter syntax in q: %d, want 400", code)
		}
		// q and category together, and a search that spans pages.
		_, both := e.get("/api/v1/reports/definitions?q=users&category=users&limit=1")
		if len(ids(both)) != 1 || cursorOf(both) == "" {
			t.Errorf("q + category + limit: %v", both)
		}
	})
}

// Acceptance 3: the definition carries columns, filters, presets and parameters as the contract states, and
// an unknown ID or version is 404 definition_not_found.
func TestGetReportDefinition(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := defSetup(t, s, true)

		// Reconciliation: for every shipped definition, the response agrees with the library entry.
		for _, it := range e.lib.List() {
			d := it.Def
			code, got := e.get("/api/v1/reports/definitions/" + string(d.ID))
			if code != 200 {
				t.Fatalf("%s: %d %v", d.ID, code, got)
			}
			if got["id"] != string(d.ID) || got["version"] != float64(d.Version) || got["name"] != d.Title || got["perDc"] != (d.PerDC != nil) ||
				got["minScheduleIntervalHours"] != wantMinInterval(d) || got["subjectKind"] != wantSubjectKind(d) {
				t.Errorf("%s: header %v", d.ID, got)
			}
			if ef := got["exportFormats"].([]any); len(ef) != 0 {
				t.Errorf("%s: this host has no export service, yet the definition offers %v", d.ID, ef)
			}
			var presets []string
			for _, p := range got["presets"].([]any) {
				presets = append(presets, p.(map[string]any)["id"].(string))
			}
			var wantPresets []string
			for _, p := range d.Presets {
				wantPresets = append(wantPresets, p.ID)
			}
			if !slices.Equal(presets, wantPresets) {
				t.Errorf("%s: presets %v, want %v", d.ID, presets, wantPresets)
			}
			var visible, all []string
			for _, c := range got["columns"].([]any) {
				m := c.(map[string]any)
				all = append(all, m["id"].(string))
				if m["defaultVisible"] == true {
					visible = append(visible, m["id"].(string))
				}
			}
			var wantVisible []string
			for _, c := range d.Columns {
				wantVisible = append(wantVisible, string(c))
			}
			if !slices.Equal(visible, wantVisible) || !slices.Equal(all[:len(visible)], wantVisible) {
				t.Errorf("%s: default columns %v, want %v first", d.ID, visible, wantVisible)
			}
			if len(all) != len(slices.Compact(slices.Sorted(slices.Values(all)))) {
				t.Errorf("%s: a column is listed twice: %v", d.ID, all)
			}
		}

		// usr-03: the Inactive Users preset opens with 90 days, and its filters say what it filters.
		code, got := e.get("/api/v1/reports/definitions/usr-03?version=1")
		if code != 200 {
			t.Fatalf("usr-03 v1: %d %v", code, got)
		}
		var inactive map[string]any
		for _, p := range got["presets"].([]any) {
			if p.(map[string]any)["id"] == "inactive" {
				inactive = p.(map[string]any)
			}
		}
		if inactive == nil || inactive["name"] != "Inactive Users" || inactive["meName"] != "Inactive Users" || inactive["periodDays"] != float64(90) {
			t.Fatalf("inactive preset: %v", inactive)
		}
		fs := inactive["filters"].([]any)
		if len(fs) != 2 {
			t.Fatalf("inactive filters: %v", fs)
		}
		enabled := fs[0].(map[string]any)
		v := enabled["values"].([]any)[0].(map[string]any)
		if enabled["kind"] != "condition" || enabled["column"] != "enabled" || enabled["operator"] != "equals" || v["kind"] != "boolean" || v["value"] != true {
			t.Errorf("filter 1: %v", enabled)
		}
		any1 := fs[1].(map[string]any)
		if any1["kind"] != "group" || any1["match"] != "any" || len(any1["filters"].([]any)) != 2 {
			t.Fatalf("filter 2: %v", any1)
		}
		older := any1["filters"].([]any)[0].(map[string]any)["filters"].([]any)[1].(map[string]any)
		ov := older["values"].([]any)[0].(map[string]any)
		if older["column"] != "last_logon_timestamp" || older["operator"] != "older_than" || ov["kind"] != "integer" || ov["value"] != float64(90) {
			t.Errorf("the threshold must show the parameter's default: %v", older)
		}
		// A column that a filter may use says which operators it takes.
		for _, c := range got["columns"].([]any) {
			m := c.(map[string]any)
			if m["id"] == "last_logon_timestamp" {
				if m["filterable"] != true || !slices.Contains(toStrings(m["filterOperators"]), "older_than") || m["type"] != "time" {
					t.Errorf("last_logon_timestamp: %v", m)
				}
			}
		}

		// usr-01 "all" has no filter and no period.
		_, u1 := e.get("/api/v1/reports/definitions/usr-01")
		for _, p := range u1["presets"].([]any) {
			m := p.(map[string]any)
			if m["id"] == "all" && (len(m["filters"].([]any)) != 0 || m["periodDays"] != nil) {
				t.Errorf("all: %v", m)
			}
			if m["id"] == "recently_created" && m["periodDays"] != float64(30) {
				t.Errorf("recently_created: %v", m)
			}
		}

		for _, bad := range []string{"/api/v1/reports/definitions/usr-99", "/api/v1/reports/definitions/usr-03?version=2", "/api/v1/reports/definitions/usr-03?version=1000000"} {
			if code, p := e.get(bad); code != 404 || errCode(p) != "definition_not_found" {
				t.Errorf("%s: %d %v, want 404 definition_not_found", bad, code, p)
			}
		}
		if code, _ := e.get("/api/v1/reports/definitions/usr-03?version=0"); code != 400 {
			t.Errorf("version 0: %d, want 400", code)
		}
		if code, _ := e.get("/api/v1/reports/definitions/USR-03"); code != 400 && code != 404 {
			t.Errorf("an ID outside the pattern: %d", code)
		}
	})
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// A handler set with no library fails closed instead of answering an empty library.
func TestDefinitionsWithoutLibraryAreNotReady(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := defSetup(t, s, false)
		if code, _ := e.get("/api/v1/reports/definitions"); code != 503 {
			t.Errorf("list without a library: %d, want 503", code)
		}
		if code, _ := e.get("/api/v1/reports/definitions/usr-01"); code != 503 {
			t.Errorf("get without a library: %d, want 503", code)
		}
	})
}

// AC-4: a definition lists the formats this installation can produce. With the export service wired every
// shipped definition (all within a PDF page's 24 columns) offers csv, xlsx, pdf and html; without it, none.
func TestDefinitionOffersExportFormats(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		with := defSetupExports(t, s, true, true)
		for _, it := range with.lib.List() {
			code, got := with.get("/api/v1/reports/definitions/" + string(it.Def.ID))
			if code != 200 {
				t.Fatalf("%s: %d", it.Def.ID, code)
			}
			var offered []string
			for _, f := range got["exportFormats"].([]any) {
				offered = append(offered, f.(string))
			}
			want := []string{"csv", "xlsx", "pdf", "html"}
			if widest(it.Def) > pdf.MaxColumns {
				want = []string{"csv", "xlsx", "html"}
			}
			if !slices.Equal(offered, want) {
				t.Errorf("%s (%d columns): exportFormats = %v, want %v", it.Def.ID, widest(it.Def), offered, want)
			}
		}
	})
}

func widest(d report.Definition) int {
	n := len(d.Columns)
	for _, p := range d.Presets {
		n = max(n, len(p.Columns))
	}
	return n
}

// wantSubjectKind is what the API says a definition's subjects are: none without a preset that needs
// subjects, otherwise the kind the preset names ("object" when it names none).
func wantSubjectKind(d report.Definition) string {
	kind := "none"
	for _, p := range d.Presets {
		if p.Requires != nil {
			kind = "object"
			if p.Requires.Kind != "" {
				kind = p.Requires.Kind
			}
		}
	}
	return kind
}

// wantMinInterval is the shortest schedule interval a definition allows: a per-DC report reads every DC, so a day.
func wantMinInterval(d report.Definition) float64 {
	if d.PerDC != nil {
		return 24
	}
	return 1
}
