package library_test

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// specRow is one row of reports-2a 6.2 for a batch-1 report, as the spec table words it. Columns are the
// registry column that shows each spec column. Deviations are the places the shipped definition differs
// from the table today, each with the ticket that closes it; a deviation not listed here fails the test.
type specRow struct {
	id         string
	title      string
	category   report.Category
	dataset    report.DatasetID
	presets    map[string][]string // preset ID -> ME names
	columns    []string
	deviations []string
}

var specRows = []specRow{
	{"usr-01", "Users", report.CategoryUsers, "inventory.users",
		map[string][]string{"all": {"All Users"}, "enabled": {"Enabled Users"}, "disabled": {"Disabled Users"}, "recently_created": {"Recently Created Users"}},
		// Name, Logon name, UPN, Status, Domain, OU path, Manager, Created
		[]string{"display_name", "sam_account_name", "user_principal_name", "enabled", "domain", "dn", "when_created"},
		[]string{"OU path is shown by the dn column (T-1041 adds the masked OU path)", "Manager column and the Users Without Managers preset wait for T-1041"}},
	{"usr-02", "Account expiry", report.CategoryUsers, "inventory.users",
		map[string][]string{"expired": {"Account Expired Users"}, "recently_expired": {"Recently Account Expired Users"},
			"soon": {"Soon-to-expire User Accounts"}, "never": {"Account Never Expires Users"}},
		// Name, Logon name, Domain, OU path, Account expires, Days to / since expiry, Status
		[]string{"display_name", "sam_account_name", "domain", "dn", "account_expires", "days_to_account_expiry", "enabled"},
		[]string{"OU path is shown by the dn column (T-1041)"}},
	{"usr-03", "Logon activity", report.CategoryUsers, "inventory.users",
		map[string][]string{"inactive": {"Inactive Users"}, "recent": {"Recently Logged on Users"}, "never": {"Users Never Logged On"}},
		// Name, Logon name, Domain, OU path, Last logon (replicated), Days since, Created, Status, Probable service account
		[]string{"display_name", "sam_account_name", "domain", "dn", "last_logon_timestamp", "days_since_logon", "when_created", "enabled",
			"probable_service_account", "probable_service_account_reason"},
		[]string{"OU path is shown by the dn column (T-1041)", "adds the service-account reason column (spec 6.7: every flagged row shows its reason)"}},
	{"usr-05", "Locked-out users", report.CategoryUsers, "inventory.users",
		map[string][]string{"locked_out": {"Locked-out Users"}},
		// Name, Logon name, Domain, OU path, Locked out since, Lockout ends, Policy source, Data as of
		[]string{"display_name", "sam_account_name", "domain", "dn", "lockout_time", "lockout_ends_at", "policy_source", "observed_at"},
		[]string{"OU path is shown by the dn column (T-1041)"}},
}

// reports_library_matches_spec (AC-01): each batch-1 report has the ID, category, dataset, presets and
// default columns of the 6.2 row.
func Test_reports_library_matches_spec(t *testing.T) {
	l := shipped(t)
	items := l.List()
	if len(items) != len(specRows) {
		t.Fatalf("library lists %d reports, want %d", len(items), len(specRows))
	}
	for i, row := range specRows {
		d := items[i].Def
		if string(d.ID) != row.id || d.Title != row.title || d.Category != row.category || d.Dataset != row.dataset || d.Version != 1 {
			t.Errorf("%s: got %s %q %s %s v%d", row.id, d.ID, d.Title, d.Category, d.Dataset, d.Version)
		}
		if got := d.Columns; !slices.Equal(got, toCols(row.columns)) {
			t.Errorf("%s: columns %v, want %v", row.id, got, row.columns)
		}
		if len(d.Presets) != len(row.presets) {
			t.Errorf("%s: %d presets, want %d", row.id, len(d.Presets), len(row.presets))
		}
		for pid, names := range row.presets {
			p, ok := d.Preset(pid)
			if !ok || !slices.Equal(p.Names, names) {
				t.Errorf("%s/%s: names %v, want %v", row.id, pid, p.Names, names)
			}
		}
		if len(row.deviations) == 0 {
			t.Errorf("%s: no deviations listed; delete this check if there are none", row.id)
		}
	}
	// The crosswalk answers every ME name of 6.2: 54.
	if n := len(l.Names()); n != 54 {
		t.Errorf("crosswalk lists %d names, spec 6.2 says 54", n)
	}
}

func toCols(s []string) []report.ColumnID {
	out := make([]report.ColumnID, len(s))
	for i, c := range s {
		out[i] = report.ColumnID(c)
	}
	return out
}

// Default filters of 6.2/6.4/6.7 and the E2 and AC-16 rules, read from the definitions.
func Test_reports_library_default_filters(t *testing.T) {
	l := shipped(t)
	d3, _ := l.Definition("usr-03", 0)
	p, _ := d3.Def.Preset("") // the default preset opens without Generate (FR-04)
	if p.ID != "inactive" {
		t.Fatalf("default preset of usr-03 is %s", p.ID)
	}
	var svc, sync *report.HiddenGroup
	for i := range p.Hidden {
		switch p.Hidden[i].ID {
		case "service_accounts":
			svc = &p.Hidden[i]
		case "sync_off":
			sync = &p.Hidden[i]
		}
	}
	if svc == nil || svc.Locked || sync == nil || !sync.Locked {
		t.Fatalf("hidden groups: service %+v, sync %+v", svc, sync)
	}
	// 90 days default, 30-day floor (spec 6.4).
	for _, c := range []struct {
		days int64
		code report.Code
	}{{29, report.CodeBelowFloor}, {7, report.CodeBelowFloor}} {
		_, err := report.Resolve(d3.Def, "inactive", report.RunParams{Params: map[string]report.ParamValue{"days": report.DaysP(c.days)}}, d3.Dataset)
		if got, _ := report.CodeOf(err); got != c.code {
			t.Errorf("days=%d: %v, want %s", c.days, err, c.code)
		}
	}
	if _, err := report.Resolve(d3.Def, "inactive", report.RunParams{Params: map[string]report.ParamValue{"days": report.DaysP(30)}}, d3.Dataset); err != nil {
		t.Errorf("days=30: %v", err)
	}
	// AC-16: the sync-off group cannot be shown; the service-account group can.
	if _, err := report.Resolve(d3.Def, "inactive", report.RunParams{ShowHidden: []string{"sync_off"}}, d3.Dataset); err == nil {
		t.Error("sync_off was shown")
	}
	q, err := report.Resolve(d3.Def, "inactive", report.RunParams{ShowHidden: []string{"service_accounts"}}, d3.Dataset)
	if err != nil || len(q.Hidden) != 1 || q.Hidden[0].ID != "sync_off" {
		t.Errorf("show service accounts: %v %+v", err, q.Hidden)
	}
}

// reports_search_by_me_name (AC-02).
func Test_reports_search_by_me_name(t *testing.T) {
	l := shipped(t)
	m, ok := l.Resolve("Recently Logged on Users")
	if !ok || m.Report != "usr-03" || m.Preset != "recent" || !m.Available || !slices.Equal(m.AlsoKnownAs, []string{"Recently Logged on Users"}) {
		t.Fatalf("resolve: %+v", m)
	}
	hits := l.Search("recently logged on users", 5)
	if len(hits) == 0 || hits[0].Report != "usr-03" || hits[0].Preset != "recent" || hits[0].Score != 100 {
		t.Fatalf("search: %+v", hits)
	}
	// Spelling does not matter: ME writes Locked-Out Users in one place.
	for _, q := range []string{"Locked-Out Users", "locked out users", "  LOCKED-out   users "} {
		if m, ok := l.Resolve(q); !ok || m.Report != "usr-05" || m.Preset != "locked_out" {
			t.Errorf("%q: %+v", q, m)
		}
	}
	// A prefix and a title finds the report; the title hit opens the default preset.
	if h := l.Search("logon act", 5); len(h) == 0 || h[0].Report != "usr-03" || h[0].Name != "" || h[0].Preset != "inactive" {
		t.Errorf("title search: %+v", h)
	}
	// Names of reports that ship later still answer, honestly.
	if m, ok := l.Resolve("Password Expired Users"); !ok || m.Report != "pwd-01" || m.Available || m.Preset != "" {
		t.Errorf("unshipped: %+v", m)
	}
	// A shipped report whose preset waits for data says why.
	if m, ok := l.Resolve("Users Without Managers"); !ok || m.Report != "usr-01" || m.Available || !strings.Contains(m.Pending, "T-1041") {
		t.Errorf("pending: %+v", m)
	}
	if _, ok := l.Resolve("nonsense"); ok {
		t.Error("resolved nonsense")
	}
	if len(l.Search("   ", 5)) != 0 || len(l.Search("zzzzzz", 5)) != 0 {
		t.Error("empty results expected")
	}
	// Every name in the crosswalk resolves to itself.
	for _, n := range l.Names() {
		if m, ok := l.Resolve(n); !ok || m.Name != n {
			t.Errorf("%q does not resolve to itself: %+v", n, m)
		}
	}
}

// AC-03: a shipped definition is immutable. The loader refuses an edited file, an unlisted file and a
// removed one; the catalogue answers by (ID, version) with the file's SHA-256 so a run can record it.
func Test_reports_library_is_immutable(t *testing.T) {
	reg := registry(t)
	opt := library.Options{Datasets: inventory.Datasets(), Registry: reg}
	fresh := func() fstest.MapFS {
		m := fstest.MapFS{}
		for _, n := range []string{"LOCK", "crosswalk.tsv", "usr-01.v1.json", "usr-02.v1.json", "usr-03.v1.json", "usr-05.v1.json"} {
			b, err := fsReadFile(n)
			if err != nil {
				t.Fatal(err)
			}
			m[n] = &fstest.MapFile{Data: b}
		}
		return m
	}
	if _, err := library.Load(fresh(), opt); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	edit := fresh()
	edit["usr-01.v1.json"].Data = append(edit["usr-01.v1.json"].Data, ' ')
	if _, err := library.Load(edit, opt); err == nil || !strings.Contains(err.Error(), "changed since it was locked") {
		t.Errorf("edited file: %v", err)
	}
	unlisted := fresh()
	unlisted["usr-01.v2.json"] = &fstest.MapFile{Data: unlisted["usr-01.v1.json"].Data}
	if _, err := library.Load(unlisted, opt); err == nil || !strings.Contains(err.Error(), "not listed in LOCK") {
		t.Errorf("unlisted file: %v", err)
	}
	gone := fresh()
	delete(gone, "usr-05.v1.json")
	if _, err := library.Load(gone, opt); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("removed file: %v", err)
	}
	noLock := fresh()
	delete(noLock, "LOCK")
	if _, err := library.Load(noLock, opt); err == nil {
		t.Error("no LOCK")
	}
	l := shipped(t)
	d, ok := l.Definition("usr-02", 1)
	d0, _ := l.Definition("usr-02", 0)
	if !ok || d.Def.Version != 1 || d.SHA256 != d0.SHA256 || d.SHA256 == ([32]byte{}) {
		t.Errorf("definition: %+v", d)
	}
	for _, c := range []struct {
		id string
		v  int
	}{{"usr-02", 2}, {"usr-02", -1}, {"nope", 0}, {"USR-02", 0}} {
		if _, ok := l.Definition(c.id, c.v); ok {
			t.Errorf("Definition(%q, %d) found", c.id, c.v)
		}
	}
}

// A strict decoder: an unknown member, a wrong file name and a column the dataset lacks stop start-up.
func Test_reports_library_refuses_broken_definitions(t *testing.T) {
	good, _ := fsReadFile("usr-05.v1.json")
	cases := map[string]func(string) string{
		"unknown member":  func(s string) string { return strings.Replace(s, `"version": 1,`, `"version": 1, "sql": "x",`, 1) },
		"unknown column":  func(s string) string { return strings.Replace(s, `"policy_source"`, `"password_hash"`, 1) },
		"unknown dataset": func(s string) string { return strings.Replace(s, `inventory.users`, `inventory.nothing`, 1) },
		"wrong version":   func(s string) string { return strings.Replace(s, `"version": 1,`, `"version": 2,`, 1) },
		"bad operator":    func(s string) string { return strings.Replace(s, `"op": "eq"`, `"op": "regex"`, 1) },
	}
	for name, mutate := range cases {
		body := []byte(mutate(string(good)))
		m := fstest.MapFS{
			"usr-05.v1.json": &fstest.MapFile{Data: body},
			"crosswalk.tsv":  &fstest.MapFile{Data: []byte("Locked-out Users\tusr-05\tLocked-out users\tlocked_out\t\n")},
		}
		m["LOCK"] = &fstest.MapFile{Data: []byte(lockOf("usr-05.v1.json", body))}
		if _, err := library.Load(m, library.Options{Datasets: inventory.Datasets(), Registry: registry(t)}); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// The crosswalk and the presets must agree, both ways.
func Test_reports_library_crosswalk_must_match_presets(t *testing.T) {
	good, _ := fsReadFile("usr-05.v1.json")
	lock := lockOf("usr-05.v1.json", good)
	for name, tsv := range map[string]string{
		"preset name missing from crosswalk": "Other Name\tusr-05\tLocked-out users\tlocked_out\t\n",
		"unknown preset":                     "Locked-out Users\tusr-05\tLocked-out users\tnope\t\n",
		"wrong title":                        "Locked-out Users\tusr-05\tLocked Out\tlocked_out\t\n",
		"duplicate name":                     "Locked-out Users\tusr-05\tLocked-out users\tlocked_out\t\nLocked-Out Users\tusr-05\tLocked-out users\tlocked_out\t\n",
		"unshipped with a preset":            "Locked-out Users\tusr-05\tLocked-out users\tlocked_out\t\nReal Last Logon\tusr-04\tReal last logon\treal\t\n",
	} {
		m := fstest.MapFS{"usr-05.v1.json": {Data: good}, "LOCK": {Data: []byte(lock)}, "crosswalk.tsv": {Data: []byte(tsv)}}
		if _, err := library.Load(m, library.Options{Datasets: inventory.Datasets(), Registry: registry(t)}); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}
