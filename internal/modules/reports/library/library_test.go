package library_test

import (
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// specRow is one row of reports-2a 6.2 for a shipped report, as the spec table words it. Columns are the
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
	// filters is, per preset, the columns the preset's filter reads, sorted: the "Default filters" cell of the
	// 6.2 row says which attributes each preset constrains. Only the batch-2 rows state it.
	filters map[string][]string
	// subject is "<kind>:<column>" for the reports that require objects (GRP-02, GRP-03).
	subject string
}

var specRows = []specRow{
	{id: "usr-01", title: "Users", category: report.CategoryUsers, dataset: "inventory.users",
		presets: map[string][]string{"all": {"All Users"}, "enabled": {"Enabled Users"}, "disabled": {"Disabled Users"}, "recently_created": {"Recently Created Users"}},
		// Name, Logon name, UPN, Status, Domain, OU path, Manager, Created
		columns:    []string{"display_name", "sam_account_name", "user_principal_name", "enabled", "domain", "dn", "when_created"},
		deviations: []string{"OU path is shown by the dn column (T-1041 adds the masked OU path)", "Manager column and the Users Without Managers preset wait for T-1041"}},
	{id: "usr-02", title: "Account expiry", category: report.CategoryUsers, dataset: "inventory.users",
		presets: map[string][]string{"expired": {"Account Expired Users"}, "recently_expired": {"Recently Account Expired Users"},
			"soon": {"Soon-to-expire User Accounts"}, "never": {"Account Never Expires Users"}},
		// Name, Logon name, Domain, OU path, Account expires, Days to / since expiry, Status
		columns:    []string{"display_name", "sam_account_name", "domain", "dn", "account_expires", "days_to_account_expiry", "enabled"},
		deviations: []string{"OU path is shown by the dn column (T-1041)"}},
	{id: "usr-03", title: "Logon activity", category: report.CategoryUsers, dataset: "inventory.users",
		presets: map[string][]string{"inactive": {"Inactive Users"}, "recent": {"Recently Logged on Users"}, "never": {"Users Never Logged On"}},
		// Name, Logon name, Domain, OU path, Last logon (replicated), Days since, Created, Status, Probable service account
		columns: []string{"display_name", "sam_account_name", "domain", "dn", "last_logon_timestamp", "days_since_logon", "when_created", "enabled",
			"probable_service_account", "probable_service_account_reason"},
		deviations: []string{"OU path is shown by the dn column (T-1041)", "adds the service-account reason column (spec 6.7: every flagged row shows its reason)"}},
	{id: "usr-04", title: "Real last logon", category: report.CategoryUsers, dataset: "inventory.users",
		presets: map[string][]string{"real": {"Real Last Logon"}},
		// Name, Logon name, Domain, OU path, Real last logon, From DC, DC coverage, Days since, Status
		columns:    []string{"display_name", "sam_account_name", "domain", "dn", "real_last_logon", "real_logon_dc", "dc_coverage", "days_since_real_logon", "enabled"},
		filters:    map[string][]string{"real": {"enabled"}},
		deviations: []string{"OU path is shown by the dn column (T-1041)", "read live from every DC (T-0971): a partial answer is labelled and the value is a lower bound"}},
	{id: "pwd-03", title: "Recent logon failures", category: report.CategoryPasswords, dataset: "inventory.users",
		presets: map[string][]string{"recent": {"Recent Logon Failures"}},
		// Name, Logon name, Domain, OU path, Last failed logon, From DC, Failures on that DC, DC coverage
		columns:    []string{"display_name", "sam_account_name", "domain", "dn", "last_failed_logon", "failed_logon_dc", "failures_on_dc", "dc_coverage"},
		filters:    map[string][]string{"recent": {"last_failed_logon"}},
		deviations: []string{"OU path is shown by the dn column (T-1041)", "badPwdCount is per DC: the count at the DC of the latest failure, never a sum"}},
	{id: "usr-05", title: "Locked-out users", category: report.CategoryUsers, dataset: "inventory.users",
		presets: map[string][]string{"locked_out": {"Locked-out Users"}},
		// Name, Logon name, Domain, OU path, Locked out since, Lockout ends, Policy source, Data as of
		columns:    []string{"display_name", "sam_account_name", "domain", "dn", "lockout_time", "lockout_ends_at", "policy_source", "observed_at"},
		deviations: []string{"OU path is shown by the dn column (T-1041)"}},

	// ---- batch 2 (T-0962)
	{id: "pwd-01", title: "Password status", category: report.CategoryPasswords, dataset: "inventory.users",
		presets: map[string][]string{"expired": {"Password Expired Users"}, "soon": {"Soon-to-expire User Passwords"},
			"never": {"Users with Password Never Expires"}, "must_change": {"Users with Change Password at Next Logon"}},
		// Name, Logon name, Domain, OU path, Password last set, Password expires, Password state, Policy source, Status, Probable service account
		columns: []string{"display_name", "sam_account_name", "domain", "dn", "pwd_last_set", "password_expires_at", "password_state", "policy_source", "enabled",
			"probable_service_account", "probable_service_account_reason"},
		filters:    map[string][]string{"expired": {"password_state"}, "soon": {"password_expires_at", "password_state"}, "never": {"password_state"}, "must_change": {"password_state"}},
		deviations: []string{"OU path is shown by the dn column (T-1041)", "adds the service-account reason column (spec 6.7: every flagged row shows its reason)"}},
	{id: "pwd-02", title: "Password age", category: report.CategoryPasswords, dataset: "inventory.users",
		presets: map[string][]string{"changed": {"Password Changed Users"}, "unchanged": {"Password Unchanged Users"}},
		// Name, Logon name, Domain, OU path, Password last set, Days since, Status
		columns:    []string{"display_name", "sam_account_name", "domain", "dn", "pwd_last_set", "days_since_password_set", "enabled"},
		filters:    map[string][]string{"changed": {"pwd_last_set"}, "unchanged": {"enabled", "pwd_last_set", "pwd_set_recorded", "when_created"}},
		deviations: []string{"OU path is shown by the dn column (T-1041)", "Unchanged also lists enabled accounts whose pwdLastSet is 0 and that were created before the threshold (never changed)"}},
	// ---- batch 4 (T-1107)
	{id: "pwd-04", title: "Password change blocked", category: report.CategoryPasswords, dataset: "inventory.users",
		presets: map[string][]string{"blocked": {"Users with Cannot Change Password"}},
		// Name, Logon name, Domain, OU path, Password change right, Status, Password state, Probable service account, Descriptor as of
		columns: []string{"display_name", "sam_account_name", "domain", "dn", "password_change_right", "enabled", "password_state",
			"probable_service_account", "probable_service_account_reason", "descriptor_as_of"},
		filters: map[string][]string{"blocked": {"password_change_right"}},
		deviations: []string{"OU path is shown by the dn column (T-1041)", "adds the service-account reason column (spec 6.7: every flagged row shows its reason)",
			"the preset also selects Not confirmed users so the locked not_confirmed group counts them in the header; they are never listed"}},
	{id: "grp-01", title: "Groups", category: report.CategoryGroups, dataset: "inventory.groups",
		presets: map[string][]string{"all": {"All Groups"}, "security": {"Security Groups"}, "distribution": {"Distribution Groups"}, "type_scope": {"Group Type and Scope"},
			"no_members": {"Groups Without Members"}, "managed": {"Managed Groups"}, "unmanaged": {"Unmanaged Groups"}, "top": {"Top N Big Groups"},
			"recently_created": {"Recently Created Groups"}},
		// Name, Domain, OU path, Type, Scope, Direct members, Effective members, Managed by, Created
		columns: []string{"name", "domain", "dn", "group_type", "group_scope", "direct_members", "effective_members", "managed_by", "when_created"},
		filters: map[string][]string{"all": nil, "security": {"group_type"}, "distribution": {"group_type"}, "type_scope": nil, "no_members": {"has_members"},
			"managed": {"has_manager"}, "unmanaged": {"has_manager"}, "top": nil, "recently_created": {"when_created"}},
		deviations: []string{"OU path is shown by the dn column (T-1041)"}},
	{id: "grp-02", title: "Group members", category: report.CategoryGroups, dataset: "inventory.group_members",
		presets: map[string][]string{"members": {"Group Members"}, "detailed": {"Detailed Group Members"}, "users": {"Users in Groups"}},
		// Group, Member, Member type, Domain, OU path, Status, Membership kind, Via
		columns: []string{"group_name", "member_name", "member_kind", "member_domain", "member_dn", "member_enabled", "edge_kind", "via_path", "finding"},
		filters: map[string][]string{"members": {"depth"}, "detailed": nil, "users": {"finding", "member_kind"}},
		subject: "group:group_guid",
		deviations: []string{"OU path is shown by the member's dn column (T-1041)", "adds the Finding column: a cycle, a group too large to expand and a nesting cut are rows that need their sentence (spec 6.6)",
			"Users in Groups also lists the finding rows, so a user-only list is never silently incomplete"}},
	{id: "grp-03", title: "Groups for users", category: report.CategoryGroups, dataset: "inventory.group_members",
		presets: map[string][]string{"groups_for_users": {"Groups for Users"}},
		// User, Group, Group type, Group scope, Membership kind, Via
		columns: []string{"member_name", "group_name", "group_type", "group_scope", "edge_kind", "via_path"},
		filters: map[string][]string{"groups_for_users": nil}, subject: "user:member_guid",
		deviations: []string{"the effective, primary-group-inclusive rule is the dataset's: every closure row of the user"}},
	{id: "grp-04", title: "Not in any group", category: report.CategoryGroups, dataset: "inventory.principals",
		presets: map[string][]string{"users": {"Users Not in Groups"}, "computers": {"Computers Not in Groups"}},
		// Name, Domain, OU path, Primary group, Status, Created, Last logon (replicated)
		columns: []string{"name", "domain", "dn", "primary_group", "enabled", "when_created", "last_logon_timestamp"},
		filters: map[string][]string{"users": {"in_other_groups", "object_kind"}, "computers": {"in_other_groups", "object_kind"}},
		deviations: []string{"the dataset is inventory.principals (users and computers in one registered dataset) because a definition holds one dataset and the preset chooses the kind",
			"OU path is shown by the dn column (T-1041)"}},
	{id: "cmp-01", title: "Computers", category: report.CategoryComputers, dataset: "inventory.computers",
		presets: map[string][]string{"all": {"All computers"}, "enabled": {"Enabled Computers"}, "disabled": {"Disabled Computers"}, "workstation": {"Workstation Computers"},
			"domain_controller": {"Domain Controllers"}, "delegation": {"Computers Trusted for Delegation"}, "os": {"OS based computers"}, "recently_created": {"Recently Created Computers"}},
		// Name, DNS name, Domain, OU path, Type, Operating system, OS version, Status, Delegation, Created
		columns: []string{"name", "dns_host_name", "domain", "dn", "computer_type", "operating_system", "operating_system_version", "enabled", "delegation", "when_created"},
		filters: map[string][]string{"all": nil, "enabled": {"enabled"}, "disabled": {"enabled"}, "workstation": {"computer_type"}, "domain_controller": {"computer_type"},
			"delegation": {"delegation"}, "os": {"operating_system"}, "recently_created": {"when_created"}},
		deviations: []string{"OU path is shown by the dn column (T-1041)",
			"OS based computers lists the computers that report an operating system, grouped by it; narrowing to one name is the grid filter (a text parameter kind does not exist)"}},
	{id: "cmp-02", title: "Computer activity", category: report.CategoryComputers, dataset: "inventory.computers",
		presets: map[string][]string{"inactive": {"Inactive computers"}, "active": {"Active Computers"}},
		// Name, DNS name, Domain, OU path, Operating system, Last activity, Activity source, Days since, Status, Created
		columns:    []string{"name", "dns_host_name", "domain", "dn", "operating_system", "last_activity", "activity_source", "days_since_activity", "enabled", "when_created"},
		filters:    map[string][]string{"inactive": {"enabled", "last_activity"}, "active": {"last_activity"}},
		deviations: []string{"OU path is shown by the dn column (T-1041)", "gMSA objects are counted in the header; cluster objects wait for the servicePrincipalName values (follow-up ticket)"}},
	{id: "ou-01", title: "Organizational units", category: report.CategoryOUs, dataset: "inventory.ous",
		presets: map[string][]string{"all": {"All OUs"}, "empty": {"Empty OUs"}, "users_only": {"Users-Only OUs"}, "computers_only": {"Computers-Only OUs"}, "recently_created": {"Recently Created OUs"}},
		// Name, Domain, Path, Users, Computers, Groups, Other objects, Objects in subtree, Created
		columns: []string{"name", "domain", "dn", "subtree_users", "subtree_computers", "subtree_groups", "subtree_other", "subtree_objects", "when_created"},
		filters: map[string][]string{"all": nil, "empty": {"subtree_computers", "subtree_groups", "subtree_other", "subtree_users"},
			"users_only": {"subtree_computers", "subtree_groups", "subtree_other", "subtree_users"}, "computers_only": {"subtree_computers", "subtree_groups", "subtree_other", "subtree_users"},
			"recently_created": {"when_created"}},
		deviations: []string{"Users, Computers, Groups and Other count the whole subtree, the same set the Empty, Users-only and Computers-only filters test"}},
	{id: "ctc-01", title: "Contacts", category: report.CategoryContacts, dataset: "inventory.contacts",
		presets: map[string][]string{"all": {"All Contacts"}, "mail_enabled": {"Mail Enabled Contacts"}, "recently_created": {"Recently Created Contacts"}},
		// Name, E-mail, Domain, OU path, Created
		columns:    []string{"name", "mail", "domain", "dn", "when_created"},
		filters:    map[string][]string{"all": nil, "mail_enabled": {"mail"}, "recently_created": {"when_created"}},
		deviations: []string{"OU path is shown by the dn column (T-1041)"}},
}

// reports_library_matches_spec (AC-01): each batch-1 report has the ID, category, dataset, presets and
// default columns of the 6.2 row.
func Test_reports_library_matches_spec(t *testing.T) {
	l := shipped(t)
	items := l.List()
	// 16 reports in the spec; USR-04 and PWD-03 are the per-DC pair (B8, T-0971).
	if len(items) != len(specRows) {
		t.Fatalf("library lists %d reports, want %d", len(items), len(specRows))
	}
	byID := map[string]report.Definition{}
	for _, it := range items {
		byID[string(it.Def.ID)] = it.Def
	}
	for _, row := range specRows {
		d, ok := byID[row.id]
		if !ok {
			t.Errorf("%s is not in the library", row.id)
			continue
		}
		if d.Title != row.title || d.Category != row.category || d.Dataset != row.dataset || d.Version != 1 {
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
			if row.filters != nil {
				want, stated := row.filters[pid]
				if !stated {
					t.Errorf("%s/%s: the spec row states no filter columns for this preset", row.id, pid)
				}
				if got := filterColumns(p.Where); !slices.Equal(got, want) {
					t.Errorf("%s/%s: the filter reads %v, the spec row says %v", row.id, pid, got, want)
				}
			}
			switch {
			case row.subject == "" && p.Requires != nil:
				t.Errorf("%s/%s requires subjects", row.id, pid)
			case row.subject != "" && (p.Requires == nil || p.Requires.Kind+":"+string(p.Requires.Column) != row.subject):
				t.Errorf("%s/%s: subjects %+v, want %s", row.id, pid, p.Requires, row.subject)
			}
		}
		if len(row.deviations) == 0 {
			t.Errorf("%s: no deviations listed; delete this check if there are none", row.id)
		}
	}
	// The crosswalk answers every ME name of 6.2: 54.
	if n := len(l.Names()); n != 55 {
		t.Errorf("crosswalk lists %d names, spec 6.2 says 54 plus Cannot Change Password from the second slice", n)
	}
}

// filterColumns lists, sorted and once each, the columns an expression reads.
func filterColumns(e report.Expr) []string {
	set := map[string]bool{}
	var walk func(report.Expr)
	walk = func(e report.Expr) {
		switch x := e.(type) {
		case report.And:
			for _, t := range x.Terms {
				walk(t)
			}
		case report.Or:
			for _, t := range x.Terms {
				walk(t)
			}
		case report.Not:
			walk(x.Term)
		case report.Cmp:
			set[string(x.Column)] = true
		}
	}
	if e != nil {
		walk(e)
	}
	var out []string
	for c := range set {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
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
	// Names of reports that ship later still answer, honestly (USR-04 shipped with T-0971).
	if m, ok := l.Resolve("Real Last Logon"); !ok || m.Report != "usr-04" || !m.Available || m.Preset != "real" {
		t.Errorf("per-DC report: %+v", m)
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
		files, err := fs.Glob(library.Shipped(), "*.json")
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range append(files, "LOCK", "crosswalk.tsv") {
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
		"unshipped with a preset":            "Locked-out Users\tusr-05\tLocked-out users\tlocked_out\t\nSome Name\tusr-99\tSome title\tsome\t\n",
	} {
		m := fstest.MapFS{"usr-05.v1.json": {Data: good}, "LOCK": {Data: []byte(lock)}, "crosswalk.tsv": {Data: []byte(tsv)}}
		if _, err := library.Load(m, library.Options{Datasets: inventory.Datasets(), Registry: registry(t)}); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// AC-S05 (T-1107): PWD-04 filters on the stored inventory.users state only. It has no per-DC stage, so no
// descriptor is read when it runs, and the filter reads nothing but password_change_right.
func Test_reports_library_pwd04_reads_the_stored_state_only(t *testing.T) {
	d, ok := shipped(t).Definition("pwd-04", 0)
	if !ok {
		t.Fatal("pwd-04 is not in the library")
	}
	if d.Def.PerDC != nil {
		t.Error("pwd-04 has a per-DC stage: a descriptor would be read at run time")
	}
	for _, p := range d.Def.Presets {
		if got := filterColumns(p.Where); !slices.Equal(got, []string{"password_change_right"}) {
			t.Errorf("preset %s filters on %v, want only password_change_right", p.ID, got)
		}
		var nc *report.HiddenGroup
		for i := range p.Hidden {
			if p.Hidden[i].ID == "not_confirmed" {
				nc = &p.Hidden[i]
			}
		}
		if nc == nil || !nc.Locked {
			t.Errorf("preset %s has no locked not_confirmed group: unreadable users would not be counted", p.ID)
		}
	}
}
