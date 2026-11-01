package report_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

func TestDatasetValidate(t *testing.T) {
	if err := usersDataset().Validate(); err != nil {
		t.Fatalf("valid dataset: %v", err)
	}
	cases := map[string]func(*report.Dataset){
		"bad ID":                   func(d *report.Dataset) { d.ID = "Users" },
		"no anchors":               func(d *report.Dataset) { d.Anchors = nil },
		"table not listed":         func(d *report.Dataset) { d.Tables = []string{"other"} },
		"duplicate column":         func(d *report.Dataset) { d.Columns = append(d.Columns, d.Columns[0]) },
		"operator does not fit":    func(d *report.Dataset) { d.Columns[0].Filter = []report.Op{report.OpOlderThanDays} },
		"enum without values":      func(d *report.Dataset) { d.Columns[1].Enum = nil },
		"unknown on non-derived":   func(d *report.Dataset) { d.Columns[2].Source = report.Attr{Col: "state"} },
		"UnknownWhen target wrong": func(d *report.Dataset) { d.Columns[3].UnknownWhen = "status" },
		"UnknownWhen on enum":      func(d *report.Dataset) { d.Columns[1].UnknownWhen = "locked_out" },
		"count not derived":        func(d *report.Dataset) { d.Columns[0].Count = true },
		"json attr type differs":   func(d *report.Dataset) { d.Columns[0].Type = report.TypeInt },
		"undeclared rel slot": func(d *report.Dataset) {
			d.Columns[1].Source = report.Derived{SQL: report.SQL("(SELECT count(*) FROM {rel.ghost})")}
		},
		"in_scope needs mask anchor": func(d *report.Dataset) { d.Columns[1].Source = report.Derived{SQL: report.SQL("{in_scope.t}")} },
		"semicolon":                  func(d *report.Dataset) { d.Columns[1].Source = report.Derived{SQL: report.SQL("1; DROP TABLE x")} },
		"dollar":                     func(d *report.Dataset) { d.Columns[1].Source = report.Derived{SQL: report.SQL("$1")} },
		"comment":                    func(d *report.Dataset) { d.Columns[1].Source = report.Derived{SQL: report.SQL("1 -- x")} },
		"unknown slot":               func(d *report.Dataset) { d.Columns[1].Source = report.Derived{SQL: report.SQL("{table}")} },
		"unbalanced parens":          func(d *report.Dataset) { d.Columns[1].Source = report.Derived{SQL: report.SQL("(1")} },
		"quoted identifier":          func(d *report.Dataset) { d.Columns[1].Source = report.Derived{SQL: report.SQL(`"x"`)} },
		"per-DC bad aggregate":       func(d *report.Dataset) { d.Columns[5].Source = report.PerDC{Attr: report.PerDCLastLogon} },
		"no source":                  func(d *report.Dataset) { d.Columns[0].Source = nil },
		"no freshness":               func(d *report.Dataset) { d.Freshness = 0 },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			d := usersDataset()
			d.Columns = append([]report.Column(nil), d.Columns...)
			mut(&d)
			err := d.Validate()
			if err == nil {
				t.Fatal("accepted")
			}
			if _, ok := report.CodeOf(err); !ok {
				t.Fatalf("untyped: %v", err)
			}
		})
	}
}

// AC 3 at the host: a dataset over a table owned by another package is refused, naming the table.
func TestHostRefusesForeignTable(t *testing.T) {
	owners := map[string]string{"directory_objects": "inventory", "report_runs": "reports"}
	h := report.NewHost(func(tb string) (string, bool) { o, ok := owners[tb]; return o, ok })
	d := usersDataset()
	d.Tables = []string{"directory_objects", "report_runs"}
	d.Anchors = append(d.Anchors, report.Anchor{ID: "r", Table: "report_runs", Mode: report.FilterAnchor, Project: []report.Ident{"id"},
		Connection: "a", NC: "b", Object: "c", Parent: "d", Ancestry: "e", Complete: "f"})
	err := h.Add("inventory", d)
	var te *report.TableOwnershipError
	if !errors.As(err, &te) || te.Table != "report_runs" || !errors.Is(err, report.ErrTableOwnership) || !strings.Contains(err.Error(), `"report_runs"`) {
		t.Fatalf("error = %v", err)
	}
	if len(h.Datasets()) != 0 {
		t.Fatal("dataset registered despite the failure")
	}
	// A table nobody declared fails closed, and so does a missing ownership map.
	if err := report.CheckTables("inventory", usersDataset(), nil); !errors.Is(err, report.ErrTableOwnership) {
		t.Fatalf("nil map: %v", err)
	}
	// Wrong namespace.
	if err := report.CheckTables("reports", usersDataset(), func(string) (string, bool) { return "reports", true }); !errors.Is(err, report.ErrNamespace) {
		t.Fatalf("namespace: %v", err)
	}
}

func TestHostSealAndDuplicates(t *testing.T) {
	h := report.NewHost(func(string) (string, bool) { return "inventory", true })
	if err := h.Add("inventory", usersDataset()); err != nil {
		t.Fatal(err)
	}
	if err := h.Add("inventory", usersDataset()); !errors.Is(err, report.ErrDuplicateDataset) {
		t.Fatalf("duplicate: %v", err)
	}
	h.Seal()
	other := usersDataset()
	other.ID = "inventory.computers"
	if err := h.Add("inventory", other); !errors.Is(err, report.ErrSealed) {
		t.Fatalf("sealed: %v", err)
	}
	var nilHost *report.Host
	if _, ok := nilHost.Dataset("inventory.users"); ok || nilHost.Add("x") == nil {
		t.Fatal("nil host")
	}
}

func TestFreshnessLabel(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	th := time.Hour
	w := func(c byte, ago time.Duration, s report.NCState) report.NCWatermark {
		return report.NCWatermark{Connection: oid(c), NC: oid(c + 100), LastPassAt: now.Add(-ago), State: s}
	}
	if f := report.Label([]report.NCWatermark{w(1, 10*time.Minute, report.NCOK)}, th, now); f.State != report.FreshnessSynced || !f.AsOf.Equal(now.Add(-10*time.Minute)) {
		t.Fatalf("synced: %+v", f)
	}
	f := report.Label([]report.NCWatermark{w(1, 10*time.Minute, report.NCOK), w(2, 3*time.Hour, report.NCOK), w(3, 5*time.Minute, report.NCPaused)}, th, now)
	if f.State != report.FreshnessStale || len(f.Stale) != 2 || f.Stale[0].Connection != oid(2) || !f.AsOf.Equal(now.Add(-3*time.Hour)) {
		t.Fatalf("stale: %+v", f)
	}
	f = report.Label([]report.NCWatermark{w(1, time.Minute, report.NCOK), {Connection: oid(9), State: report.NCNeverSynced}}, th, now)
	if f.State != report.FreshnessSynced || len(f.NotSynced) != 1 {
		t.Fatalf("skipped: %+v", f)
	}
	if f := report.Label([]report.NCWatermark{{Connection: oid(9), State: report.NCNeverSynced}}, th, now); f.State != report.FreshnessNotSyncedYet || !f.AsOf.IsZero() {
		t.Fatalf("never: %+v", f)
	}
	if f := report.Label(nil, th, now); f.State != report.FreshnessNotSyncedYet {
		t.Fatalf("empty: %+v", f)
	}
}

func TestGUIDStringInvertsParse(t *testing.T) {
	const s = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
	g, err := parse(s)
	if err != nil || report.GUIDString(g) != s {
		t.Fatalf("%v %s", err, report.GUIDString(g))
	}
}
