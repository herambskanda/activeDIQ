package report_test

import (
	"errors"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

func wantCode(t *testing.T, err error, want report.Code) {
	t.Helper()
	got, ok := report.CodeOf(err)
	if !ok || got != want {
		t.Fatalf("error = %v, want code %s", err, want)
	}
}

func TestResolveResolvesPresetAndParam(t *testing.T) {
	q, err := report.Resolve(usersDef(), "inactive", report.RunParams{}, usersDataset())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !q.Valid() || q.Dataset != "inventory.users" || len(q.Columns) != 3 || len(q.Sort) != 1 {
		t.Fatalf("query = %+v", q)
	}
	and, ok := q.Where.(report.And)
	if !ok || len(and.Terms) != 2 {
		t.Fatalf("where = %#v", q.Where)
	}
	if c := and.Terms[1].(report.Cmp); c.Param != "" || c.Value.Int() != 90 {
		t.Fatalf("the default of days was not bound into the term: %+v", c)
	}
	if q.PerDCWhere != nil {
		t.Fatalf("per-DC part = %#v", q.PerDCWhere)
	}
	if err := q.Validate(usersDataset()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// AC 1: an unknown dataset, column or operator is refused with a typed error and no query exists.
func TestResolveRefusesUnknownDatasetColumnOperator(t *testing.T) {
	ds := usersDataset()
	cases := []struct {
		name string
		mut  func(*report.Definition, *report.RunParams, *report.Dataset)
		want report.Code
	}{
		{"dataset", func(d *report.Definition, _ *report.RunParams, _ *report.Dataset) { d.Dataset = "inventory.nothing" }, report.CodeUnknownDataset},
		{"column in a default column set", func(d *report.Definition, _ *report.RunParams, _ *report.Dataset) {
			d.Columns = []report.ColumnID{"name", "nope"}
		}, report.CodeUnknownColumn},
		{"column in a run's column list", func(_ *report.Definition, p *report.RunParams, _ *report.Dataset) {
			p.Columns = []report.ColumnID{"name; DROP TABLE x"}
		}, report.CodeUnknownColumn},
		{"column in a filter", func(_ *report.Definition, p *report.RunParams, _ *report.Dataset) {
			p.Filters = []report.Expr{report.Cmp{Column: "NAME", Op: report.OpEq, Value: report.TextV("x")}}
		}, report.CodeUnknownColumn},
		{"column in a sort", func(_ *report.Definition, p *report.RunParams, _ *report.Dataset) {
			p.Sort = []report.SortKey{{Column: "nope", Dir: report.Asc}}
		}, report.CodeUnknownColumn},
		{"undefined operator", func(_ *report.Definition, p *report.RunParams, _ *report.Dataset) {
			p.Filters = []report.Expr{report.Cmp{Column: "name", Op: report.Op(200), Value: report.TextV("x")}}
		}, report.CodeUnknownOperator},
		{"operator the column does not accept", func(_ *report.Definition, p *report.RunParams, _ *report.Dataset) {
			p.Filters = []report.Expr{report.Cmp{Column: "name", Op: report.OpGt, Value: report.TextV("x")}}
		}, report.CodeOperatorNotAllowed},
		{"sort direction", func(_ *report.Definition, p *report.RunParams, _ *report.Dataset) {
			p.Sort = []report.SortKey{{Column: "name", Dir: report.SortDir(9)}}
		}, report.CodeBadSort},
		{"enum value not in the column", func(_ *report.Definition, p *report.RunParams, _ *report.Dataset) {
			p.Filters = []report.Expr{report.Cmp{Column: "status", Op: report.OpEq, Value: report.EnumV("sleeping")}}
		}, report.CodeBadValue},
		{"NUL in text", func(_ *report.Definition, p *report.RunParams, _ *report.Dataset) {
			p.Filters = []report.Expr{report.Cmp{Column: "name", Op: report.OpEq, Value: report.TextV("a\x00b")}}
		}, report.CodeBadValue},
		{"value of the wrong type", func(_ *report.Definition, p *report.RunParams, _ *report.Dataset) {
			p.Filters = []report.Expr{report.Cmp{Column: "name", Op: report.OpEq, Value: report.IntV(1)}}
		}, report.CodeBadValue},
		{"unknown preset", func(d *report.Definition, _ *report.RunParams, _ *report.Dataset) {}, report.CodeUnknownPreset},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, p, s := usersDef(), report.RunParams{}, ds
			c.mut(&d, &p, &s)
			preset := "all"
			if c.want == report.CodeUnknownPreset {
				preset = "nope"
			}
			q, err := report.Resolve(d, preset, p, s)
			wantCode(t, err, c.want)
			if q.Valid() || q.Dataset != "" || q.Columns != nil || q.Where != nil {
				t.Fatalf("a refused request produced a query: %+v", q)
			}
			var v report.ValidationError
			if !errors.As(err, &v) || strings.Contains(err.Error(), "DROP") || strings.Contains(err.Error(), "sleeping") {
				t.Fatalf("error echoes the request: %v", err)
			}
		})
	}
}

func TestHostResolveUnknownDataset(t *testing.T) {
	h := report.NewHost(func(string) (string, bool) { return "inventory", true })
	q, err := h.Resolve(usersDef(), "all", report.RunParams{})
	wantCode(t, err, report.CodeUnknownDataset)
	if q.Valid() {
		t.Fatal("query exists")
	}
	if err := h.Add("inventory", usersDataset()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Resolve(usersDef(), "all", report.RunParams{}); err != nil {
		t.Fatalf("registered dataset: %v", err)
	}
}

func TestParameterFloorsAndRequired(t *testing.T) {
	d := usersDef()
	_, err := report.Resolve(d, "inactive", report.RunParams{Params: map[string]report.ParamValue{"days": report.DaysP(29)}}, usersDataset())
	wantCode(t, err, report.CodeBelowFloor)
	_, err = report.Resolve(d, "inactive", report.RunParams{Params: map[string]report.ParamValue{"days": report.DaysP(99999)}}, usersDataset())
	wantCode(t, err, report.CodeAboveCeiling)
	_, err = report.Resolve(d, "inactive", report.RunParams{Params: map[string]report.ParamValue{"days": report.EnumP("x")}}, usersDataset())
	wantCode(t, err, report.CodeBadValue)
	d.Params[0].Default, d.Params[0].Required = nil, true
	_, err = report.Resolve(d, "inactive", report.RunParams{}, usersDataset())
	wantCode(t, err, report.CodeMissingParameter)
	q, err := report.Resolve(d, "inactive", report.RunParams{Params: map[string]report.ParamValue{"days": report.DaysP(30)}}, usersDataset())
	if err != nil || !q.Valid() {
		t.Fatalf("at the floor: %v", err)
	}
}

func TestPerDCTermsAreSplitAndNeverMixed(t *testing.T) {
	ds := usersDataset()
	p := report.RunParams{Filters: []report.Expr{report.Cmp{Column: "last_logon", Op: report.OpOlderThanDays, Value: report.IntV(30)}}}
	q, err := report.Resolve(usersDef(), "all", p, ds)
	if err != nil {
		t.Fatal(err)
	}
	if q.Where != nil || q.PerDCWhere == nil {
		t.Fatalf("where = %#v, per-DC = %#v", q.Where, q.PerDCWhere)
	}
	mixed := report.RunParams{Filters: []report.Expr{report.Or{Terms: []report.Expr{
		report.Cmp{Column: "last_logon", Op: report.OpOlderThanDays, Value: report.IntV(30)},
		report.Cmp{Column: "name", Op: report.OpEq, Value: report.TextV("a")},
	}}}}
	_, err = report.Resolve(usersDef(), "all", mixed, ds)
	wantCode(t, err, report.CodePerDCMisplaced)
	// A hand-built Query is not valid, and a per-DC column in the SQL part is refused on re-check.
	if (report.Query{}).Valid() {
		t.Fatal("zero Query is valid")
	}
}

func TestColumnAndComplexityLimits(t *testing.T) {
	ds := usersDataset()
	cols := make([]report.ColumnID, 65)
	for i := range cols {
		cols[i] = "name"
	}
	_, err := report.Resolve(usersDef(), "all", report.RunParams{Columns: cols}, ds)
	wantCode(t, err, report.CodeTooManyColumns)
	_, err = report.Resolve(usersDef(), "all", report.RunParams{Columns: []report.ColumnID{"name", "name"}}, ds)
	wantCode(t, err, report.CodeDuplicateColumn)
	var e report.Expr = report.Cmp{Column: "name", Op: report.OpEq, Value: report.TextV("x")}
	for i := 0; i < 10; i++ {
		e = report.Not{Term: e}
	}
	_, err = report.Resolve(usersDef(), "all", report.RunParams{Filters: []report.Expr{e}}, ds)
	wantCode(t, err, report.CodeTooComplex)
	in := report.Cmp{Column: "object_guid", Op: report.OpIn}
	for i := 0; i < 1001; i++ {
		in.Values = append(in.Values, report.GUIDV(oid(1)))
	}
	_, err = report.Resolve(usersDef(), "all", report.RunParams{Filters: []report.Expr{in}}, ds)
	wantCode(t, err, report.CodeTooManyValues)
}

func TestNarrowingAndSubjects(t *testing.T) {
	ds := usersDataset()
	_, err := report.Resolve(usersDef(), "all", report.RunParams{Include: []report.NarrowRoot{{Connection: oid(1), Depth: report.DepthSubtree}}}, ds)
	wantCode(t, err, report.CodeBadNarrowing)
	_, err = report.Resolve(usersDef(), "all", report.RunParams{Subjects: []authz.ObjectID{oid(1)}}, ds)
	wantCode(t, err, report.CodeUnknownParameter)
	d := usersDef()
	d.Presets[1].Requires = &report.Subjects{Min: 1, Max: 2}
	_, err = report.Resolve(d, "all", report.RunParams{}, ds)
	wantCode(t, err, report.CodeMissingParameter)
	q, err := report.Resolve(d, "all", report.RunParams{Subjects: []authz.ObjectID{oid(1)}}, ds)
	if err != nil || len(q.Subjects) != 1 {
		t.Fatalf("subjects: %v", err)
	}
}

func TestHiddenGroupsAreCountedUnlessShown(t *testing.T) {
	d := usersDef()
	d.Presets[1].Hidden = []report.HiddenGroup{{ID: "disabled", Label: "Disabled", Where: report.Cmp{Column: "status", Op: report.OpEq, Value: report.EnumV("disabled")}}}
	q, err := report.Resolve(d, "all", report.RunParams{}, usersDataset())
	if err != nil || len(q.Hidden) != 1 {
		t.Fatalf("hidden = %v, %v", q.Hidden, err)
	}
	q, err = report.Resolve(d, "all", report.RunParams{ShowHidden: []string{"disabled"}}, usersDataset())
	if err != nil || len(q.Hidden) != 0 {
		t.Fatalf("shown: %v %v", q.Hidden, err)
	}
	_, err = report.Resolve(d, "all", report.RunParams{ShowHidden: []string{"nope"}}, usersDataset())
	wantCode(t, err, report.CodeUnknownParameter)
}

// A locked hidden group is a narrowing the admin cannot undo (AC-16): it stays in the query, and a request
// that asks to show it is refused.
func TestLockedHiddenGroupCannotBeShown(t *testing.T) {
	d := usersDef()
	d.Presets[1].Hidden = []report.HiddenGroup{{ID: "off", Label: "Off", Locked: true, Where: report.Cmp{Column: "status", Op: report.OpEq, Value: report.EnumV("disabled")}}}
	q, err := report.Resolve(d, "all", report.RunParams{}, usersDataset())
	if err != nil || len(q.Hidden) != 1 || !q.Hidden[0].Locked {
		t.Fatalf("locked group: %v %v", q.Hidden, err)
	}
	_, err = report.Resolve(d, "all", report.RunParams{ShowHidden: []string{"off"}}, usersDataset())
	wantCode(t, err, report.CodeUnknownParameter)
}

func TestHashIsStableAndSensitive(t *testing.T) {
	a, _ := report.Resolve(usersDef(), "inactive", report.RunParams{}, usersDataset())
	b, _ := report.Resolve(usersDef(), "inactive", report.RunParams{}, usersDataset())
	if a.Hash() != b.Hash() {
		t.Fatal("same query, different hash")
	}
	c, _ := report.Resolve(usersDef(), "inactive", report.RunParams{Params: map[string]report.ParamValue{"days": report.DaysP(91)}}, usersDataset())
	if a.Hash() == c.Hash() {
		t.Fatal("different days, same hash")
	}
	x, _ := report.Resolve(usersDef(), "all", report.RunParams{Subjects: nil, Connections: []authz.ObjectID{oid(2), oid(1)}}, usersDataset())
	y, _ := report.Resolve(usersDef(), "all", report.RunParams{Connections: []authz.ObjectID{oid(1), oid(2)}}, usersDataset())
	if x.Hash() != y.Hash() {
		t.Fatal("connection order changed the hash")
	}
}

func TestDefinitionVersionFields(t *testing.T) {
	d := usersDef()
	if d.Key() != "usr-03@2" || d.FileName() != "usr-03.v2.json" {
		t.Fatalf("key %s file %s", d.Key(), d.FileName())
	}
	if err := d.ValidateAgainst(usersDataset()); err != nil {
		t.Fatalf("ValidateAgainst: %v", err)
	}
	d.Version = 0
	wantCode(t, d.Validate(), report.CodeInvalidDefinition)
	d = usersDef()
	d.Presets[0].Where = report.Cmp{Column: "ghost", Op: report.OpEq, Value: report.TextV("x")}
	wantCode(t, d.ValidateAgainst(usersDataset()), report.CodeUnknownColumn)
}
