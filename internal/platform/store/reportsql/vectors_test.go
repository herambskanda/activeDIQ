package reportsql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// FF-SP4 for the report compiler (AC 6). The records are kind "e2e": the store package, which
// cannot import reportsql, does not run them, and this test is where they are proven. It fails on
// any record of the unit whose call names reportsql and that it does not handle.

var errNames = []struct {
	err  error
	name string
}{
	{reportsql.ErrUnknownColumn, "UnknownColumn"}, {reportsql.ErrBadSortDirection, "BadSortDirection"},
	{reportsql.ErrTooManyValues, "TooManyValues"}, {reportsql.ErrBadValue, "BadValue"},
	{reportsql.ErrQueryTimeout, "QueryTimeout"}, {reportsql.ErrBadOperator, "BadOperator"},
	{reportsql.ErrPerDCInSQL, "PerDCInSQL"},
}

func errName(err error) string {
	for _, e := range errNames {
		if errors.Is(err, e.err) {
			return e.name
		}
	}
	return "other: " + err.Error()
}

var placeholder = regexp.MustCompile(`\$[0-9]+::[a-z]+(\[\])?`)

func argText(t *testing.T, r corpus.Record, name string) string {
	t.Helper()
	in, err := r.Arg(name)
	if err != nil {
		t.Fatalf("%s: arg %s: %v", r.ID, name, err)
	}
	return string(in.Raw)
}

func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ax, _ := json.Marshal(x)
	by, _ := json.Marshal(y)
	return bytes.Equal(ax, by)
}

func TestVectors_SQL(t *testing.T) {
	f := corpustest.Load(t, "sql")
	var mine []corpus.Record
	for _, r := range f.Records {
		if strings.HasPrefix(r.Call, "reportsql.") {
			mine = append(mine, r)
		}
	}
	if len(mine) < 17 {
		t.Fatalf("only %d reportsql records in the sql corpus", len(mine))
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		withDB(t, s, nil, func(ctx context.Context, tx pgx.Tx) {
			for _, r := range mine {
				t.Run(r.ID, func(t *testing.T) { runVector(t, ctx, tx, s, r) })
			}
		})
	})
}

func runVector(t *testing.T, ctx context.Context, tx pgx.Tx, s *storetest.Server, r corpus.Record) {
	_, ds := resolve(t, report.RunParams{})
	var got any // an error name (string) or a value
	scope := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermNamingContext, 1, 0x10)}))
	switch {
	case r.Call == "reportsql.Compile":
		v := argText(t, r, "value")
		q, ds := resolve(t, report.RunParams{Filters: []report.Expr{report.Cmp{Column: "name", Op: report.OpEq, Value: report.TextV(v)}}})
		c, err := reportsql.Compile(q, ds, scope, in())
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		rows := runAll(t, ctx, tx, c, 10)
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM directory_objects`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		bound := false
		for _, a := range reportsql.Args(c) {
			if a == v {
				bound = true
			}
		}
		// Placeholders are the only dollar signs the compiler writes; take them out before looking for the value.
		if strings.Contains(placeholder.ReplaceAllString(reportsql.SQL(c), ""), v) {
			bound = false
		}
		got = map[string]any{"rows": len(rows), "bound": bound, "table_intact": n == len(fixtureRows())}
	case r.Call == "reportsql.OrderBy":
		key := report.ColumnID("name")
		dir := report.Asc
		if _, ok := r.Args["key"]; ok {
			key = report.ColumnID(argText(t, r, "key"))
		}
		if _, ok := r.Args["dir"]; ok {
			d, ok := report.ParseSortDir(argText(t, r, "dir"))
			if !ok {
				d = report.SortDir(255)
			}
			dir = d
		}
		_, _, err := reportsql.OrderBy(ds, []report.SortKey{{Column: key, Dir: dir}})
		got = errName(err)
		if err == nil {
			got = "no error"
		}
	case r.Call == "reportsql.Cmp" && strings.HasPrefix(r.ID, "SQL-15"):
		vals := make([]report.Value, 100001)
		for i := range vals {
			vals[i] = report.TextV("x")
		}
		_, _, err := reportsql.Cmp(ds, report.Cmp{Column: "sam", Op: report.OpIn, Values: vals}, fixedNow)
		got = errName(err)
	case r.Call == "reportsql.Cmp":
		_, _, err := reportsql.Cmp(ds, report.Cmp{Column: "pwd_last_set", Op: report.OpOlderThanDays, Value: report.TextV(argText(t, r, "text"))}, fixedNow)
		got = errName(err)
	case r.Call == "reportsql.NewRegistry" && strings.HasPrefix(r.ID, "SQL-16"):
		key := argText(t, r, "jsonKey")
		d := usersDataset()
		d.Columns[0].Source = report.JSONAttr{Col: "attributes", Key: key, As: report.TypeText}
		reg, err := reportsql.NewRegistry(opts(), d)
		if err != nil {
			t.Fatalf("NewRegistry: %v", err)
		}
		rd, _ := reg.Dataset(d.ID)
		def := usersDef()
		q, err := report.Resolve(def, "all", report.RunParams{}, d)
		if err != nil {
			t.Fatal(err)
		}
		c, err := reportsql.Compile(q, rd, scope, in())
		if err != nil {
			t.Fatal(err)
		}
		runAll(t, ctx, tx, c, 10) // the key is a bound text: the database accepts the query
		got = map[string]any{"key_in_sql": strings.Contains(reportsql.SQL(c), key), "key_bound": argIndex(reportsql.Args(c), key) >= 0}
	case r.Call == "reportsql.NewRegistry":
		d := usersDataset()
		d.Columns[2].Source = report.Derived{SQL: report.SQL("pg_sleep(1)")}
		if _, err := reportsql.NewRegistry(opts(), d); err != nil {
			got = "RegistryRefused"
		} else {
			got = "no error"
		}
	case r.Call == "reportsql.Exec":
		got = errName(execUnderTimeout(t, s))
	default:
		t.Fatalf("%s: no handler for %s", r.ID, r.Call)
	}
	key, want := r.ExpectKey()
	switch key {
	case "error":
		var w string
		if err := json.Unmarshal(want, &w); err != nil {
			t.Fatal(err)
		}
		if got != w {
			t.Fatalf("%s: got %v, want error %s", r.ID, got, w)
		}
	case "value":
		g, _ := json.Marshal(got)
		if !sameJSON(g, want) {
			t.Fatalf("%s: got %s, want %s", r.ID, g, want)
		}
	default:
		t.Fatalf("%s: expectation %q", r.ID, key)
	}
}
