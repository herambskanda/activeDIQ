package reportsql_test

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
)

func term(k authz.TermKind, conn, root byte) authz.ScopeTerm {
	return authz.ScopeTerm{Kind: k, Connection: oid(conn), Root: oid(root)}
}

func grant(inc []authz.ScopeTerm, exc ...authz.ScopeTerm) authz.ScopeGrant {
	return authz.ScopeGrant{Include: inc, Exclude: exc}
}

func compile(t *testing.T, scope authz.ReadScope, p report.RunParams) reportsql.Query {
	t.Helper()
	q, ds := resolve(t, p)
	c, err := reportsql.Compile(q, ds, scope, in())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

func guidText(b byte) string { return report.GUIDString(oid(b)) }

func argIndex(args []any, v any) int {
	for i, a := range args {
		if reflect.DeepEqual(a, v) {
			return i
		}
	}
	return -1
}

// ---- scope shapes (§4.3) --------------------------------------------------------------------------

func TestCompile_scope_shapes(t *testing.T) {
	cases := []struct {
		name  string
		scope authz.ReadScope
		want  []string // fragments the WHERE must contain
		args  []string // canonical GUIDs that must be bound
	}{
		{"subtree", authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)})),
			[]string{`"t"."ancestry_complete"`, `"t"."ancestry" @> ARRAY[$`, `"t"."object_guid" = $`, `COALESCE(`}, []string{guidText(1), guidText(2)}},
		{"naming context", authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermNamingContext, 1, 3)})),
			[]string{`"t"."nc_guid" = $`}, []string{guidText(3)}},
		{"one level", authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermOneLevel, 1, 4)})),
			[]string{`"t"."parent_guid" = $`}, []string{guidText(4)}},
		{"exclude", authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}, term(authz.TermSubtree, 1, 5))),
			[]string{`AND NOT (`}, []string{guidText(5)}},
		{"two grants are a union", authztest.ReadScope(
			grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}), grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 6)})),
			[]string{`) OR (`}, []string{guidText(2), guidText(6)}},
		{"token layer", authztest.ReadScopeWithToken(authz.TokenLayer{Include: []authz.ScopeTerm{term(authz.TermSubtree, 1, 7)}},
			grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)})),
			[]string{`) AND (`}, []string{guidText(2), guidText(7)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := compile(t, c.scope, report.RunParams{})
			sql := reportsql.SQL(q)
			for _, w := range c.want {
				if !strings.Contains(sql, w) {
					t.Errorf("SQL lacks %q:\n%s", w, sql)
				}
			}
			for _, g := range c.args {
				if argIndex(reportsql.Args(q), g) < 0 {
					t.Errorf("GUID %s is not a bound argument: %v", g, reportsql.Args(q))
				}
				if strings.Contains(sql, g) {
					t.Errorf("GUID %s is in the SQL text", g)
				}
			}
			if strings.Contains(sql, "FALSE") {
				t.Errorf("a satisfiable scope rendered FALSE:\n%s", sql)
			}
		})
	}
}

// AC 3 (AC-07): unsupported kinds, zero roots, an empty scope: the scope renders FALSE, nothing is
// widened, the reason is reported and the query still compiles.
func TestReports_unsupported_scope_fails_closed(t *testing.T) {
	valid := term(authz.TermSubtree, 1, 2)
	cases := []struct {
		name   string
		scope  authz.ReadScope
		reason string
	}{
		{"zero scope", authz.ReadScope{}, "scope_empty"},
		{"no grants", authztest.ReadScope(), "scope_empty"},
		{"unsupported include only", authztest.ReadScope(grant([]authz.ScopeTerm{{Kind: authz.TermKind(99), Connection: oid(1), Root: oid(2)}})), "scope_term_unsupported:99"},
		{"zero kind", authztest.ReadScope(grant([]authz.ScopeTerm{{Connection: oid(1), Root: oid(2)}})), "scope_term_unsupported:0"},
		{"zero root include", authztest.ReadScope(grant([]authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: oid(1)}})), "scope_term_invalid"},
		{"zero connection include", authztest.ReadScope(grant([]authz.ScopeTerm{{Kind: authz.TermSubtree, Root: oid(1)}})), "scope_term_invalid"},
		{"zero root exclude drops the grant", authztest.ReadScope(grant([]authz.ScopeTerm{valid}, authz.ScopeTerm{Kind: authz.TermSubtree, Connection: oid(1)})), "scope_term_invalid"},
		{"unsupported exclude drops the grant", authztest.ReadScope(grant([]authz.ScopeTerm{valid}, authz.ScopeTerm{Kind: authz.TermKind(42), Connection: oid(1), Root: oid(9)})), "scope_term_unsupported:42"},
		{"token with no include narrows to nothing", authztest.ReadScopeWithToken(authz.TokenLayer{}, grant([]authz.ScopeTerm{valid})), "scope_empty"},
		{"token with an unsupported term", authztest.ReadScopeWithToken(authz.TokenLayer{Include: []authz.ScopeTerm{{Kind: authz.TermKind(7), Connection: oid(1), Root: oid(2)}}}, grant([]authz.ScopeTerm{valid})), "scope_term_unsupported:7"},
		{"token with a zero root", authztest.ReadScopeWithToken(authz.TokenLayer{Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: oid(1)}}}, grant([]authz.ScopeTerm{valid})), "scope_term_invalid"},
		{"token exclude unsupported", authztest.ReadScopeWithToken(authz.TokenLayer{Include: []authz.ScopeTerm{valid}, Exclude: []authz.ScopeTerm{{Kind: authz.TermKind(7), Connection: oid(1), Root: oid(3)}}}, grant([]authz.ScopeTerm{valid})), "scope_term_unsupported:7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := compile(t, c.scope, report.RunParams{})
			sql := reportsql.SQL(q)
			if !strings.Contains(sql, "(FALSE)") {
				t.Fatalf("the scope did not render FALSE:\n%s", sql)
			}
			// No scope column of the object is read at all: nothing was admitted by accident.
			if strings.Contains(sql, `"t"."ancestry"`) || strings.Contains(sql, `"t"."nc_guid"`) {
				t.Fatalf("a FALSE scope still renders terms:\n%s", sql)
			}
			if !slicesContain(q.ScopeReasons(), c.reason) {
				t.Fatalf("reasons = %v, want %q", q.ScopeReasons(), c.reason)
			}
		})
	}
}

// A grant that cannot be bound is dropped; the other grants still apply, and nothing widens.
func TestCompile_an_invalid_grant_is_dropped_not_widened(t *testing.T) {
	bad := grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}, authz.ScopeTerm{Kind: authz.TermSubtree, Connection: oid(1)})
	ok := grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 6)})
	q := compile(t, authztest.ReadScope(bad, ok), report.RunParams{})
	if argIndex(reportsql.Args(q), guidText(2)) >= 0 {
		t.Fatal("the dropped grant's root is still bound")
	}
	if argIndex(reportsql.Args(q), guidText(6)) < 0 {
		t.Fatal("the valid grant was lost")
	}
	if !slicesContain(q.ScopeReasons(), "scope_term_invalid") {
		t.Fatalf("reasons = %v", q.ScopeReasons())
	}
}

// An unsupported include term is dropped on its own; a grant whose only include was unsupported goes.
func TestCompile_unsupported_include_keeps_the_other_terms(t *testing.T) {
	g := grant([]authz.ScopeTerm{{Kind: authz.TermKind(9), Connection: oid(1), Root: oid(2)}, term(authz.TermSubtree, 1, 3)})
	q := compile(t, authztest.ReadScope(g), report.RunParams{})
	if argIndex(reportsql.Args(q), guidText(3)) < 0 || argIndex(reportsql.Args(q), guidText(2)) >= 0 {
		t.Fatalf("args = %v", reportsql.Args(q))
	}
}

func TestCompile_producer_reasons_come_first_in_order(t *testing.T) {
	s := authztest.ReadScopeWithReasons([]authz.ScopeReason{"b_reason", "a_reason"},
		grant([]authz.ScopeTerm{{Kind: authz.TermKind(9), Connection: oid(1), Root: oid(2)}}))
	q := compile(t, s, report.RunParams{})
	want := []string{"b_reason", "a_reason", "scope_term_unsupported:9"}
	if got := q.ScopeReasons(); !reflect.DeepEqual(got, want) {
		t.Fatalf("reasons = %v, want %v", got, want)
	}
}

func TestCompile_refuses_an_oversized_scope(t *testing.T) {
	var inc []authz.ScopeTerm
	for i := 0; i <= reportsql.MaxScopeTerms; i++ {
		inc = append(inc, authz.ScopeTerm{Kind: authz.TermSubtree, Connection: oid(1), Root: authz.ObjectID{byte(i), byte(i >> 8), 1}})
	}
	q, ds := resolve(t, report.RunParams{})
	_, err := reportsql.Compile(q, ds, authztest.ReadScope(grant(inc)), in())
	if !errors.Is(err, reportsql.ErrScopeTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if _, err := reportsql.Compile(q, ds, authztest.ReadScope(grant(inc[:reportsql.MaxScopeTerms])), in()); err != nil {
		t.Fatalf("exactly the cap must compile: %v", err)
	}
}

func TestCompile_requires_Now_and_a_resolved_query(t *testing.T) {
	q, ds := resolve(t, report.RunParams{})
	s := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}))
	if _, err := reportsql.Compile(q, ds, s, reportsql.Inputs{}); !errors.Is(err, reportsql.ErrNoNow) {
		t.Fatalf("zero Now: %v", err)
	}
	if _, err := reportsql.Compile(report.Query{}, ds, s, in()); err == nil {
		t.Fatal("an unresolved Query compiled")
	}
	if _, err := reportsql.Compile(q, reportsql.Dataset{}, s, in()); err == nil {
		t.Fatal("the zero Dataset compiled")
	}
}

// ---- narrowing (§4.4) -----------------------------------------------------------------------------

func TestCompile_narrowing_is_anded_with_the_scope(t *testing.T) {
	s := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}))
	n := report.RunParams{
		Connections: []authz.ObjectID{oid(1)},
		Include:     []report.NarrowRoot{{Connection: oid(1), Root: oid(8), Depth: report.DepthOneLevel}},
		Exclude:     []report.NarrowRoot{{Connection: oid(1), Root: oid(9), Depth: report.DepthSubtree}},
	}
	q := compile(t, s, n)
	sql := reportsql.SQL(q)
	for _, g := range []string{guidText(8), guidText(9)} {
		if argIndex(reportsql.Args(q), g) < 0 || strings.Contains(sql, g) {
			t.Fatalf("narrowing root %s is not bound", g)
		}
	}
	if !strings.Contains(sql, `"t"."connection_id" = ANY(`) || !strings.Contains(sql, "NOT (") {
		t.Fatalf("SQL = %s", sql)
	}
	// With the scope FALSE the narrowing cannot widen it.
	q = compile(t, authz.ReadScope{}, n)
	if !strings.Contains(reportsql.SQL(q), "(FALSE)") {
		t.Fatal("an empty scope with a narrowing is not FALSE")
	}
	// An empty narrowing adds nothing.
	empty := reportsql.SQL(compile(t, s, report.RunParams{}))
	if strings.Contains(empty, "ANY(") {
		t.Fatalf("empty narrowing rendered a clause: %s", empty)
	}
}

func TestCompile_refuses_a_zero_GUID_in_a_narrowing(t *testing.T) {
	q, ds := resolve(t, report.RunParams{})
	s := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}))
	for name, n := range map[string]report.Narrowing{
		"connection":   {Connections: []authz.ObjectID{{}}},
		"include root": {Include: []report.NarrowRoot{{Connection: oid(1), Depth: report.DepthSubtree}}},
		"exclude conn": {Exclude: []report.NarrowRoot{{Root: oid(1), Depth: report.DepthSubtree}}},
		"depth":        {Include: []report.NarrowRoot{{Connection: oid(1), Root: oid(2), Depth: report.Depth(77)}}},
	} {
		q2 := q
		q2.Narrowing = n
		_, err := reportsql.Compile(q2, ds, s, in())
		if code, ok := report.CodeOf(err); !ok || code != report.CodeBadNarrowing {
			t.Errorf("%s: err = %v, want bad_narrowing", name, err)
		}
	}
}

// ---- values, columns and sort keys (AC 5, AC 6) --------------------------------------------------

var hostile = []string{
	"'; DROP TABLE directory_objects; --", "' OR '1'='1", `" OR ""="`, "x'); DELETE FROM directory_objects; --",
	"\\'; --", "%' OR 1=1 --", "$$", "${jndi}", "a\u2028b", "'||(SELECT pg_sleep(10))||'", "Robert'); DROP TABLE students;--",
}

func TestCompile_hostile_values_are_bound_never_in_sql(t *testing.T) {
	s := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}))
	for _, h := range hostile {
		for _, op := range []report.Op{report.OpEq, report.OpContains, report.OpPrefix} {
			q, ds := resolve(t, report.RunParams{Filters: []report.Expr{report.Cmp{Column: "name", Op: op, Value: report.TextV(h)}}})
			c, err := reportsql.Compile(q, ds, s, in())
			if err != nil {
				t.Fatalf("%q: %v", h, err)
			}
			sql := reportsql.SQL(c)
			if strings.Contains(sql, h) {
				t.Fatalf("hostile value %q is in the SQL text:\n%s", h, sql)
			}
			bound := false
			for _, a := range reportsql.Args(c) {
				if sa, ok := a.(string); ok && strings.Contains(sa, strings.Trim(h, "%")) {
					bound = true
				}
				if v, ok := a.(driver.Valuer); ok {
					if dv, _ := v.Value(); dv != nil && strings.Contains(strings.ReplaceAll(fmt.Sprint(dv), `\`, ""), strings.ReplaceAll(strings.Trim(h, "%"), `\`, "")) {
						bound = true
					}
				}
			}
			if !bound {
				t.Fatalf("%q is not among the bound arguments %v", h, reportsql.Args(c))
			}
		}
	}
}

func TestCompile_in_list_binds_one_array(t *testing.T) {
	vals := []report.Value{report.TextV("a"), report.TextV("'; DROP TABLE x; --")}
	q, ds := resolve(t, report.RunParams{Filters: []report.Expr{report.Cmp{Column: "sam", Op: report.OpIn, Values: vals}}})
	c, err := reportsql.Compile(q, ds, authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)})), in())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(reportsql.SQL(c), "DROP") || argIndex(reportsql.Args(c), []string{"a", "'; DROP TABLE x; --"}) < 0 {
		t.Fatalf("SQL = %s args = %v", reportsql.SQL(c), reportsql.Args(c))
	}
}

// The renderer itself refuses what Resolve would have: it does not rely on its caller.
func TestRenderer_refuses_unknown_and_hostile_columns_operators_and_sort_keys(t *testing.T) {
	_, ds := resolve(t, report.RunParams{})
	for _, id := range []report.ColumnID{"nope", "name; DROP TABLE x", `"name"`, "", "unicodePwd", "NAME"} {
		if _, _, err := reportsql.Cmp(ds, report.Cmp{Column: id, Op: report.OpEq, Value: report.TextV("x")}, fixedNow); !errors.Is(err, reportsql.ErrUnknownColumn) {
			t.Errorf("filter column %q: %v", id, err)
		}
		if _, _, err := reportsql.OrderBy(ds, []report.SortKey{{Column: id, Dir: report.Asc}}); !errors.Is(err, reportsql.ErrUnknownColumn) {
			t.Errorf("sort column %q: %v", id, err)
		}
	}
	if _, _, err := reportsql.OrderBy(ds, []report.SortKey{{Column: "name", Dir: report.SortDir(9)}}); !errors.Is(err, reportsql.ErrBadSortDirection) {
		t.Errorf("direction: %v", err)
	}
	if _, _, err := reportsql.OrderBy(ds, []report.SortKey{{Column: "enabled", Dir: report.Asc}}); !errors.Is(err, reportsql.ErrBadOperator) {
		t.Errorf("a column that is not sortable: %v", err)
	}
	if _, _, err := reportsql.OrderBy(ds, []report.SortKey{{Column: "last_logon", Dir: report.Asc}}); !errors.Is(err, reportsql.ErrPerDCInSQL) {
		t.Errorf("per-DC sort: %v", err)
	}
	if _, _, err := reportsql.Cmp(ds, report.Cmp{Column: "last_logon", Op: report.OpOlderThanDays, Value: report.IntV(3)}, fixedNow); !errors.Is(err, reportsql.ErrPerDCInSQL) {
		t.Errorf("per-DC filter: %v", err)
	}
	for _, op := range []report.Op{report.Op(200), report.OpGt} {
		if _, _, err := reportsql.Cmp(ds, report.Cmp{Column: "name", Op: op, Value: report.TextV("x")}, fixedNow); !errors.Is(err, reportsql.ErrBadOperator) {
			t.Errorf("operator %d: %v", op, err)
		}
	}
	for name, c := range map[string]report.Cmp{
		"wrong type":    {Column: "name", Op: report.OpEq, Value: report.IntV(1)},
		"enum not in":   {Column: "status", Op: report.OpEq, Value: report.EnumV("sleeping")},
		"NUL":           {Column: "name", Op: report.OpEq, Value: report.TextV("a\x00b")},
		"bad UTF-8":     {Column: "name", Op: report.OpEq, Value: report.TextV("a\xffb")},
		"zero GUID":     {Column: "object_guid", Op: report.OpEq, Value: report.GUIDV(authz.ObjectID{})},
		"days negative": {Column: "pwd_last_set", Op: report.OpOlderThanDays, Value: report.IntV(-1)},
		"days huge":     {Column: "pwd_last_set", Op: report.OpOlderThanDays, Value: report.IntV(1 << 40)},
		"unbound param": {Column: "name", Op: report.OpEq, Param: "p"},
		"empty in":      {Column: "sam", Op: report.OpIn},
	} {
		if _, _, err := reportsql.Cmp(ds, c, fixedNow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	vals := make([]report.Value, report.MaxInValues+1)
	for i := range vals {
		vals[i] = report.TextV("x")
	}
	if _, _, err := reportsql.Cmp(ds, report.Cmp{Column: "sam", Op: report.OpIn, Values: vals}, fixedNow); !errors.Is(err, reportsql.ErrTooManyValues) {
		t.Errorf("too many values: %v", err)
	}
}

func TestCompile_sort_and_row_key_tie_break(t *testing.T) {
	_, ds := resolve(t, report.RunParams{})
	s, args, err := reportsql.OrderBy(ds, []report.SortKey{{Column: "status", Dir: report.Desc}, {Column: "pwd_last_set", Dir: report.Asc}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(s, ", 1") || !strings.Contains(s, "DESC NULLS LAST") || !strings.Contains(s, "ASC NULLS LAST") || !strings.Contains(s, "CASE") {
		t.Fatalf("order = %s", s)
	}
	if argIndex(args, "enabled") < 0 || !strings.Contains(s, "WHEN $1::text THEN 2") {
		t.Fatalf("enum IDs must be bound: %s %v", s, args)
	}
}

func TestCompile_JSON_key_is_bound(t *testing.T) {
	q := compile(t, authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)})), report.RunParams{})
	if strings.Contains(reportsql.SQL(q), "'cn'") || argIndex(reportsql.Args(q), "cn") < 0 {
		t.Fatalf("the JSON key must be bound: %s %v", reportsql.SQL(q), reportsql.Args(q))
	}
}

func TestCompile_relative_time_and_now_are_bound(t *testing.T) {
	s := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}))
	q, ds := resolve(t, report.RunParams{Filters: []report.Expr{report.Cmp{Column: "pwd_last_set", Op: report.OpOlderThanDays, Value: report.IntV(90)}}})
	c, err := reportsql.Compile(q, ds, s, in())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(reportsql.SQL(c), "now()") || strings.Contains(strings.ToLower(reportsql.SQL(c)), "current_timestamp") {
		t.Fatalf("the SQL reads the database clock: %s", reportsql.SQL(c))
	}
	if argIndex(reportsql.Args(c), fixedNow) < 0 || argIndex(reportsql.Args(c), int64(90)) < 0 {
		t.Fatalf("args = %v", reportsql.Args(c))
	}
}

func TestCompileCount_shares_from_and_where(t *testing.T) {
	s := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}))
	p := report.RunParams{Filters: []report.Expr{report.Cmp{Column: "sam", Op: report.OpEq, Value: report.TextV("bob")}}}
	q, ds := resolve(t, p)
	rows, err := reportsql.Compile(q, ds, s, in())
	if err != nil {
		t.Fatal(err)
	}
	cnt, err := reportsql.CompileCount(q, ds, s, in())
	if err != nil {
		t.Fatal(err)
	}
	rs, cs := reportsql.SQL(rows), reportsql.SQL(cnt)
	if !strings.HasPrefix(cs, "SELECT count(*) FROM") {
		t.Fatalf("count = %s", cs)
	}
	body := func(s string) string {
		i := strings.Index(s, " FROM ")
		if j := strings.Index(s, " ORDER BY"); j > 0 {
			return s[i:j]
		}
		return s[i:]
	}
	num := regexp.MustCompile(`\$\d+`)
	if num.ReplaceAllString(body(rs), "$") != num.ReplaceAllString(body(cs), "$") {
		t.Fatalf("the count has a different FROM/WHERE:\nrows:  %s\ncount: %s", body(rs), body(cs))
	}
	if strings.Contains(cs, "ORDER BY") || strings.Contains(cs, "LIMIT") {
		t.Fatal("a count orders or limits")
	}
}

func TestCompile_subjects_need_the_t_anchor_and_bind_ids(t *testing.T) {
	s := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}))
	q, ds := resolve(t, report.RunParams{Subjects: []authz.ObjectID{oid(5), oid(6)}})
	c, err := reportsql.Compile(q, ds, s, in())
	if err != nil {
		t.Fatal(err)
	}
	if argIndex(reportsql.Args(c), []string{guidText(5), guidText(6)}) < 0 {
		t.Fatalf("subjects not bound: %v", reportsql.Args(c))
	}
}

func TestCompile_limit_is_bound_and_top_wins_when_smaller(t *testing.T) {
	s := authztest.ReadScope(grant([]authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}))
	q, ds := resolve(t, report.RunParams{})
	c, err := reportsql.Compile(q, ds, s, reportsql.Inputs{Now: fixedNow, Limit: 1001})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reportsql.SQL(c), " LIMIT $") || argIndex(reportsql.Args(c), int64(1001)) < 0 {
		t.Fatalf("SQL = %s args = %v", reportsql.SQL(c), reportsql.Args(c))
	}
	c, _ = reportsql.Compile(q, ds, s, in())
	if strings.Contains(reportsql.SQL(c), "LIMIT") {
		t.Fatal("no limit was asked for")
	}
}

func slicesContain(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
