package reportsql_test

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// T-1033 AC2: a text column is KindEnum only when a single-column CHECK is, as a whole, "col is one
// of these literals". A check OR-ed or AND-ed with another condition, a list holding an expression
// and a negated list leave the column KindText, so no Rel or MaskAnchor can project it.
func TestCatalogSchema_enum_is_the_whole_constraint(t *testing.T) {
	const probe = `
CREATE TABLE enum_probe (
  in_list      text NOT NULL CHECK (in_list IN ('a', 'b')),
  any_array    text NOT NULL CHECK (any_array = ANY (ARRAY['a', 'b'])),
  varchar_list varchar(10) NOT NULL CHECK (varchar_list IN ('a', 'b')),
  one_literal  text NOT NULL CHECK (one_literal = 'a' OR one_literal = 'b'),
  quoted_lits  text NOT NULL CHECK (quoted_lits IN ('it''s', 'x]y', 'a)), ')),
  "Mixed Case" text NOT NULL CHECK ("Mixed Case" IN ('a', 'b')),
  "a.b+c"      text NOT NULL CHECK ("a.b+c" IN ('a', 'b')),
  empty_ok     text NOT NULL CHECK (empty_ok IN ('', 'a')),
  single_lit   text NOT NULL CHECK (single_lit IN ('a')),

  or_open      text NOT NULL CHECK (or_open = ANY (ARRAY['a']) OR or_open ~ '^x'),
  or_in        text NOT NULL CHECK (or_in IN ('a', 'b') OR length(or_in) < 5),
  and_open     text NOT NULL CHECK (and_open IN ('a', 'b') AND length(and_open) > 0),
  expr_list    text NOT NULL CHECK (expr_list = ANY (ARRAY['a', lower(expr_list)])),
  not_in       text NOT NULL CHECK (not_in NOT IN ('a')),
  pattern_only text NOT NULL CHECK (pattern_only ~ '^[a-z]+$'),
  no_check     text NOT NULL,
  pair_a       text NOT NULL, pair_b text NOT NULL,
  CHECK (pair_a IN ('a') OR pair_b IN ('b')),
  CONSTRAINT mixed CHECK (mixed_col IN ('a', 'b') OR mixed_col <> ''),
  mixed_col    text NOT NULL
);
GRANT SELECT ON enum_probe TO activediq_app;`
	want := map[string]reportsql.ColKind{
		"in_list": reportsql.KindEnum, "any_array": reportsql.KindEnum, "varchar_list": reportsql.KindEnum,
		"quoted_lits": reportsql.KindEnum, "Mixed Case": reportsql.KindEnum, "a.b+c": reportsql.KindEnum, "empty_ok": reportsql.KindEnum,

		"single_lit":  reportsql.KindText, // PostgreSQL prints a one-element IN as col = 'a'::text: not a list, as before
		"one_literal": reportsql.KindText, // an OR of equalities is bounded, but it is not the one printed form we accept
		"or_open":     reportsql.KindText, "or_in": reportsql.KindText, "and_open": reportsql.KindText,
		"expr_list": reportsql.KindText, "not_in": reportsql.KindText, "pattern_only": reportsql.KindText,
		"no_check": reportsql.KindText, "pair_a": reportsql.KindText, "pair_b": reportsql.KindText, "mixed_col": reportsql.KindText,
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		d := s.NewDatabase(t)
		if err := d.ExecOwner(ctx, probe); err != nil {
			t.Fatal(err)
		}
		app, err := d.App(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer app.Close(ctx)
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		sch, err := reportsql.CatalogSchema(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		for col, k := range want {
			got, ok := sch.Column("enum_probe", col)
			if !ok || got != k {
				t.Errorf("enum_probe.%s = %v (found %v), want %v", col, got, ok, k)
			}
		}
	})
}
