package report_test

import (
	"sort"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

func TestCellSortKeyOrdersLikeTheValues(t *testing.T) {
	ints := report.Column{ID: "n", Type: report.TypeInt, Sortable: true}
	vals := []int64{-9223372036854775808, -5, -1, 0, 1, 7, 10, 9223372036854775807}
	keys := make([]string, len(vals))
	for i, v := range vals {
		k, ok := report.CellSortKey(report.IntCell(v), ints)
		if !ok {
			t.Fatal("an integer has a key")
		}
		keys[i] = k
	}
	if !sort.StringsAreSorted(keys) {
		t.Fatalf("integer keys do not sort like the integers: %v", keys)
	}

	times := report.Column{ID: "t", Type: report.TypeTime, Sortable: true}
	var tk []string
	for _, c := range []report.Cell{
		report.Never(),
		report.TimeCell(time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC)),
		report.TimeCell(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)),
		report.TimeCell(time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)),
	} {
		k, ok := report.CellSortKey(c, times)
		if !ok {
			t.Fatal("time and never have keys in a time column")
		}
		tk = append(tk, k)
	}
	if !sort.StringsAreSorted(tk) {
		t.Fatalf("time keys do not sort: %v", tk)
	}
}

func TestCellSortKeyTextIsCaseFoldedAndNormalised(t *testing.T) {
	col := report.Column{ID: "s", Type: report.TypeText, Sortable: true}
	a, _ := report.CellSortKey(report.TextCell("Ünal"), col)  // precomposed
	b, _ := report.CellSortKey(report.TextCell("ÜNAL"), col) // decomposed, upper case
	if a != b {
		t.Fatalf("NFC and case fold must agree: %q vs %q", a, b)
	}
}

func TestCellSortKeyEnumUsesSortRankAndGapsHaveNoKey(t *testing.T) {
	col := report.Column{ID: "e", Type: report.TypeEnum, Sortable: true,
		Enum: []report.EnumValue{{ID: "a", SortRank: 2}, {ID: report.UnknownInputMissing, SortRank: 99}}}
	if k, ok := report.CellSortKey(report.EnumCell("a"), col); !ok || k != "0000000002" {
		t.Fatalf("enum key = %q, %v", k, ok)
	}
	for _, c := range []report.Cell{report.Absent(), report.Unknown(), report.EnumCell("undeclared"), report.ListCell("x")} {
		if _, ok := report.CellSortKey(c, col); ok {
			t.Fatalf("%s must have no key", c.Tag())
		}
	}
	notSortable := report.Column{ID: "x", Type: report.TypeText}
	if _, ok := report.CellSortKey(report.TextCell("a"), notSortable); ok {
		t.Fatal("a column that is not sortable has no key")
	}
}
