package report_test

import (
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

var readAt = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func answer(dc string, logon time.Time, bad time.Time, count int64) report.PerDCResult {
	return report.PerDCResult{DC: dc, Values: []report.PerDCValue{
		{Attr: report.PerDCLastLogon, Time: logon}, {Attr: report.PerDCBadPasswordTime, Time: bad}, {Attr: report.PerDCBadPwdCount, Int: count}}}
}

func down(dc string) report.PerDCResult { return report.PerDCResult{DC: dc, Err: "unavailable"} }

var perDCCols = func() []report.Column {
	pd := func(id report.ColumnID, t report.ValueType, s report.PerDC) report.Column {
		return report.Column{ID: id, Label: string(id), Type: t, Source: s}
	}
	return []report.Column{
		pd("logon", report.TypeTime, report.PerDC{Attr: report.PerDCLastLogon, Agg: report.AggMax}),
		pd("logon_dc", report.TypeText, report.PerDC{Attr: report.PerDCLastLogon, Agg: report.AggMax, Part: report.PartFromDC}),
		pd("days", report.TypeInt, report.PerDC{Attr: report.PerDCLastLogon, Agg: report.AggMax, Part: report.PartDaysSince}),
		pd("cov", report.TypeText, report.PerDC{Attr: report.PerDCLastLogon, Agg: report.AggMax, Part: report.PartCoverage}),
		pd("bad", report.TypeTime, report.PerDC{Attr: report.PerDCBadPasswordTime, Agg: report.AggMax}),
		pd("bad_count", report.TypeInt, report.PerDC{Attr: report.PerDCBadPwdCount, Agg: report.AggMax, Part: report.PartAtWinner, Of: report.PerDCBadPasswordTime}),
	}
}()

// AC-39: the real last logon is the maximum over the DCs, from the DC that holds it, and complete coverage.
func Test_perdc_maximum_over_dcs_names_the_dc(t *testing.T) {
	d1 := readAt.Add(-48 * time.Hour)
	d3 := readAt.Add(-5 * 24 * time.Hour)
	var zero time.Time
	obj := report.PerDCObject{Results: []report.PerDCResult{answer("dc2", zero, zero, 0), answer("dc3", d3, zero, 0), answer("dc1", d1, zero, 0)}}
	f := report.FoldPerDC(obj)
	c := f.Cells(perDCCols, readAt)
	if got := c.Stored["logon"]; got.Kind() != report.CellTime || !got.Time().Equal(d1) {
		t.Fatalf("logon = %+v", got)
	}
	if got := c.Stored["logon_dc"].Text(); got != "dc1" {
		t.Fatalf("from DC = %q", got)
	}
	if got := c.Stored["cov"].Text(); got != "3 of 3 DCs" || !f.Complete() {
		t.Fatalf("coverage = %q complete %v", got, f.Complete())
	}
	if got := c.Stored["days"]; got.Kind() != report.CellInt || got.Int() != 2 {
		t.Fatalf("days = %+v", got)
	}
}

// AC-40: one DC silent, and the user has no logon on the others: Not confirmed, never "never".
func Test_perdc_partial_coverage_is_not_never(t *testing.T) {
	var zero time.Time
	obj := report.PerDCObject{Results: []report.PerDCResult{answer("dc1", zero, zero, 0), answer("dc2", zero, zero, 0), down("dc3")}}
	f := report.FoldPerDC(obj)
	c := f.Cells(perDCCols, readAt)
	if f.Complete() {
		t.Fatal("complete with a DC down")
	}
	if got := c.Stored["logon"]; got.Kind() != report.CellText || got.Text() != report.NotConfirmedText {
		t.Fatalf("logon = %+v, want Not confirmed", got)
	}
	if got := c.Eval["logon"]; !got.IsUnknown() {
		t.Fatalf("eval cell = %+v, want unknown", got)
	}
	if got := c.Stored["cov"].Text(); got != "2 of 3 DCs" {
		t.Fatalf("coverage = %q", got)
	}
	if c.Stored["logon_dc"].Kind() != report.CellAbsent {
		t.Fatalf("from DC = %+v", c.Stored["logon_dc"])
	}
	// the same account with every DC answering and no logon anywhere IS never
	all := report.FoldPerDC(report.PerDCObject{Results: []report.PerDCResult{answer("dc1", zero, zero, 0), answer("dc2", zero, zero, 0)}})
	if got := all.Cells(perDCCols, readAt).Stored["logon"]; got.Kind() != report.CellNever {
		t.Fatalf("complete and unset = %+v, want never", got)
	}
	// a value on an answering DC under partial coverage is kept: it is a lower bound
	lb := report.FoldPerDC(report.PerDCObject{Results: []report.PerDCResult{answer("dc1", readAt.Add(-time.Hour), zero, 0), down("dc2")}})
	if got := lb.Cells(perDCCols, readAt).Stored["logon"]; got.Kind() != report.CellTime {
		t.Fatalf("lower bound = %+v", got)
	}
}

// The failure count is the count at the DC of the latest failed logon, never a sum.
func Test_perdc_count_is_at_the_winning_dc_and_never_summed(t *testing.T) {
	f := report.FoldPerDC(report.PerDCObject{Results: []report.PerDCResult{
		answer("dc1", readAt, readAt.Add(-time.Hour), 3), answer("dc2", readAt, readAt.Add(-time.Minute), 4), answer("dc3", readAt, readAt.Add(-2*time.Hour), 9)}})
	c := f.Cells(perDCCols, readAt)
	if got := c.Stored["bad_count"]; got.Int() != 4 {
		t.Fatalf("failures on that DC = %+v, want 4 (dc2), not 16", got)
	}
}

func cmp(col string, op report.Op, v report.Value) report.Cmp {
	return report.Cmp{Column: report.ColumnID(col), Op: op, Value: v}
}

func Test_EvalPerDC(t *testing.T) {
	var zero time.Time
	recent := report.FoldPerDC(report.PerDCObject{Results: []report.PerDCResult{answer("dc1", zero, readAt.Add(-24*time.Hour), 2)}}).Cells(perDCCols, readAt).Eval
	old := report.FoldPerDC(report.PerDCObject{Results: []report.PerDCResult{answer("dc1", zero, readAt.Add(-10*24*time.Hour), 2)}}).Cells(perDCCols, readAt).Eval
	silent := report.FoldPerDC(report.PerDCObject{Results: []report.PerDCResult{answer("dc1", zero, zero, 0), down("dc2")}}).Cells(perDCCols, readAt).Eval
	week := cmp("bad", report.OpWithinLastDays, report.IntV(7))
	for _, tc := range []struct {
		name string
		e    report.Expr
		row  map[report.ColumnID]report.Cell
		want bool
	}{
		{"nil", nil, recent, true},
		{"within, recent", week, recent, true},
		{"within, old", week, old, false},
		{"older than, old", cmp("bad", report.OpOlderThanDays, report.IntV(7)), old, true},
		{"count gt", cmp("bad_count", report.OpGt, report.IntV(1)), recent, true},
		{"count eq", cmp("bad_count", report.OpEq, report.IntV(3)), recent, false},
		{"and", report.And{Terms: []report.Expr{week, cmp("bad_count", report.OpGe, report.IntV(2))}}, recent, true},
		{"or", report.Or{Terms: []report.Expr{cmp("bad_count", report.OpGt, report.IntV(9)), week}}, old, false},
		{"not", report.Not{Term: week}, old, true},
		{"unconfirmed matches no comparison", week, silent, false},
		{"unconfirmed is not absent", cmp("bad", report.OpAbsent, report.Value{}), silent, false},
		{"not of unconfirmed stays false", report.Not{Term: week}, silent, false},
		{"present", cmp("bad", report.OpPresent, report.Value{}), recent, true},
	} {
		got, err := report.EvalPerDC(tc.e, tc.row, readAt)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := report.EvalPerDC(cmp("nope", report.OpEq, report.IntV(1)), recent, readAt); err == nil {
		t.Error("an unknown column was accepted")
	}
}

func Test_PerDCReads_saturates_and_tally_names_unreachable(t *testing.T) {
	if got := report.PerDCReads(41_200, 6); got != 247_200 {
		t.Fatalf("estimate = %d", got)
	}
	if got := report.PerDCReads(1<<62, 1<<62); got != ^uint64(0) {
		t.Fatalf("overflow not saturated: %d", got)
	}
	var tally report.PerDCTally
	var zero time.Time
	tally.Add(report.PerDCObject{Results: []report.PerDCResult{answer("dc1", zero, zero, 0), down("dc3")}})
	tally.Add(report.PerDCObject{Results: []report.PerDCResult{answer("dc1", zero, zero, 0), down("dc3")}})
	if tally.Complete() || tally.InScope != 2 || tally.Answered != 1 || len(tally.Sorted()) != 1 || tally.Sorted()[0] != (report.DCFault{DC: "dc3", Err: "unavailable"}) {
		t.Fatalf("tally = %+v", tally)
	}
}
