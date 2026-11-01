package run

import (
	"context"
	"io"
	"iter"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/export/csv"
	"github.com/skenzeriq/activediq/internal/platform/report"
)

var storedCols = []report.Column{
	{ID: "name", Label: "Name", Type: report.TypeText},
	{ID: "n", Label: "Count", Type: report.TypeInt},
	{ID: "seen", Label: "Last seen", Type: report.TypeTime},
	{ID: "kind", Label: "Kind", Type: report.TypeEnum, Enum: []report.EnumValue{{ID: "u", Label: "User"}, {ID: "c", Label: "Computer"}}},
}

func storedRowAt(i int64) StoredRow {
	return StoredRow{Key: "k", Ordinal: i, Cells: []report.Cell{
		report.TextCell("account-" + strings.Repeat("x", int(i%40))),
		report.IntCell(i),
		report.TimeCell(time.Unix(1_700_000_000+i, 0)),
		report.EnumCell([]string{"u", "c"}[i%2]),
	}}
}

// pagerOf serves n generated rows by keyset, as the job's pager does, without a database.
func pagerOf(n int64) RowPager {
	return func(_ context.Context, after int64, limit int) ([]StoredRow, error) {
		var out []StoredRow
		for i := after + 1; i < n && len(out) < limit; i++ {
			out = append(out, storedRowAt(i))
		}
		return out, nil
	}
}

func storedRun(n int64) Run {
	return Run{RowCount: &n, Columns: []string{"name", "n", "seen", "kind"}}
}

// AC-25: a 300k-row export streams; the heap never holds the result. The bound is far below the size of the
// file (tens of MB), so a source or encoder that buffered rows would fail it.
func TestStoredExportStreamsInBoundedMemory(t *testing.T) {
	const n = 300_000
	src, err := NewStoredSource(storedRun(n), storedCols, pagerOf(n))
	if err != nil {
		t.Fatal(err)
	}
	var peak uint64
	var ms runtime.MemStats
	sink := &countingWriter{onWrite: func(total int64) {
		if total%(1<<20) < 4096 {
			runtime.ReadMemStats(&ms)
			peak = max(peak, ms.HeapAlloc)
		}
	}}
	runtime.GC()
	enc, err := csv.Format(csv.Options{}).New(sink)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := export.Run(context.Background(), src, enc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if src.Served() != n || rep.Rows != n {
		t.Fatalf("served=%d rendered=%d, want %d", src.Served(), rep.Rows, n)
	}
	if sink.total < 10<<20 {
		t.Fatalf("file only %d bytes: the test would not catch buffering", sink.total)
	}
	const bound = 16 << 20 // the file is ~19 MB, so buffering it would break this
	if peak > bound {
		t.Fatalf("peak heap %d MB over the %d MB bound while writing a %d MB file", peak>>20, bound>>20, sink.total>>20)
	}
	t.Logf("300k rows, %d MB file, peak heap %d MB", sink.total>>20, peak>>20)

	want := export.Digest([]string{"name", "n", "seen", "kind"}, func() iter.Seq[[]export.Typed] {
		return func(yield func([]export.Typed) bool) {
			for i := int64(0); i < n; i++ {
				if !yield(typed(storedRowAt(i).Cells)) {
					return
				}
			}
		}
	}())
	if src.Digest() != want {
		t.Fatal("the served digest differs from an independent recomputation over the same rows")
	}
}

type countingWriter struct {
	total   int64
	onWrite func(int64)
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.total += int64(len(p))
	w.onWrite(w.total)
	return len(p), nil
}

// A source over a run whose count is over the cap refuses before any row is read.
func TestStoredSourceRefusesOverCapBeforeReading(t *testing.T) {
	calls := 0
	src, err := NewStoredSource(storedRun(11), storedCols, func(context.Context, int64, int) ([]StoredRow, error) {
		calls++
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := csv.Format(csv.Options{}).New(io.Discard)
	if _, err := export.Run(context.Background(), src, enc, 10); err != export.ErrRowCapExceeded {
		t.Fatalf("err = %v, want ErrRowCapExceeded", err)
	}
	if calls != 0 {
		t.Fatalf("the pager ran %d times before the cap refusal", calls)
	}
}

func TestStoredSourceRejectsCellCountMismatch(t *testing.T) {
	src, err := NewStoredSource(storedRun(1), storedCols, func(context.Context, int64, int) ([]StoredRow, error) {
		return []StoredRow{{Ordinal: 0, Cells: []report.Cell{report.TextCell("only one")}}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Next(context.Background()); err == nil || !strings.Contains(err.Error(), "cells") {
		t.Fatalf("err = %v, want a cell-count error", err)
	}
}

func TestNewStoredSourceChecksColumns(t *testing.T) {
	if _, err := NewStoredSource(Run{Columns: []string{"name"}}, storedCols[:1], nil); err == nil {
		t.Fatal("a run without a row count must be refused")
	}
	n := int64(0)
	if _, err := NewStoredSource(Run{RowCount: &n, Columns: []string{"other"}}, storedCols[:1], nil); err == nil {
		t.Fatal("columns that are not the run's must be refused")
	}
}

// ExportCell is total: every defined kind maps to something, and the four "no value" kinds stay distinct.
func TestExportCellTotal(t *testing.T) {
	enum := report.Column{Type: report.TypeEnum, Enum: []report.EnumValue{{ID: "u", Label: "User"}}}
	cells := map[report.CellKind]report.Cell{
		report.CellAbsent:   report.Absent(),
		report.CellText:     report.TextCell("t"),
		report.CellInt:      report.IntCell(7),
		report.CellBool:     report.BoolCell(true),
		report.CellTime:     report.TimeCell(time.Unix(1_700_000_000, 0)),
		report.CellEnum:     report.EnumCell("u"),
		report.CellGUID:     report.GUIDCell([16]byte{1}),
		report.CellTextList: report.ListCell("a", "b"),
		report.CellNever:    report.Never(),
		report.CellUnknown:  report.Unknown(),
	}
	// 0..9 are the defined kinds; a cell can only carry one of these through the constructors above.
	for k := report.CellAbsent; k <= report.CellUnknown; k++ {
		c, ok := cells[k]
		if !ok {
			t.Fatalf("kind %d has no constructor in this test: a new CellKind needs a mapping in ExportCell and a row here", k)
		}
		if c.Kind() != k {
			t.Fatalf("constructor for %d built kind %d", k, c.Kind())
		}
		resolve(t, ExportCell(c, enum)) // must map and resolve
	}
	if got := resolve(t, ExportCell(cells[report.CellEnum], enum)); got.Text != "User" {
		t.Errorf("enum = %+v, want its label", got)
	}
	if got := resolve(t, ExportCell(report.EnumCell("gone"), enum)); got.Text != "gone" {
		t.Errorf("a retired enum value must show its ID, got %+v", got)
	}
	distinct := map[export.Resolved]bool{}
	for _, k := range []report.CellKind{report.CellAbsent, report.CellNever, report.CellUnknown} {
		distinct[resolve(t, ExportCell(cells[k], enum))] = true
	}
	if len(distinct) != 3 {
		t.Errorf("absent, never and unknown must export differently, got %v", distinct)
	}
}

func resolve(t *testing.T, c export.Cell) export.Resolved {
	t.Helper()
	r, err := c.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	return r
}
