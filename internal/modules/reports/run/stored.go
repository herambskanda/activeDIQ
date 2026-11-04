package run

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"

	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// RowPager reads up to limit stored rows with an ordinal greater than after, in ordinal order. The export
// job supplies one that runs each call in its own short tenant transaction, so an export of a million rows
// never holds a transaction (or a cursor) open while it writes the file.
type RowPager func(ctx context.Context, after int64, limit int) ([]StoredRow, error)

// StoredSource is an export.Source and export.Counter over a run's stored result (reports.md §7.1). It is
// the only way an export reads rows: from report_run_rows, never from the directory and never through
// reportsql (RP3, ADR-0010 rule 4). Because it knows the run's row count it lets export.Run refuse a result
// over the cap before a byte is written, and because it feeds every row it serves into the canonical digest
// it lets the export job prove the file was made from exactly the rows the run's digest covers.
type StoredSource struct {
	cols   []report.Column
	header []export.Column
	total  int64
	pager  RowPager
	batch  int

	buf  []StoredRow
	pos  int
	last int64
	eof  bool
	n    int64
	dig  *export.Digester
}

var (
	_ export.Source  = (*StoredSource)(nil)
	_ export.Counter = (*StoredSource)(nil)
)

// NewStoredSource serves run r's stored rows, whose columns are cols (in stored order), through pager.
func NewStoredSource(r Run, cols []report.Column, pager RowPager) (*StoredSource, error) {
	if r.RowCount == nil || len(cols) != len(r.Columns) {
		return nil, errors.New("run: the stored source needs a succeeded run and its columns")
	}
	ids := make([]string, len(cols))
	hdr := make([]export.Column, len(cols))
	for i, c := range cols {
		ids[i], hdr[i] = string(c.ID), export.Column{Label: r.ColumnLabel(c)}
		if ids[i] != r.Columns[i] {
			return nil, errors.New("run: the columns are not the run's columns")
		}
	}
	return &StoredSource{cols: cols, header: hdr, total: *r.RowCount, pager: pager, batch: BatchSize, last: -1, dig: export.NewDigester(ids)}, nil
}

// Columns implements export.Source.
func (s *StoredSource) Columns() []export.Column { return s.header }

// Count implements export.Counter: the run's own row count, so no count query runs.
func (s *StoredSource) Count(context.Context) (int64, error) { return s.total, nil }

// Next implements export.Source.
func (s *StoredSource) Next(ctx context.Context) ([]export.Cell, error) {
	if s.pos >= len(s.buf) {
		if s.eof {
			return nil, io.EOF
		}
		rows, err := s.pager(ctx, s.last, s.batch)
		if err != nil {
			return nil, err
		}
		if len(rows) < s.batch {
			s.eof = true
		}
		if len(rows) == 0 {
			return nil, io.EOF
		}
		s.buf, s.pos = rows, 0
	}
	row := s.buf[s.pos]
	s.pos++
	if len(row.Cells) != len(s.cols) {
		return nil, fmt.Errorf("run: a stored row has %d cells, the run has %d columns", len(row.Cells), len(s.cols))
	}
	s.last = row.Ordinal
	s.n++
	s.dig.Row(typed(row.Cells))
	out := make([]export.Cell, len(row.Cells))
	for i, c := range row.Cells {
		out[i] = ExportCell(c, s.cols[i])
	}
	return out, nil
}

// Served is how many rows Next has returned.
func (s *StoredSource) Served() int64 { return s.n }

// Digest is the canonical digest of the rows served so far, over the stored columns in order. After a
// complete pass it equals the run's stored digest, or the file was not made from the run.
func (s *StoredSource) Digest() [32]byte { return s.dig.Sum() }

// ExportCell maps a stored cell onto the export model: absent is blank, never and unknown are their own
// visible texts, an enum shows its label (its ID when the column no longer lists it), a GUID its canonical
// text and a list one cell. The mapping is total over report.CellKind, which a test asserts.
func ExportCell(c report.Cell, col report.Column) export.Cell {
	switch c.Kind() {
	case report.CellText:
		return export.Text(c.Text())
	case report.CellInt:
		return export.Int64(c.Int())
	case report.CellBool:
		return export.Bool(c.Bool())
	case report.CellTime:
		return export.Time(c.Time())
	case report.CellEnum:
		for _, e := range col.Enum {
			if e.ID == c.Text() {
				return export.Text(e.Label)
			}
		}
		return export.Text(c.Text())
	case report.CellGUID:
		return export.Text(report.GUIDString(c.GUID()))
	case report.CellTextList:
		return export.Multi(c.List()...)
	case report.CellNever:
		return export.Never()
	case report.CellUnknown:
		return export.Unknown()
	}
	return export.Empty()
}

// PageAfter reads a keyset page of a succeeded run's stored rows (ordinal > after) for the export job. The
// run gate has cleared the caller already; the join keeps a page from reading a run that is not succeeded
// and live.
func PageAfter(ctx context.Context, tx store.Tx, id ID, after int64, limit int) ([]StoredRow, error) {
	rows, err := tx.Query(ctx, pageAfter, id.String(), after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredRow
	for rows.Next() {
		var sr StoredRow
		var cj string
		if err := rows.Scan(&sr.Key, &sr.Ordinal, &cj); err != nil {
			return nil, err
		}
		if err := jsonv2.Unmarshal([]byte(cj), &sr.Cells); err != nil {
			return nil, err
		}
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		// An empty page before the run's end means the rows are gone (the database clock passed expiry).
		var live bool
		if err := tx.QueryRow(ctx, runLive, id.String()).Scan(&live); err != nil {
			return nil, err
		}
		if !live {
			return nil, ErrRunExpired
		}
	}
	return out, nil
}

const pageAfter = `SELECT w.row_key, w.ordinal, w.cells::text FROM public.report_run_rows w
JOIN public.report_runs r ON r.tenant_id = w.tenant_id AND r.id = w.run_id
WHERE w.run_id = $1::uuid AND w.ordinal > $2 AND r.state = 'succeeded' AND r.expires_at > now()
ORDER BY w.ordinal LIMIT $3`

const runLive = `SELECT EXISTS (SELECT 1 FROM public.report_runs WHERE id = $1::uuid AND state = 'succeeded' AND expires_at > now())`
