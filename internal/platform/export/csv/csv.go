// Package csv is the CSV writer and its inverse reader (safe-primitives §12.3). It is the only
// package that names the CSV media type or extension (with httpx) and the only one allowed to
// import encoding/csv (FF-SP1).
//
// There is no WriteRaw, no []string row and no TAB delimiter. Every text field is quoted; a field
// that cellsafe classifies as a formula lead gets a TAB inside the quotes; Reader reverses that.
package csv

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/export/cellsafe"
)

// Delimiter is the closed set of field delimiters. There is deliberately no Tab: the TAB is the
// neutraliser, and a TAB-delimited file would turn it into a cell break (CSV-16).
type Delimiter uint8

const (
	// Comma is the default (zero value).
	Comma Delimiter = iota
	// Semicolon is for list-separator-';' locales.
	Semicolon
)

// ErrDelimiterNotAllowed is the wire form of CSV-16: the Delimiter is not Comma or Semicolon.
var ErrDelimiterNotAllowed = errors.New("csv: DelimiterNotAllowed")

func (d Delimiter) byte() (byte, bool) {
	switch d {
	case Comma:
		return ',', true
	case Semicolon:
		return ';', true
	}
	return 0, false
}

// Options configures a Writer or Reader. The zero value is comma, UTF-8 BOM, the default row cap.
type Options struct {
	Delimiter Delimiter
	// OmitBOM drops the UTF-8 byte order mark. Excel needs it to read UTF-8, so the default is to write it.
	OmitBOM bool
	// MaxRows lowers the data-row cap (never raises it above export.MaxDataRows); 0 means the maximum.
	MaxRows int64
}

const (
	tab = "\t"
	bom = "\xEF\xBB\xBF" // UTF-8 byte order mark
)

// Writer streams CSV. It is not safe for concurrent use.
type Writer struct {
	bw      *bufio.Writer
	delim   byte
	started bool
	closed  bool
	hdr     bool
	width   int
	maxRows int64
	rep     export.RenderReport
	err     error
}

var _ export.Encoder = (*Writer)(nil)

// NewWriter returns a Writer on w. The BOM is written first, before the header.
func NewWriter(w io.Writer, o Options) (*Writer, error) {
	d, ok := o.Delimiter.byte()
	if !ok {
		return nil, ErrDelimiterNotAllowed
	}
	max := o.MaxRows
	if max <= 0 || max > export.MaxDataRows {
		max = export.MaxDataRows
	}
	wr := &Writer{bw: bufio.NewWriterSize(w, 64<<10), delim: d, maxRows: max}
	if !o.OmitBOM {
		wr.bw.WriteString(bom)
	}
	return wr, nil
}

// Header writes the column labels; they go through the same cell rules as values.
func (w *Writer) Header(cols []export.Column) error {
	if w.closed {
		return export.ErrClosed
	}
	if w.hdr || w.started {
		return export.ErrHeaderAfterRow
	}
	if len(cols) > export.MaxColumns {
		return export.ErrTooManyColumns
	}
	cells := make([]export.Cell, len(cols))
	for i, c := range cols {
		cells[i] = export.Text(c.Label)
	}
	w.hdr, w.width = true, len(cols)
	return w.write(cells)
}

// Row writes one data row. It returns export.ErrRowCapExceeded for the row after the cap.
func (w *Writer) Row(cells []export.Cell) error {
	if w.closed {
		return export.ErrClosed
	}
	if w.rep.Rows >= w.maxRows {
		return export.ErrRowCapExceeded
	}
	if w.hdr && len(cells) != w.width {
		return export.ErrColumnMismatch
	}
	if len(cells) > export.MaxColumns {
		return export.ErrTooManyColumns
	}
	if err := w.write(cells); err != nil {
		return err
	}
	w.rep.Rows++
	return nil
}

func (w *Writer) write(cells []export.Cell) error {
	if w.err != nil {
		return w.err
	}
	w.started = true
	// Resolve every cell first so a bad cell leaves no partial record behind.
	res := make([]export.Resolved, len(cells))
	for i, c := range cells {
		r, err := c.Resolve()
		if err != nil {
			return err
		}
		res[i] = r
	}
	for i, r := range res {
		if i > 0 {
			w.bw.WriteByte(w.delim)
		}
		w.field(r)
	}
	w.bw.WriteByte('\r') // RFC 4180 record terminator, written as bytes: FF-SP3 reserves CRLF literals for notify/mail
	w.bw.WriteByte('\n')
	return nil
}

func (w *Writer) field(r export.Resolved) {
	switch r.Kind {
	case export.KindEmpty:
		// An empty cell is an unquoted empty field, distinct from the empty string "".
	case export.KindInt:
		w.bw.WriteString(strconv.FormatInt(r.Int, 10))
	case export.KindFloat:
		w.bw.WriteString(export.FormatFloat(r.Float))
	case export.KindBool:
		w.bw.WriteString(strconv.FormatBool(r.Bool))
	case export.KindTime:
		w.bw.WriteString(r.Time.Format(export.TimeLayout))
	default:
		w.text(r.Text)
	}
}

func (w *Writer) text(s string) {
	s, mapped := export.Sanitize(s)
	if mapped {
		w.rep.Mapped++
	}
	s, cut := export.LimitCell(s, export.MaxCellUnits)
	if cut {
		w.rep.Truncated++
	}
	w.bw.WriteByte('"')
	if cellsafe.Classify(s) == cellsafe.FormulaLead {
		w.rep.Neutralised++
		w.bw.WriteString(tab)
	}
	for {
		i := strings.IndexByte(s, '"')
		if i < 0 {
			break
		}
		w.bw.WriteString(s[:i+1])
		w.bw.WriteByte('"')
		s = s[i+1:]
	}
	w.bw.WriteString(s)
	w.bw.WriteByte('"')
}

// Close flushes and returns the RenderReport. A file with no header and no rows still gets its BOM.
func (w *Writer) Close() (export.RenderReport, error) {
	if w.closed {
		return w.rep, export.ErrClosed
	}
	w.closed = true
	if err := w.bw.Flush(); err != nil && w.err == nil {
		w.err = err
	}
	return w.rep, w.err
}

// Format is the export.Format for CSV, for export.RunToBlob.
func Format(o Options) export.Format {
	return export.Format{
		ContentType: "text/csv; charset=utf-8",
		New:         func(w io.Writer) (export.Encoder, error) { return NewWriter(w, o) },
	}
}
