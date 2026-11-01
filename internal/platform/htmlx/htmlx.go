// Package htmlx is the HTML output of the product (safe-primitives §12.5). Today it holds the HTML
// export: a standalone document with no active content, written row by row as an export.Encoder.
//
// The page structure lives in templates/*.html, embedded and parsed once with html/template, so
// every data value is escaped for its context by the template engine and no HTML is ever assembled by
// string formatting (rule 1, O1). Rule 4 is built in: the first <head> element is the Content-Security-
// Policy meta (default-src 'none'; style-src pinned to the SHA-256 of the one <style> block;
// img-src data:), there is no <script>, no link and no external URL, and every data value sits in
// <bdi> (O6). The typed template strings (template.HTML and friends) are never used: nothing in this
// package is exempted from escaping.
package htmlx

import (
	"bufio"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/export/cellsafe"
)

//go:embed templates/*.html
var templateFS embed.FS

var tpl = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// styleSHA256 is the SHA-256 of the text between <style> and </style> in head.html, which the CSP
// pins. It is computed from the embedded template at start-up, so the policy cannot drift from the CSS.
var styleSHA256 = func() [sha256.Size]byte {
	b, err := templateFS.ReadFile("templates/head.html")
	if err != nil {
		panic(err)
	}
	s := string(b)
	i := strings.Index(s, "<style>")
	j := strings.Index(s, "</style>")
	if i < 0 || j < i {
		panic("htmlx: head.html has no <style> block")
	}
	return sha256.Sum256([]byte(s[i+len("<style>") : j]))
}()

// StyleSHA256 is the hash a download's Content-Security-Policy header must pin for the HTML export
// (httpx.WithStyleSHA256).
func StyleSHA256() [sha256.Size]byte { return styleSHA256 }

// Options configures a Writer.
type Options struct {
	// Title is the report title: the <title> and the heading.
	Title string
	// MaxRows lowers the data-row cap (never above export.MaxDataRows); 0 means the maximum.
	MaxRows int64
	// About, when not empty, is shown under the heading (reports-2a §8.3).
	About []export.AboutLine
	// Location is the time zone Time cells are shown in, with its abbreviation; nil means UTC.
	Location *time.Location
}

// MaxTitleUnits bounds the title (R5).
const MaxTitleUnits = 255

// Writer streams the HTML export. It is not safe for concurrent use.
type Writer struct {
	bw      *bufio.Writer
	o       Options
	loc     *time.Location
	maxRows int64
	hdr     bool
	closed  bool
	width   int
	rep     export.RenderReport
	err     error
}

var _ export.Encoder = (*Writer)(nil)

type headData struct {
	Title     string
	StyleHash string
	About     []export.AboutLine
	Cols      []string
}

type cellView struct {
	Class string
	Text  string
}

// Cell classes: n number, t text (also the spreadsheet text format, see head.html), d date and time, e empty.
const (
	classNum   = "n"
	classText  = "t"
	classDate  = "d"
	classEmpty = "e"
)

// NewWriter returns a Writer on w. Nothing is written until Header.
func NewWriter(w io.Writer, o Options) (*Writer, error) {
	if len(o.About) > export.MaxAboutLines {
		return nil, export.ErrTooManyColumns
	}
	max := o.MaxRows
	if max <= 0 || max > export.MaxDataRows {
		max = export.MaxDataRows
	}
	loc := o.Location
	if loc == nil {
		loc = time.UTC
	}
	x := &Writer{bw: bufio.NewWriterSize(w, 64<<10), o: o, loc: loc, maxRows: max}
	x.o.Title, _ = export.Sanitize(o.Title)
	x.o.Title, _ = export.LimitCell(x.o.Title, MaxTitleUnits)
	if strings.TrimSpace(x.o.Title) == "" {
		x.o.Title = "Report"
	}
	return x, nil
}

// Header writes the document head, the About block and the column labels. It must come first and only once.
func (x *Writer) Header(cols []export.Column) error {
	if x.closed {
		return export.ErrClosed
	}
	if x.hdr || x.rep.Rows > 0 {
		return export.ErrHeaderAfterRow
	}
	if len(cols) > export.MaxColumns {
		return export.ErrTooManyColumns
	}
	x.hdr, x.width = true, len(cols)
	d := headData{Title: x.o.Title, StyleHash: base64.StdEncoding.EncodeToString(styleSHA256[:])}
	for _, a := range x.o.About {
		d.About = append(d.About, export.AboutLine{Label: x.text(a.Label), Value: x.text(a.Value)})
	}
	for _, c := range cols {
		d.Cols = append(d.Cols, x.text(c.Label))
	}
	return x.exec("head.html", d)
}

// Row writes one data row. It returns export.ErrRowCapExceeded for the row after the cap.
func (x *Writer) Row(cells []export.Cell) error {
	if x.closed {
		return export.ErrClosed
	}
	if x.rep.Rows >= x.maxRows {
		return export.ErrRowCapExceeded
	}
	if x.err != nil {
		return x.err
	}
	if !x.hdr {
		if err := x.Header(make([]export.Column, len(cells))); err != nil {
			return err
		}
	}
	if len(cells) != x.width {
		return export.ErrColumnMismatch
	}
	views := make([]cellView, len(cells))
	for i, c := range cells {
		r, err := c.Resolve()
		if err != nil {
			return err
		}
		views[i] = x.view(r)
	}
	if err := x.exec("row.html", views); err != nil {
		return err
	}
	x.rep.Rows++
	return nil
}

func (x *Writer) view(r export.Resolved) cellView {
	switch r.Kind {
	case export.KindEmpty:
		return cellView{Class: classEmpty}
	case export.KindInt:
		return cellView{Class: classNum, Text: strconv.FormatInt(r.Int, 10)}
	case export.KindFloat:
		return cellView{Class: classNum, Text: export.FormatFloat(r.Float)}
	case export.KindBool:
		return cellView{Class: classText, Text: strconv.FormatBool(r.Bool)}
	case export.KindTime:
		return cellView{Class: classDate, Text: r.Time.In(x.loc).Format("2006-01-02 15:04:05 MST")}
	}
	return x.textCell(r.Text)
}

// textCell is a text value. A value a spreadsheet could read as a formula is counted, as in the other
// encoders (O8): in HTML the cell is already text-typed (class t, head.html), so the value is shown as is.
func (x *Writer) textCell(s string) cellView {
	t := x.text(s)
	if cellsafe.Classify(t) == cellsafe.FormulaLead {
		x.rep.Neutralised++
	}
	return cellView{Class: classText, Text: t}
}

// text prepares one value for the page: valid UTF-8, within the cell limit, CRLF as LF, other control
// characters visible as ⟨U+XXXX⟩ (O3). Bidi and other format characters are kept: <bdi> isolates them (O6).
func (x *Writer) text(s string) string {
	s, mapped := export.Sanitize(s)
	if mapped {
		x.rep.Mapped++
	}
	s, cut := export.LimitCell(s, export.MaxCellUnits)
	if cut {
		x.rep.Truncated++
	}
	if !needsMapping(s) {
		return s
	}
	var b strings.Builder
	rs := []rune(s)
	changed := false
	for i, r := range rs {
		switch {
		case r == '\t' || r == '\n':
			b.WriteRune(r)
		case r == '\r' && i+1 < len(rs) && rs[i+1] == '\n':
			// CRLF: the LF follows.
		case unicode.Is(unicode.Cc, r):
			changed = true
			b.WriteString("⟨U+" + hex4(r) + "⟩")
		default:
			b.WriteRune(r)
		}
	}
	if changed {
		x.rep.Mapped++
	}
	return b.String()
}

func needsMapping(s string) bool {
	for _, r := range s {
		if r != '\t' && r != '\n' && unicode.Is(unicode.Cc, r) {
			return true
		}
	}
	return false
}

func hex4(r rune) string {
	h := strings.ToUpper(strconv.FormatInt(int64(r), 16))
	if len(h) < 4 {
		h = strings.Repeat("0", 4-len(h)) + h
	}
	return h
}

func (x *Writer) exec(name string, data any) error {
	if x.err != nil {
		return x.err
	}
	if err := tpl.ExecuteTemplate(x.bw, name, data); err != nil {
		x.err = err
	}
	return x.err
}

// Close writes the document end and returns the RenderReport. A document with no Header still gets its head.
func (x *Writer) Close() (export.RenderReport, error) {
	if x.closed {
		return x.rep, export.ErrClosed
	}
	if !x.hdr && x.err == nil {
		x.Header(nil)
	}
	x.closed = true
	if x.err == nil {
		x.exec("foot.html", nil)
	}
	if err := x.bw.Flush(); err != nil && x.err == nil {
		x.err = err
	}
	return x.rep, x.err
}

// Format is the export.Format for HTML, for export.RunToBlob.
func Format(o Options) export.Format {
	return export.Format{
		ContentType: "text/html; charset=utf-8",
		New:         func(w io.Writer) (export.Encoder, error) { return NewWriter(w, o) },
	}
}
