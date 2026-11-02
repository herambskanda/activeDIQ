// Package xlsx is the streaming XLSX writer (safe-primitives §12.4). It is built directly on
// archive/zip and a fixed set of SpreadsheetML parts instead of a general spreadsheet library, so the
// format features the spec forbids (formulas, hyperlinks, comments, images, data validation, defined
// names, external links, connections, macros) are not filtered out: the API cannot express them (O5).
// The workbook shape is fixed (rule 4) and the only text cell encoding is t="inlineStr".
package xlsx

import (
	"archive/zip"
	"bufio"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/export/cellsafe"
)

// MaxSheetNameUnits is Excel's sheet-name limit in UTF-16 code units.
const MaxSheetNameUnits = 31

// MaxTitleUnits bounds the dc:title (R5).
const MaxTitleUnits = 255

// SheetName is a sheet name that is valid for Excel. Only ParseSheetName makes one.
type SheetName struct{ s string }

// String returns the name.
func (n SheetName) String() string { return n.s }

// ParseSheetName maps a label to a valid sheet name (O3): Cc, Cf and \ / : * ? " < > | % [ ] become
// '_'; a leading or trailing apostrophe becomes '_'; the reserved name "History" gets a '_' suffix;
// it is capped at 31 UTF-16 units and never empty (default "Sheet1").
func ParseSheetName(s string) SheetName {
	s, _ = export.Sanitize(s)
	var b strings.Builder
	units := 0
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || strings.ContainsRune(`\/:*?"<>|%[]`, r):
			r = '_'
		case r == '\'' && (i == 0 || i == len(rs)-1):
			r = '_'
		}
		n := utf16.RuneLen(r)
		if units+n > MaxSheetNameUnits {
			break
		}
		units += n
		b.WriteRune(r)
	}
	out := b.String()
	if strings.TrimSpace(out) == "" {
		return SheetName{"Sheet1"}
	}
	if strings.EqualFold(out, "History") {
		out += "_"
	}
	return SheetName{out}
}

// Options configures a Writer.
type Options struct {
	// Sheet names the single sheet. The zero SheetName is "Sheet1".
	Sheet SheetName
	// Title is the report title, stored as dc:title (data, XML-escaped).
	Title string
	// MaxRows lowers the data-row cap (never above export.MaxDataRows); 0 means the maximum.
	MaxRows int64
	// About, when not empty, adds a first sheet named "About" with one label and one value per line
	// (the export About block, reports-2a §8.3). Labels and values are text cells with the same rules
	// as every other cell; the block is small and fixed before the data streams.
	About []AboutLine
}

// AboutLine is one label and value of the About sheet.
type AboutLine = export.AboutLine

// AboutSheetName is the name of the About sheet. A data sheet of the same name gets a suffix.
const AboutSheetName = "About"

// MaxAboutLines bounds the About sheet.
const MaxAboutLines = export.MaxAboutLines

// Style indexes in styles.xml cellXfs.
const (
	styleDefault   = 0
	styleQuote     = 1 // quotePrefix="1"
	styleHeader    = 2 // bold
	styleHeaderQ   = 3 // bold + quotePrefix
	styleDateTime  = 4
	headerRowIndex = 1
)

// Writer streams one worksheet. Not safe for concurrent use.
type Writer struct {
	zw      *zip.Writer
	bw      *bufio.Writer // current sheet part, nil before the first row
	sheet   SheetName
	title   string
	maxRows int64
	hdr     bool
	width   int
	rowNo   int
	closed  bool
	rep     export.RenderReport
	err     error
	bwOpen  bool
	about   []AboutLine
}

var _ export.Encoder = (*Writer)(nil)

// NewWriter returns a Writer on w. The static parts are written immediately; the sheet streams.
func NewWriter(w io.Writer, o Options) (*Writer, error) {
	max := o.MaxRows
	if max <= 0 || max > export.MaxDataRows {
		max = export.MaxDataRows
	}
	sheet := o.Sheet
	if sheet.s == "" {
		sheet = SheetName{"Sheet1"}
	}
	if len(o.About) > MaxAboutLines {
		return nil, export.ErrTooManyColumns
	}
	if len(o.About) > 0 && strings.EqualFold(sheet.s, AboutSheetName) {
		sheet = SheetName{sheet.s + "_"}
	}
	x := &Writer{zw: zip.NewWriter(w), sheet: sheet, maxRows: max, about: o.About}
	x.title, _ = export.Sanitize(o.Title)
	x.title, _ = export.LimitCell(x.title, MaxTitleUnits)
	if err := x.static(); err != nil {
		return nil, err
	}
	return x, nil
}

func (x *Writer) part(name, body string) error {
	f, err := x.zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.WriteString(f, body)
	return err
}

const xmlDecl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

func (x *Writer) static() error {
	aboutType, aboutSheet, aboutRel := "", "", ""
	if len(x.about) > 0 {
		aboutType = `<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`
		aboutSheet = `<sheet name="` + AboutSheetName + `" sheetId="2" r:id="rId3"/>`
		aboutRel = `<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>`
	}
	parts := []struct{ name, body string }{
		{"[Content_Types].xml", xmlDecl + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
			`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` + aboutType +
			`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` +
			`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
			`</Types>`},
		{"_rels/.rels", xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
			`</Relationships>`},
		{"docProps/core.xml", xmlDecl + `<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ` +
			`xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>` + escape(x.title) + `</dc:title></cp:coreProperties>`},
		{"xl/workbook.xml", xmlDecl + `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ` +
			`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>` + aboutSheet +
			`<sheet name="` + escape(x.sheet.s) + `" sheetId="1" r:id="rId1"/></sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` + aboutRel +
			`</Relationships>`},
		{"xl/styles.xml", xmlDecl + `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
			`<numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy\-mm\-dd\ hh:mm:ss"/></numFmts>` +
			`<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>` +
			`<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>` +
			`<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>` +
			`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
			`<cellXfs count="5">` +
			`<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
			`<xf numFmtId="49" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1" quotePrefix="1"/>` +
			`<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>` +
			`<xf numFmtId="49" fontId="1" fillId="0" borderId="0" xfId="0" applyNumberFormat="1" applyFont="1" quotePrefix="1"/>` +
			`<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>` +
			`</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`},
	}
	for _, p := range parts {
		if err := x.part(p.name, p.body); err != nil {
			return err
		}
	}
	return x.aboutSheet()
}

// aboutSheet writes the About sheet part: label in column A (bold), value in column B.
func (x *Writer) aboutSheet() error {
	if len(x.about) == 0 {
		return nil
	}
	f, err := x.zw.Create("xl/worksheets/sheet2.xml")
	if err != nil {
		return err
	}
	x.bw = bufio.NewWriterSize(f, 16<<10)
	x.bw.WriteString(xmlDecl + `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for i, l := range x.about {
		n := strconv.Itoa(i + 1)
		x.bw.WriteString(`<row r="` + n + `">`)
		x.cell("A"+n, export.Resolved{Kind: export.KindText, Text: l.Label}, true)
		x.cell("B"+n, export.Resolved{Kind: export.KindText, Text: l.Value}, false)
		x.bw.WriteString(`</row>`)
	}
	x.bw.WriteString(`</sheetData></worksheet>`)
	err = x.bw.Flush()
	x.bw = nil
	return err
}

// openSheet starts the streaming sheet part.
func (x *Writer) openSheet() error {
	if x.bwOpen {
		return nil
	}
	f, err := x.zw.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		return err
	}
	x.bw = bufio.NewWriterSize(f, 64<<10)
	x.bwOpen = true
	x.bw.WriteString(xmlDecl + `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	return nil
}

// Header writes the column labels (bold). Labels are text cells with the same rules as values.
func (x *Writer) Header(cols []export.Column) error {
	if x.closed {
		return export.ErrClosed
	}
	if x.hdr || x.rowNo > 0 {
		return export.ErrHeaderAfterRow
	}
	if len(cols) > export.MaxColumns {
		return export.ErrTooManyColumns
	}
	cells := make([]export.Cell, len(cols))
	for i, c := range cols {
		cells[i] = export.Text(c.Label)
	}
	x.hdr, x.width = true, len(cols)
	return x.write(cells, true)
}

// Row writes one data row; the row after the cap is export.ErrRowCapExceeded (XL-14).
func (x *Writer) Row(cells []export.Cell) error {
	if x.closed {
		return export.ErrClosed
	}
	if x.rep.Rows >= x.maxRows {
		return export.ErrRowCapExceeded
	}
	if x.hdr && len(cells) != x.width {
		return export.ErrColumnMismatch
	}
	if len(cells) > export.MaxColumns {
		return export.ErrTooManyColumns
	}
	if err := x.write(cells, false); err != nil {
		return err
	}
	x.rep.Rows++
	return nil
}

func (x *Writer) write(cells []export.Cell, header bool) error {
	if x.err != nil {
		return x.err
	}
	res := make([]export.Resolved, len(cells))
	for i, c := range cells {
		r, err := c.Resolve()
		if err != nil {
			return err
		}
		res[i] = r
	}
	if err := x.openSheet(); err != nil {
		x.err = err
		return err
	}
	x.rowNo++
	w := x.bw
	w.WriteString(`<row r="` + strconv.Itoa(x.rowNo) + `">`)
	for i, r := range res {
		ref := colName(i) + strconv.Itoa(x.rowNo)
		x.cell(ref, r, header)
	}
	w.WriteString(`</row>`)
	return nil
}

func (x *Writer) cell(ref string, r export.Resolved, header bool) {
	w := x.bw
	switch r.Kind {
	case export.KindEmpty:
		return // no cell element at all
	case export.KindInt:
		w.WriteString(`<c r="` + ref + `" t="n"><v>` + strconv.FormatInt(r.Int, 10) + `</v></c>`)
	case export.KindFloat:
		w.WriteString(`<c r="` + ref + `" t="n"><v>` + export.FormatFloat(r.Float) + `</v></c>`)
	case export.KindBool:
		v := "0"
		if r.Bool {
			v = "1"
		}
		w.WriteString(`<c r="` + ref + `" t="b"><v>` + v + `</v></c>`)
	case export.KindTime:
		w.WriteString(`<c r="` + ref + `" s="` + strconv.Itoa(styleDateTime) + `" t="n"><v>` + serial(r) + `</v></c>`)
	default:
		s, mapped := export.Sanitize(r.Text)
		if mapped {
			x.rep.Mapped++
		}
		s, cut := export.LimitCell(s, export.MaxCellUnits)
		if cut {
			x.rep.Truncated++
		}
		style := styleDefault
		if header {
			style = styleHeader
		}
		if cellsafe.Classify(s) == cellsafe.FormulaLead {
			x.rep.Neutralised++
			style = styleQuote
			if header {
				style = styleHeaderQ
			}
		}
		attr := ""
		if s != "" && (unicode.IsSpace([]rune(s)[0]) || unicode.IsSpace(lastRune(s))) {
			attr = ` xml:space="preserve"`
		}
		sattr := ""
		if style != styleDefault {
			sattr = ` s="` + strconv.Itoa(style) + `"`
		}
		w.WriteString(`<c r="` + ref + `"` + sattr + ` t="inlineStr"><is><t` + attr + `>` + escape(s) + `</t></is></c>`)
	}
}

func lastRune(s string) rune {
	rs := []rune(s)
	return rs[len(rs)-1]
}

// Close finishes the sheet and the archive and returns the RenderReport.
func (x *Writer) Close() (export.RenderReport, error) {
	if x.closed {
		return x.rep, export.ErrClosed
	}
	x.closed = true
	if x.err == nil {
		if err := x.openSheet(); err != nil {
			x.err = err
		}
	}
	if x.err == nil {
		x.bw.WriteString(`</sheetData></worksheet>`)
		if err := x.bw.Flush(); err != nil {
			x.err = err
		}
	}
	if err := x.zw.Close(); err != nil && x.err == nil {
		x.err = err
	}
	return x.rep, x.err
}

// Format is the export.Format for XLSX, for export.RunToBlob.
func Format(o Options) export.Format {
	return export.Format{
		ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		New:         func(w io.Writer) (export.Encoder, error) { return NewWriter(w, o) },
	}
}
