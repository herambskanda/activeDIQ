// Package pdf is the streaming PDF writer (safe-primitives §12.7). It is built directly on the PDF
// file structure instead of a PDF library or an HTML-to-PDF engine, the way export/xlsx is built on
// archive/zip: the format features the spec forbids (links, annotations, JavaScript, actions,
// attachments, forms, page import) are not filtered out, the API cannot express them (O5, rule 3).
//
// Data enters only as text runs: every string is written as a hex string, so no cell can end a string,
// start an operator or open a name (rule 2). Text uses the standard Helvetica and Helvetica-Bold fonts,
// which every reader supplies, so nothing is embedded or fetched. A character the standard font has no
// glyph for is drawn with a visible fallback glyph and carries its real code point in a /ToUnicode map,
// so extracted text equals the input (rule 5, PDF-13). Cc, Cf, U+2028 and U+2029 are drawn as the
// visible token ⟨U+XXXX⟩ (O3, O6).
//
// Layout is fixed before the rows stream: A4 landscape, a fixed column width per column, the header row
// repeated on every page, a row taller than a page split across pages. Memory holds one page.
package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"

	"github.com/skenzeriq/activediq/internal/platform/export"
)

// Limits (O7). Named constants; provisional until load tests.
const (
	// MaxRows is the encoder's own row cap (O7). The report export's cap for PDF is lower (5,000).
	MaxRows = 100_000
	// MaxCellLines is the most lines one cell shows; a longer cell ends with the truncation marker.
	MaxCellLines = 200
	// MaxColumns is the widest table a page holds legibly.
	MaxColumns = 24
	// MaxFallbackRunes bounds the distinct non-WinAnsi characters one weight can draw; past it a
	// character is drawn as U+FFFD, visibly and counted.
	MaxFallbackRunes = 2048
	// MaxTitleUnits bounds /Title and the printed title (R5).
	MaxTitleUnits = 255
	// MaxHeaderLines is the most lines a column label wraps to, so a header row always fits a page.
	MaxHeaderLines = 3
)

// Page geometry in points (A4 landscape).
const (
	pageW, pageH = 842.0, 595.0
	margin       = 36.0
	footerH      = 18.0
	pad          = 3.0
	textSize     = 8.0
	leading      = 10.0
	aboutSize    = 9.0
	aboutLead    = 12.0
	titleSize    = 14.0
	titleLead    = 18.0
	aboutLabelW  = 130.0
)

// Options configures a Writer.
type Options struct {
	// Title is the report title: the document's /Title (UTF-16BE hex) and the heading of page 1.
	Title string
	// MaxRows lowers the data-row cap (never above MaxRows); 0 means MaxRows.
	MaxRows int64
	// About, when not empty, is printed under the title on the first page (reports-2a §8.3).
	About []export.AboutLine
	// Location is the time zone Time cells are shown in, with its abbreviation; nil means UTC.
	Location *time.Location
}

// Writer streams a PDF. It is not safe for concurrent use.
type Writer struct {
	cw      *countWriter
	o       Options
	loc     *time.Location
	maxRows int64
	hdr     bool
	closed  bool
	started bool // first page begun
	width   int
	colX    []float64 // left edge of each column
	colW    []float64
	hdrCols []export.Column
	rep     export.RenderReport
	err     error

	nextID  int
	pageIDs []int
	offs    map[int]int64

	page   bytes.Buffer
	pageNo int
	y      float64 // top-down cursor: the next free y on the page, in PDF coordinates
	table  bool    // the header row repeats on a new page
	fresh  bool    // nothing but the header is on this page yet

	fonts fontRegistry
}

var _ export.Encoder = (*Writer)(nil)

// Fixed object numbers, so pages written before the end can point at them.
const (
	idCatalog   = 1
	idPages     = 2
	idInfo      = 3
	idResources = 4
	idFirstFree = 5
)

// NewWriter returns a Writer on w. The file header is written immediately.
func NewWriter(w io.Writer, o Options) (*Writer, error) {
	if len(o.About) > export.MaxAboutLines {
		return nil, export.ErrTooManyColumns
	}
	max := o.MaxRows
	if max <= 0 || max > MaxRows {
		max = MaxRows
	}
	loc := o.Location
	if loc == nil {
		loc = time.UTC
	}
	p := &Writer{cw: &countWriter{w: w}, o: o, loc: loc, maxRows: max, nextID: idFirstFree, offs: map[int]int64{}}
	p.fonts.init()
	p.o.Title, _ = export.Sanitize(o.Title)
	p.o.Title, _ = export.LimitCell(p.o.Title, MaxTitleUnits)
	p.write("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")
	return p, p.err
}

// Header fixes the column layout. It must come first and only once.
func (p *Writer) Header(cols []export.Column) error {
	if p.closed {
		return export.ErrClosed
	}
	if p.hdr || p.rep.Rows > 0 {
		return export.ErrHeaderAfterRow
	}
	if len(cols) > MaxColumns {
		return export.ErrTooManyColumns
	}
	p.hdr, p.width, p.hdrCols = true, len(cols), cols
	p.layoutColumns()
	if p.err != nil {
		return p.err
	}
	p.beginPage() // title, About block, then the header row
	p.table = true
	p.drawRow(headerCells(cols), true)
	p.fresh = true
	return p.err
}

// Row writes one data row. It returns export.ErrRowCapExceeded for the row after the cap.
func (p *Writer) Row(cells []export.Cell) error {
	if p.closed {
		return export.ErrClosed
	}
	if p.rep.Rows >= p.maxRows {
		return export.ErrRowCapExceeded
	}
	if p.hdr && len(cells) != p.width {
		return export.ErrColumnMismatch
	}
	if len(cells) > MaxColumns {
		return export.ErrTooManyColumns
	}
	if p.err != nil {
		return p.err
	}
	if !p.hdr { // a row without a header: equal columns, no header row
		p.hdr, p.width = true, len(cells)
		p.layoutColumns()
		p.beginPage()
		p.fresh = true
	}
	// Resolve first so a bad cell leaves nothing half drawn.
	for _, c := range cells {
		if _, err := c.Resolve(); err != nil {
			return err
		}
	}
	p.drawRow(cells, false)
	if p.err != nil {
		return p.err
	}
	p.rep.Rows++
	return nil
}

// Close finishes the last page and writes the document structure.
func (p *Writer) Close() (export.RenderReport, error) {
	if p.closed {
		return p.rep, export.ErrClosed
	}
	p.closed = true
	if p.err != nil {
		return p.rep, p.err
	}
	if !p.started {
		p.beginPage()
	}
	p.flushPage()
	p.writeTail()
	return p.rep, p.err
}

// Format is the export.Format for PDF, for export.RunToBlob.
func Format(o Options) export.Format {
	return export.Format{
		ContentType: "application/pdf",
		New:         func(w io.Writer) (export.Encoder, error) { return NewWriter(w, o) },
	}
}

// ---- layout ----

func (p *Writer) layoutColumns() {
	n := p.width
	usable := pageW - 2*margin
	if n == 0 {
		return
	}
	weights := make([]float64, n)
	var sum float64
	for i := range weights {
		w := 44.0
		if i < len(p.hdrCols) {
			g, _ := p.glyphs(p.hdrCols[i].Label, true, false)
			w = clamp(runWidth(g, textSize)+16, 44, 200)
		}
		weights[i] = w
		sum += w
	}
	p.colX, p.colW = make([]float64, n), make([]float64, n)
	x := margin
	for i := range weights {
		p.colW[i] = weights[i] / sum * usable
		p.colX[i] = x
		x += p.colW[i]
	}
}

func clamp(v, lo, hi float64) float64 {
	return max(lo, min(hi, v))
}

type line struct {
	g []glyph
	w float64
}

// wrap breaks glyphs into lines no wider than width. A hard break is a glyph with code '\n' in
// font nl. At most maxLines lines are returned; cut reports that glyphs were left over.
func wrap(gs []glyph, width, size float64, maxLines int) (lines []line, cut bool) {
	var cur line
	lastBreak := -1 // index in cur.g just after the last space
	flush := func() bool {
		lines = append(lines, cur)
		cur, lastBreak = line{}, -1
		return len(lines) >= maxLines
	}
	for i, g := range gs {
		if g.nl {
			if flush() {
				return lines, i+1 < len(gs)
			}
			continue
		}
		w := g.w * size / 1000
		if cur.w+w > width && len(cur.g) > 0 {
			if lastBreak > 0 {
				head := line{g: append([]glyph(nil), cur.g[:lastBreak]...)}
				head.w = runWidth(head.g, size)
				rest := append([]glyph(nil), cur.g[lastBreak:]...)
				cur = head
				if flush() {
					return lines, true
				}
				cur.g = rest
				cur.w = runWidth(rest, size)
			} else if flush() {
				return lines, true
			}
		}
		cur.g = append(cur.g, g)
		cur.w += w
		if g.space {
			lastBreak = len(cur.g)
		}
	}
	if len(cur.g) > 0 || len(lines) == 0 {
		lines = append(lines, cur)
	}
	return lines, false
}

func runWidth(gs []glyph, size float64) float64 {
	var w float64
	for _, g := range gs {
		if !g.nl {
			w += g.w * size / 1000
		}
	}
	return w
}

// cellLines renders one cell into lines for a column of width colW, and says whether it is numeric.
func (p *Writer) cellLines(c export.Cell, bold bool, colW float64, maxLines int) (lines []line, numeric bool) {
	r, _ := c.Resolve() // checked by Row; the header cells are text
	var s string
	switch r.Kind {
	case export.KindEmpty:
	case export.KindInt:
		s, numeric = strconv.FormatInt(r.Int, 10), true
	case export.KindFloat:
		s, numeric = export.FormatFloat(r.Float), true
	case export.KindBool:
		s = strconv.FormatBool(r.Bool)
	case export.KindTime:
		s = r.Time.In(p.loc).Format("2006-01-02 15:04:05 MST")
	default:
		s = r.Text
	}
	gs, changed := p.glyphs(s, bold, true)
	if changed {
		p.rep.Mapped++
	}
	lines, cut := wrap(gs, colW-2*pad, textSize, maxLines)
	if cut {
		p.rep.Truncated++
		total := utf8.RuneCountInString(s)
		m, _ := p.glyphs("… [truncated: "+strconv.Itoa(total)+" chars]", bold, false)
		lines = append(lines, line{g: m, w: runWidth(m, textSize)})
	}
	return lines, numeric
}

// ---- page flow ----

func (p *Writer) newID() int {
	id := p.nextID
	p.nextID++
	return id
}

func (p *Writer) beginPage() {
	p.started = true
	p.fresh = true
	p.pageNo++
	p.page.Reset()
	p.y = pageH - margin
	if p.pageNo == 1 {
		p.drawTitleAndAbout()
	}
}

func (p *Writer) bottom() float64 { return margin + footerH }

// newPage ends the current page and starts the next, repeating the table header.
func (p *Writer) newPage() {
	p.flushPage()
	p.beginPage()
	if p.table {
		p.drawRow(headerCells(p.hdrCols), true)
		p.fresh = true
	}
}

func headerCells(cols []export.Column) []export.Cell {
	cells := make([]export.Cell, len(cols))
	for i, c := range cols {
		cells[i] = export.Text(c.Label)
	}
	return cells
}

func (p *Writer) drawTitleAndAbout() {
	if p.o.Title != "" {
		gs, _ := p.glyphs(p.o.Title, true, true)
		ls, _ := wrap(gs, pageW-2*margin, titleSize, 3)
		for _, l := range ls {
			p.emitLine(l, margin, p.y-titleSize, titleSize)
			p.y -= titleLead
		}
		p.y -= 4
	}
	for _, a := range p.o.About {
		lg, ch1 := p.glyphs(a.Label, true, true)
		vg, ch2 := p.glyphs(a.Value, false, true)
		if ch1 || ch2 {
			p.rep.Mapped++
		}
		lls, _ := wrap(lg, aboutLabelW-4, aboutSize, 2)
		vls, vcut := wrap(vg, pageW-2*margin-aboutLabelW, aboutSize, MaxCellLines)
		if vcut {
			p.rep.Truncated++
			m, _ := p.glyphs("… [truncated: "+strconv.Itoa(utf8.RuneCountInString(a.Value))+" chars]", false, false)
			vls = append(vls, line{g: m, w: runWidth(m, aboutSize)})
		}
		n := max(len(lls), len(vls))
		for i := 0; i < n; i++ {
			if p.y-aboutLead < p.bottom() {
				p.flushPage()
				p.pageNo++
				p.page.Reset()
				p.y = pageH - margin
			}
			if i < len(lls) {
				p.emitLine(lls[i], margin, p.y-aboutSize, aboutSize)
			}
			if i < len(vls) {
				p.emitLine(vls[i], margin+aboutLabelW, p.y-aboutSize, aboutSize)
			}
			p.y -= aboutLead
		}
	}
	if len(p.o.About) > 0 || p.o.Title != "" {
		p.y -= 8
	}
}

// drawRow lays one row out and draws it, across pages if it is taller than the room left.
func (p *Writer) drawRow(cells []export.Cell, header bool) {
	type col struct {
		ls  []line
		num bool
	}
	cs := make([]col, len(cells))
	maxLines := 1
	limit := MaxCellLines
	if header {
		limit = MaxHeaderLines
	}
	for i, c := range cells {
		ls, num := p.cellLines(c, header, p.colW[i], limit)
		cs[i] = col{ls, num}
		maxLines = max(maxLines, len(ls))
	}
	const fullPage = 49 // lines of a page: (pageH - 2*margin - footerH - 2*pad) / leading, rounded down
	pos := 0
	for pos < maxLines {
		avail := int((p.y - p.bottom() - 2*pad) / leading)
		remaining := maxLines - pos
		if avail < 1 || (pos == 0 && !p.fresh && remaining <= fullPage-MaxHeaderLines-1 && remaining > avail) {
			// Not even one line fits, or a row that fits a page whole would be split: start a page.
			// newPage draws the repeated header row, so a header row stops here.
			p.newPage()
			if header {
				return
			}
			continue
		}
		n := min(remaining, avail)
		h := float64(n)*leading + 2*pad
		top := p.y
		if header {
			p.page.WriteString("0.90 g\n")
			p.rect(margin, top-h, pageW-2*margin, h, "f")
			p.page.WriteString("0 g\n")
		}
		for i, c := range cs {
			x := p.colX[i]
			p.page.WriteString("0.6 G 0.5 w\n")
			p.rect(x, top-h, p.colW[i], h, "S")
			for k := 0; k < n && pos+k < len(c.ls); k++ {
				l := c.ls[pos+k]
				tx := x + pad
				if c.num {
					tx = x + p.colW[i] - pad - l.w
				}
				p.emitLine(l, tx, top-pad-textSize-float64(k)*leading+1.5, textSize)
			}
		}
		p.y -= h
		pos += n
		if !header {
			p.fresh = false
		}
		if pos < maxLines {
			p.newPage()
			if header {
				return
			}
		}
	}
}

func (p *Writer) rect(x, y, w, h float64, op string) {
	p.page.WriteString(num(x) + " " + num(y) + " " + num(w) + " " + num(h) + " re " + op + "\n")
}

// emitLine writes one line as one text object. Runs of one font share a Tf and a Tj.
func (p *Writer) emitLine(l line, x, y, size float64) {
	if len(l.g) == 0 {
		return
	}
	p.page.WriteString("BT " + num(x) + " " + num(y) + " Td")
	font := -1
	var hex strings.Builder
	flush := func() {
		if hex.Len() > 0 {
			p.page.WriteString(" <" + hex.String() + "> Tj")
			hex.Reset()
		}
	}
	for _, g := range l.g {
		if g.font != font {
			flush()
			p.page.WriteString(" /" + fontName(g.font) + " " + num(size) + " Tf")
			font = g.font
		}
		const digits = "0123456789ABCDEF"
		hex.WriteByte(digits[g.code>>4])
		hex.WriteByte(digits[g.code&15])
	}
	flush()
	p.page.WriteString(" ET\n")
}

func num(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}

// flushPage writes the footer, compresses the content and writes the page's two objects.
func (p *Writer) flushPage() {
	if p.pageNo == 0 || p.err != nil {
		return
	}
	foot, _ := p.glyphs("Page "+strconv.Itoa(p.pageNo), false, false)
	p.emitLine(line{g: foot}, pageW/2-15, margin, 8)
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(p.page.Bytes())
	zw.Close()
	cid, pid := p.newID(), p.newID()
	p.obj(cid, "<< /Filter /FlateDecode /Length "+strconv.Itoa(z.Len())+" >>\nstream\n", z.Bytes(), "\nendstream")
	p.obj(pid, "<< /Type /Page /Parent "+ref(idPages)+" /MediaBox [0 0 "+strconv.Itoa(int(pageW))+" "+strconv.Itoa(int(pageH))+
		"] /Resources "+ref(idResources)+" /Contents "+ref(cid)+" >>", nil, "")
	p.pageIDs = append(p.pageIDs, pid)
	p.page.Reset()
}

func ref(id int) string { return strconv.Itoa(id) + " 0 R" }

// ---- document structure ----

func (p *Writer) writeTail() {
	// Fonts: the two base fonts, then each fallback font with its ToUnicode map.
	fontIDs := make([]int, 0, 2+len(p.fonts.fb))
	for _, bold := range []bool{false, true} {
		id := p.newID()
		name := "Helvetica"
		if bold {
			name = "Helvetica-Bold"
		}
		p.obj(id, "<< /Type /Font /Subtype /Type1 /BaseFont /"+name+" /Encoding /WinAnsiEncoding >>", nil, "")
		fontIDs = append(fontIDs, id)
	}
	for _, f := range p.fonts.fb {
		fontIDs = append(fontIDs, p.writeFallback(f))
	}
	var res strings.Builder
	res.WriteString("<< /Font <<")
	for i, id := range fontIDs {
		res.WriteString(" /" + fontName(i) + " " + ref(id))
	}
	res.WriteString(" >> /ProcSet [/PDF /Text] >>")
	p.obj(idResources, res.String(), nil, "")

	var kids strings.Builder
	for _, id := range p.pageIDs {
		kids.WriteString(ref(id) + " ")
	}
	p.obj(idPages, "<< /Type /Pages /Kids ["+strings.TrimSpace(kids.String())+"] /Count "+strconv.Itoa(len(p.pageIDs))+" >>", nil, "")
	p.obj(idCatalog, "<< /Type /Catalog /Pages "+ref(idPages)+" >>", nil, "")
	p.obj(idInfo, "<< /Title "+utf16Hex(p.o.Title)+" /Producer (activeDIQ) >>", nil, "")

	xref := p.cw.n
	var x strings.Builder
	x.WriteString("xref\n0 " + strconv.Itoa(p.nextID) + "\n0000000000 65535 f \n")
	for id := 1; id < p.nextID; id++ {
		x.WriteString(fmt.Sprintf("%010d 00000 n \n", p.offs[id]))
	}
	x.WriteString("trailer\n<< /Size " + strconv.Itoa(p.nextID) + " /Root " + ref(idCatalog) + " /Info " + ref(idInfo) + " >>\nstartxref\n" +
		strconv.FormatInt(xref, 10) + "\n%%EOF\n")
	p.write(x.String())
}

// writeFallback writes a simple font whose codes all draw a fixed fallback glyph and whose ToUnicode
// map carries the real code points.
func (p *Writer) writeFallback(f *fallbackFont) int {
	var widths, diffs strings.Builder
	for i, r := range f.runes {
		_ = i
		g := glyphFor(r)
		widths.WriteString(strconv.Itoa(int(g.width(f.bold))) + " ")
		diffs.WriteString("/" + g.name + " ")
	}
	var cm strings.Builder
	cm.WriteString("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n" +
		"/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n" +
		"/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n")
	for start := 0; start < len(f.runes); start += 100 {
		end := min(start+100, len(f.runes))
		cm.WriteString(strconv.Itoa(end-start) + " beginbfchar\n")
		for i := start; i < end; i++ {
			cm.WriteString(fmt.Sprintf("<%02X> <%s>\n", i+1, utf16HexDigits(f.runes[i])))
		}
		cm.WriteString("endbfchar\n")
	}
	cm.WriteString("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n")
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte(cm.String()))
	zw.Close()
	tuID := p.newID()
	p.obj(tuID, "<< /Filter /FlateDecode /Length "+strconv.Itoa(z.Len())+" >>\nstream\n", z.Bytes(), "\nendstream")
	base := "Helvetica"
	if f.bold {
		base = "Helvetica-Bold"
	}
	id := p.newID()
	p.obj(id, "<< /Type /Font /Subtype /Type1 /BaseFont /"+base+" /FirstChar 1 /LastChar "+strconv.Itoa(len(f.runes))+
		" /Widths ["+strings.TrimSpace(widths.String())+"] /Encoding << /Type /Encoding /BaseEncoding /WinAnsiEncoding /Differences [1 "+
		strings.TrimSpace(diffs.String())+"] >> /ToUnicode "+ref(tuID)+" >>", nil, "")
	return id
}

// obj writes "id 0 obj", the dictionary, optional stream bytes, "endobj", and records the offset.
func (p *Writer) obj(id int, head string, body []byte, tail string) {
	if p.err != nil {
		return
	}
	p.offs[id] = p.cw.n
	p.write(strconv.Itoa(id) + " 0 obj\n" + head)
	if body != nil {
		p.writeBytes(body)
	}
	p.write(tail + "\nendobj\n")
}

func (p *Writer) write(s string) { p.writeBytes([]byte(s)) }

func (p *Writer) writeBytes(b []byte) {
	if p.err != nil {
		return
	}
	if _, err := p.cw.Write(b); err != nil {
		p.err = err
	}
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n += int64(n)
	return n, err
}

// utf16Hex is a PDF text string as a UTF-16BE hex string with a byte order mark (rule 4).
func utf16Hex(s string) string {
	var b strings.Builder
	b.WriteString("<FEFF")
	for _, u := range utf16.Encode([]rune(s)) {
		b.WriteString(fmt.Sprintf("%04X", u))
	}
	b.WriteString(">")
	return b.String()
}

func utf16HexDigits(r rune) string {
	var b strings.Builder
	for _, u := range utf16.Encode([]rune{r}) {
		b.WriteString(fmt.Sprintf("%04X", u))
	}
	return b.String()
}

// ---- text: runes to glyphs ----

// glyph is one drawn character: the font resource it uses, its code in that font and its width in
// 1/1000 em. nl marks a hard line break; space marks a break opportunity.
type glyph struct {
	font  int
	code  byte
	w     float64
	nl    bool
	space bool
}

// fontName is the resource name of font index i: 0 regular, 1 bold, 2... fallback fonts.
func fontName(i int) string { return "F" + strconv.Itoa(i+1) }

// winAnsi is the code of every rune the standard fonts draw with WinAnsiEncoding.
var winAnsi = func() map[rune]byte {
	m := map[rune]byte{}
	for b := 0x20; b <= 0xFF; b++ {
		if b == 0x7F || b == 0x81 || b == 0x8D || b == 0x8F || b == 0x90 || b == 0x9D {
			continue
		}
		r := charmap.Windows1252.DecodeByte(byte(b))
		if isHidden(r) {
			continue
		}
		m[r] = byte(b)
	}
	return m
}()

// isHidden reports characters a PDF cannot show: Cc, Cf, line and paragraph separators (O3).
func isHidden(r rune) bool {
	return unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' '
}

type fallbackFont struct {
	bold  bool
	runes []rune
}

type fbEntry struct {
	font int // index into fonts.fb
	code byte
}

type fontRegistry struct {
	fb  []*fallbackFont
	idx [2]map[rune]fbEntry // per weight
	cur [2]int              // fallback font being filled, -1 none
	n   [2]int              // distinct fallback runes per weight
}

func (f *fontRegistry) init() {
	f.idx = [2]map[rune]fbEntry{{}, {}}
	f.cur = [2]int{-1, -1}
}

// fallback returns the font resource index and code that draw r, allocating a code if needed. Past
// MaxFallbackRunes a character becomes U+FFFD.
func (f *fontRegistry) fallback(r rune, bold bool) (font int, code byte, replaced bool) {
	w := 0
	if bold {
		w = 1
	}
	if e, ok := f.idx[w][r]; ok {
		return 2 + e.font, e.code, false
	}
	if f.n[w] >= MaxFallbackRunes && r != unicode.ReplacementChar {
		font, code, _ = f.fallback(unicode.ReplacementChar, bold)
		return font, code, true
	}
	if f.cur[w] < 0 || len(f.fb[f.cur[w]].runes) >= 255 {
		f.fb = append(f.fb, &fallbackFont{bold: bold})
		f.cur[w] = len(f.fb) - 1
	}
	ff := f.fb[f.cur[w]]
	ff.runes = append(ff.runes, r)
	e := fbEntry{font: f.cur[w], code: byte(len(ff.runes))}
	f.idx[w][r] = e
	f.n[w]++
	return 2 + e.font, e.code, false
}

type glyphShape struct {
	name string
	code byte // the WinAnsi code whose width it takes
}

func glyphFor(r rune) glyphShape {
	switch r {
	case '⟨':
		return glyphShape{"guilsinglleft", 0x8B}
	case '⟩':
		return glyphShape{"guilsinglright", 0x9B}
	}
	return glyphShape{"question", '?'}
}

func (g glyphShape) width(bold bool) uint16 {
	if bold {
		return helveticaBoldWidths[g.code]
	}
	return helveticaWidths[g.code]
}

// glyphs turns text into glyphs. Invalid UTF-8 becomes U+FFFD, \r\n a line break, other Cc, Cf and
// U+2028/9 the visible token ⟨U+XXXX⟩ (O3). With newlines false, \n is also tokenised. changed says a
// value was mapped.
func (p *Writer) glyphs(s string, bold, newlines bool) (out []glyph, changed bool) {
	s, bad := export.Sanitize(s)
	changed = bad
	w := &helveticaWidths
	if bold {
		w = &helveticaBoldWidths
	}
	add := func(r rune) {
		if c, ok := winAnsi[r]; ok {
			out = append(out, glyph{font: b2i(bold), code: c, w: float64(w[c]), space: r == ' '})
			return
		}
		font, code, rep := p.fonts.fallback(r, bold)
		if rep {
			changed = true
		}
		out = append(out, glyph{font: font, code: code, w: float64(glyphFor(r).width(bold))})
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case newlines && r == '\n':
			out = append(out, glyph{nl: true})
		case newlines && r == '\r' && i+1 < len(rs) && rs[i+1] == '\n':
			// CRLF is one line break; the LF case above takes it next.
		case isHidden(r):
			changed = true
			for _, t := range fmt.Sprintf("⟨U+%04X⟩", r) {
				add(t)
			}
		default:
			add(r)
		}
	}
	return out, changed
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
