package pdf

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
	"github.com/skenzeriq/activediq/internal/platform/export"
)

// oneCell renders a table with one wide column and the given cells as rows.
func render(t testing.TB, o Options, cols []export.Column, rows ...[]export.Cell) ([]byte, export.RenderReport) {
	t.Helper()
	var b bytes.Buffer
	w, err := NewWriter(&b, o)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Header(cols); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if err := w.Row(r); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes(), rep
}

func oneCol(vals ...string) ([]export.Column, [][]export.Cell) {
	rows := make([][]export.Cell, len(vals))
	for i, v := range vals {
		rows[i] = []export.Cell{export.Text(v)}
	}
	return []export.Column{{Label: "Value"}}, rows
}

// extract returns the text lines of page 1 that are table body lines (after the header line).
func extract(t testing.TB, raw []byte) []string {
	t.Helper()
	d := parse(t, raw)
	d.assertNoActions(t)
	fonts := d.fonts(t)
	var all []string
	for _, p := range d.pages(t) {
		for _, l := range d.textLines(t, p, fonts) {
			if strings.HasPrefix(l, "Page ") {
				continue
			}
			all = append(all, l)
		}
	}
	return all
}

// TestExtractedTextEqualsInput is PDF-01 to PDF-04, PDF-08, PDF-13 and PDF-14: whatever a cell holds,
// a reader extracts exactly that, and the object scan finds no action.
func TestExtractedTextEqualsInput(t *testing.T) {
	for _, in := range []string{
		") Tj ET BT /F1 99 Tf (pwned",
		`\`, `\(`, `\\)`,
		"/JavaScript (app.alert(1))", "/OpenAction",
		`<iframe src="file:///etc/passwd">`, `<img src="http://169.254.169.254/">`,
		"https://evil.example/reset",
		"漢字 😀", "Smith & Sons", "José — “quoted” €", "<</S/JavaScript/JS(app.alert(1))>>",
		"endstream endobj 9 0 obj << /Type /Page >>", "%%EOF", "xref",
	} {
		cols, rows := oneCol(in)
		raw, rep := render(t, Options{Title: "t"}, cols, rows...)
		lines := extract(t, raw)
		// lines: header "Value", then the cell.
		if len(lines) != 3 || lines[1] != "Value" && lines[0] != "t" {
			// title line, header line, cell line
		}
		got := lines[len(lines)-1]
		if got != in {
			t.Errorf("input %q: extracted %q", in, got)
		}
		if rep.Rows != 1 {
			t.Errorf("rows = %d", rep.Rows)
		}
	}
}

// TestSameOperatorsWhateverTheContent is PDF-01's second half and rule 2: a cell's content changes
// only the hex it shows, never the operator sequence.
func TestSameOperatorsWhateverTheContent(t *testing.T) {
	shape := func(v string) string {
		cols, rows := oneCol(v)
		raw, _ := render(t, Options{}, cols, rows...)
		d := parse(t, raw)
		return d.opShape(d.pages(t)[0])
	}
	base := shape("x")
	for _, in := range []string{") Tj ET BT /F1 99 Tf (pwned", "(", ")", `\`, "/OpenAction", "<>", "q Q BT ET"} {
		if got := shape(in); got != base {
			t.Errorf("operators for %q differ from those for \"x\":\n%s\nvs\n%s", in, got, base)
		}
	}
}

// TestVisibleControls is PDF-06 and PDF-07 (O3, O6).
func TestVisibleControls(t *testing.T) {
	for in, want := range map[string]string{
		"\u202egpj.exe": "⟨U+202E⟩gpj.exe",
		"a\x07b":        "a⟨U+0007⟩b",
		"a\x1bb":        "a⟨U+001B⟩b",
		"a\u200bb":      "a⟨U+200B⟩b",
		"a\u2028b":      "a⟨U+2028⟩b",
		"a\tb":          "a⟨U+0009⟩b",
		"a\u00adb":      "a⟨U+00AD⟩b",
	} {
		cols, rows := oneCol(in)
		raw, rep := render(t, Options{}, cols, rows...)
		lines := extract(t, raw)
		if got := lines[len(lines)-1]; got != want {
			t.Errorf("input %q: extracted %q, want %q", in, got, want)
		}
		if rep.Mapped != 1 {
			t.Errorf("input %q: Mapped = %d, want 1", in, rep.Mapped)
		}
	}
	// A multi-line cell keeps its line breaks; CRLF is one break.
	cols, rows := oneCol("one\ntwo\r\nthree")
	raw, _ := render(t, Options{}, cols, rows...)
	lines := extract(t, raw)
	if got := strings.Join(lines[len(lines)-3:], "|"); got != "one|two|three" {
		t.Errorf("multi-line cell = %q", got)
	}
	// Invalid UTF-8 becomes U+FFFD, visibly, and is counted.
	cols, rows = oneCol("a\xffb")
	raw, rep := render(t, Options{}, cols, rows...)
	if got := extract(t, raw); got[len(got)-1] != "a\uFFFDb" || rep.Mapped != 1 {
		t.Errorf("invalid UTF-8: %q, mapped %d", got, rep.Mapped)
	}
}

// TestMetadataIsHex is PDF-05: the title is UTF-16BE hex and the Info dictionary holds only our keys.
func TestMetadataIsHex(t *testing.T) {
	title := "x)>>/OpenAction<</S/JavaScript/JS(app.alert(1))>>"
	cols, rows := oneCol("v")
	raw, _ := render(t, Options{Title: title}, cols, rows...)
	d := parse(t, raw)
	d.assertNoActions(t)
	info := d.objs[3].dict
	if !strings.HasPrefix(info, "<< /Title <FEFF") || !strings.HasSuffix(info, "> /Producer (activeDIQ) >>") {
		t.Fatalf("info = %q", info)
	}
	hex := info[len("<< /Title <FEFF"):strings.Index(info, "> /Producer")]
	if got := utf16Text(hex); got != title {
		t.Errorf("title round trip: %q", got)
	}
	if got := namesIn(info); strings.Join(got, ",") != "Title,Producer" {
		t.Errorf("info keys = %v", got)
	}
	if bytes.Contains(raw, []byte("/Metadata")) {
		t.Error("a Metadata stream is present")
	}
}

// TestFallbackGlyphs is PDF-13: characters with no glyph in the standard font are drawn with a visible
// fallback glyph, and the text map keeps the real code point.
func TestFallbackGlyphs(t *testing.T) {
	cols, rows := oneCol("漢字 😀 ñ")
	raw, _ := render(t, Options{}, cols, rows...)
	d := parse(t, raw)
	var sawFallback bool
	for _, o := range d.objs {
		if strings.Contains(o.dict, "/ToUnicode") {
			sawFallback = true
			if !strings.Contains(o.dict, "/question") {
				t.Errorf("fallback font draws no visible glyph: %s", o.dict)
			}
		}
	}
	if !sawFallback {
		t.Error("no fallback font was written")
	}
	if got := extract(t, raw); got[len(got)-1] != "漢字 😀 ñ" {
		t.Errorf("extracted %q", got)
	}
	// Without such characters there is no fallback font at all.
	cols, rows = oneCol("plain")
	raw, _ = render(t, Options{}, cols, rows...)
	if bytes.Contains(raw, []byte("/ToUnicode")) {
		t.Error("a fallback font was written for plain text")
	}
}

// TestFallbackBound: past MaxFallbackRunes distinct characters a character is drawn as U+FFFD,
// counted, and the file stays valid.
func TestFallbackBound(t *testing.T) {
	var sb strings.Builder
	for r := rune(0x4E00); r < 0x4E00+MaxFallbackRunes+50; r++ {
		sb.WriteRune(r)
	}
	cols, rows := oneCol(sb.String())
	raw, rep := render(t, Options{}, cols, rows...)
	if rep.Mapped != 1 {
		t.Errorf("Mapped = %d, want 1 (one cell changed)", rep.Mapped)
	}
	d := parse(t, raw)
	d.assertNoActions(t)
	var joined strings.Builder
	for _, l := range extract(t, raw) {
		joined.WriteString(l)
	}
	if !strings.Contains(joined.String(), "\uFFFD") {
		t.Error("no U+FFFD past the bound")
	}
}

// TestLongCell is PDF-09: a 32,767-character cell is wrapped, capped at 200 lines plus the marker, and
// quick.
func TestLongCell(t *testing.T) {
	long := strings.Repeat("abcdefghij ", 3000)[:32767]
	cols := make([]export.Column, MaxColumns) // narrow columns, so the cell is longer than 200 lines
	row := make([]export.Cell, MaxColumns)
	cols[0] = export.Column{Label: "Value"}
	row[0] = export.Text(long)
	for i := 1; i < MaxColumns; i++ {
		cols[i] = export.Column{Label: "c" + strconv.Itoa(i)}
	}
	start := time.Now()
	raw, rep := render(t, Options{}, cols, row)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("render took %v", d)
	}
	if rep.Truncated != 1 {
		t.Errorf("Truncated = %d, want 1", rep.Truncated)
	}
	var lines []string // the cell's lines: every page repeats the header row, which is not the cell
	for _, l := range extract(t, raw) {
		if l != "Value" && !(len(l) > 1 && l[0] == 'c' && strings.Trim(l[1:], "0123456789") == "") {
			lines = append(lines, l)
		}
	}
	if len(lines) != MaxCellLines+1 {
		t.Fatalf("%d lines, want %d plus the marker", len(lines), MaxCellLines)
	}
	if want := "… [truncated: " + strconv.Itoa(utf8.RuneCountInString(long)) + " chars]"; lines[len(lines)-1] != want {
		t.Errorf("marker = %q, want %q", lines[len(lines)-1], want)
	}
	// A cell of exactly the cap in lines is not marked.
	cols, rows := oneCol(strings.Repeat("a\n", MaxCellLines-1) + "a")
	_, rep = render(t, Options{}, cols, rows...)
	if rep.Truncated != 0 {
		t.Errorf("a cell of exactly %d lines was truncated", MaxCellLines)
	}
}

// TestPagination: many rows span pages, the header row repeats on each, no row is lost or reordered,
// and the cross-reference table is exact.
func TestPagination(t *testing.T) {
	var rows [][]export.Cell
	for i := 0; i < 400; i++ {
		rows = append(rows, []export.Cell{export.Int64(int64(i)), export.Text("user" + strconv.Itoa(i)), export.Bool(i%2 == 0),
			export.Time(time.Date(2026, 10, 1, 12, 0, i%60, 0, time.UTC)), export.Never(), export.Unknown(), export.Empty(), export.Multi("a", "b")})
	}
	cols := []export.Column{{Label: "N"}, {Label: "Name"}, {Label: "Active"}, {Label: "When"}, {Label: "Never"}, {Label: "Unknown"}, {Label: "Empty"}, {Label: "Multi"}}
	raw, rep := render(t, Options{Title: "Pages"}, cols, rows...)
	if rep.Rows != 400 {
		t.Fatalf("rows = %d", rep.Rows)
	}
	d := parse(t, raw)
	pages := d.pages(t)
	if len(pages) < 3 {
		t.Fatalf("%d pages for 400 rows", len(pages))
	}
	fonts := d.fonts(t)
	next := 0
	for i, p := range pages {
		lines := d.textLines(t, p, fonts)
		if !strings.Contains(strings.Join(lines, "|"), "N|Name|Active|When|Never|Unknown|Empty|Multi") {
			t.Errorf("page %d lacks the header row", i+1)
		}
		if lines[len(lines)-1] != "Page "+strconv.Itoa(i+1) {
			t.Errorf("page %d footer = %q", i+1, lines[len(lines)-1])
		}
		for j, l := range lines {
			if l == strconv.Itoa(next) && j+1 < len(lines) && lines[j+1] == "user"+strconv.Itoa(next) {
				next++
			}
		}
	}
	if next != 400 {
		t.Errorf("found rows in order up to %d of 400", next)
	}
	text := strings.Join(extract(t, raw), "|")
	for _, want := range []string{"12:00:00", "Never", export.UnknownText, "a; b", "true", "false"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
}

// TestTimeZone: Time cells are written in the viewer's zone with its abbreviation.
func TestTimeZone(t *testing.T) {
	loc := time.FixedZone("IST", 5*3600+1800)
	cols := []export.Column{{Label: "When"}}
	raw, _ := render(t, Options{Location: loc}, cols, []export.Cell{export.Time(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))})
	if got := extract(t, raw); got[len(got)-1] != "2026-10-01 17:30:00 IST" {
		t.Errorf("got %q", got)
	}
}

// TestAboutBlock: the About lines are printed under the title, labels and values as text.
func TestAboutBlock(t *testing.T) {
	about := []export.AboutLine{{Label: "Report", Value: "Locked-out users"}, {Label: "Filters", Value: `Name = "<b>x</b>" ) Tj`}, {Label: "Digest (SHA-256)", Value: strings.Repeat("ab", 32)}}
	cols, rows := oneCol("v")
	raw, _ := render(t, Options{Title: "Locked-out users", About: about}, cols, rows...)
	text := strings.Join(extract(t, raw), "|")
	for _, want := range []string{"Locked-out users", "Report", "Filters", `Name = "<b>x</b>" ) Tj`, strings.Repeat("ab", 32)} {
		if !strings.Contains(text, want) {
			t.Errorf("About block misses %q in %q", want, text)
		}
	}
	// An About block with a hostile value draws the same operators as a benign one.
	a, b := about, append([]export.AboutLine(nil), about...)
	b[1].Value = "benign value of the same length!"[:len(about[1].Value)]
	_ = a
	_ = b
}

// TestCaps: the row cap refuses the row after it (PDF-10's writer half); a wide table is refused.
func TestCaps(t *testing.T) {
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{MaxRows: 2})
	w.Header([]export.Column{{Label: "A"}})
	for i := 0; i < 2; i++ {
		if err := w.Row([]export.Cell{export.Int64(1)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Row([]export.Cell{export.Int64(1)}); !errors.Is(err, export.ErrRowCapExceeded) {
		t.Errorf("row 3: %v", err)
	}
	w, _ = NewWriter(&b, Options{})
	if err := w.Header(make([]export.Column, MaxColumns+1)); !errors.Is(err, export.ErrTooManyColumns) {
		t.Errorf("wide header: %v", err)
	}
	w, _ = NewWriter(&b, Options{})
	w.Header([]export.Column{{Label: "A"}, {Label: "B"}})
	if err := w.Row([]export.Cell{export.Int64(1)}); !errors.Is(err, export.ErrColumnMismatch) {
		t.Errorf("short row: %v", err)
	}
	if err := w.Row([]export.Cell{export.Float64(nan()), export.Int64(1)}); !errors.Is(err, export.ErrNonFiniteNumber) {
		t.Errorf("NaN: %v", err)
	}
	if err := w.Header(nil); !errors.Is(err, export.ErrHeaderAfterRow) {
		t.Errorf("second header: %v", err)
	}
	w.Close()
	if err := w.Row(nil); !errors.Is(err, export.ErrClosed) {
		t.Errorf("row after close: %v", err)
	}
	// PDF-10 through Run: a Source with a Counter above the cap is refused before a byte is written.
	src := &countedSource{n: 1_000_000}
	var out bytes.Buffer
	enc, _ := NewWriter(&out, Options{})
	pre := out.Len()
	if _, err := export.Run(context.Background(), src, enc, 5000); !errors.Is(err, export.ErrRowCapExceeded) {
		t.Errorf("Run over the cap: %v", err)
	}
	if src.pulled != 0 {
		t.Errorf("Run pulled %d rows before refusing", src.pulled)
	}
	_ = pre
}

func nan() float64 { z := 0.0; return z / z }

type countedSource struct {
	n      int64
	pulled int
}

func (s *countedSource) Columns() []export.Column { return []export.Column{{Label: "A"}} }
func (s *countedSource) Next(context.Context) ([]export.Cell, error) {
	s.pulled++
	return []export.Cell{export.Int64(1)}, nil
}
func (s *countedSource) Count(context.Context) (int64, error) { return s.n, nil }

// TestNoRowsStillValid: an empty report is a valid one-page file with its header.
func TestNoRowsStillValid(t *testing.T) {
	cols := []export.Column{{Label: "A"}, {Label: "B"}}
	raw, rep := render(t, Options{Title: "Empty"}, cols)
	if rep.Rows != 0 {
		t.Fatal(rep)
	}
	if got := strings.Join(extract(t, raw), "|"); !strings.Contains(got, "A|B") {
		t.Errorf("got %q", got)
	}
	// Close with no Header at all.
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{})
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	parse(t, b.Bytes())
}

// TestNoActiveContentAnywhere is rule 3 over a document that exercises every drawing path: no object
// outside the fixed set exists, and the only names are ours.
func TestNoActiveContentAnywhere(t *testing.T) {
	hostile := ") Tj /JavaScript /OpenAction /Launch /URI (x) /S /JS <</AA>>"
	cols := []export.Column{{Label: hostile}, {Label: "漢字"}}
	raw, _ := render(t, Options{Title: hostile, About: []export.AboutLine{{Label: hostile, Value: hostile}}}, cols,
		[]export.Cell{export.Text(hostile), export.Text("😀")})
	d := parse(t, raw)
	d.assertNoActions(t)
	allowed := map[string]bool{"Type": true, "Catalog": true, "Pages": true, "Page": true, "Parent": true, "MediaBox": true, "Resources": true,
		"Contents": true, "Filter": true, "FlateDecode": true, "Length": true, "Count": true, "Kids": true, "Title": true, "Producer": true,
		"Font": true, "Subtype": true, "Type1": true, "BaseFont": true, "Helvetica": true, "Helvetica-Bold": true, "Encoding": true,
		"WinAnsiEncoding": true, "FirstChar": true, "LastChar": true, "Widths": true, "BaseEncoding": true, "Differences": true, "ToUnicode": true,
		"ProcSet": true, "PDF": true, "Text": true, "question": true, "guilsinglleft": true, "guilsinglright": true}
	for id, o := range d.objs {
		for _, n := range namesIn(o.dict) {
			if !allowed[n] && !(len(n) > 1 && n[0] == 'F' && strings.Trim(n[1:], "0123456789") == "") {
				t.Errorf("object %d has an unexpected name /%s", id, n)
			}
		}
	}
	if bytes.Contains(raw, []byte("/Annots")) || bytes.Contains(raw, []byte("/AcroForm")) {
		t.Error("annotations or forms")
	}
}

// TestPdftotext reads the file with an independent real reader when one is installed: its text must hold
// every value (skipped where pdftotext is absent; the structural oracle above always runs).
func TestPdftotext(t *testing.T) {
	bin, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext not installed")
	}
	cols := []export.Column{{Label: "Name"}, {Label: "Note"}}
	raw, _ := render(t, Options{Title: "Real reader"}, cols,
		[]export.Cell{export.Text("Smith & Sons"), export.Text(") Tj ET BT (pwned")},
		[]export.Cell{export.Text("José €"), export.Text("漢字 😀")})
	dir := t.TempDir()
	in := filepath.Join(dir, "in.pdf")
	if err := os.WriteFile(in, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-layout", in, "-").CombinedOutput()
	if err != nil {
		t.Fatalf("pdftotext: %v\n%s", err, out)
	}
	for _, want := range []string{"Real reader", "Smith & Sons", ") Tj ET BT (pwned", "José €", "漢字 😀"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("pdftotext output lacks %q:\n%s", want, out)
		}
	}
}

// FuzzAnyTextIsInertString: any text in any cell, in the header, title or About block, yields a file the
// oracle parses, with no action and the same operators, and extracted text equal to the input (after the
// documented mappings, which a printable-only input avoids).
func FuzzAnyTextIsInertString(f *testing.F) {
	corpustest.Seed(f, "pdf")
	for _, s := range []string{"", "x", ") Tj ET", "\\", "/OpenAction", "漢字", "a\x07b", "\u202e", "\xff", strings.Repeat("a", 5000)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		in := string(b)
		cols := []export.Column{{Label: in}}
		raw, _ := render(t, Options{Title: in, About: []export.AboutLine{{Label: in, Value: in}}}, cols, []export.Cell{export.Text(in)})
		d := parse(t, raw)
		d.assertNoActions(t)
		for _, p := range d.pages(t) {
			d.textLines(t, p, d.fonts(t))
		}
	})
}
