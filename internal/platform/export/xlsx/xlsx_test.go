package xlsx

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/skenzeriq/activediq/internal/platform/export"
)

type parsedCell struct {
	typ, ref string
	style    string
	text     string // decoded text (inlineStr) or raw <v>
	hasF     bool
}

type workbook struct {
	files map[string]string
	cells []parsedCell
}

// open parses the archive with encoding/xml, an independent parser (FF-SP10).
func open(t *testing.T, data []byte) workbook {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	wb := workbook{files: map[string]string{}}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		wb.files[f.Name] = string(b)
		if strings.HasSuffix(f.Name, ".xml") || strings.HasSuffix(f.Name, ".rels") {
			d := xml.NewDecoder(bytes.NewReader(b))
			d.Strict = true
			for {
				if _, err := d.Token(); err == io.EOF {
					break
				} else if err != nil {
					t.Fatalf("%s not well-formed: %v", f.Name, err)
				}
			}
		}
	}
	d := xml.NewDecoder(strings.NewReader(wb.files["xl/worksheets/sheet1.xml"]))
	var cur *parsedCell
	var in string
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch e := tok.(type) {
		case xml.StartElement:
			in = e.Name.Local
			switch in {
			case "c":
				cur = &parsedCell{}
				for _, a := range e.Attr {
					switch a.Name.Local {
					case "t":
						cur.typ = a.Value
					case "r":
						cur.ref = a.Value
					case "s":
						cur.style = a.Value
					}
				}
			case "f":
				cur.hasF = true
			}
		case xml.CharData:
			if cur != nil && (in == "t" || in == "v") {
				cur.text += string(e)
			}
		case xml.EndElement:
			if e.Name.Local == "c" {
				wb.cells = append(wb.cells, *cur)
				cur = nil
			}
			in = ""
		}
	}
	return wb
}

var xesc = regexp.MustCompile(`_x([0-9A-Fa-f]{4})_`)

// excelText decodes ST_Xstring the way Excel displays it.
func excelText(s string) string {
	return xesc.ReplaceAllStringFunc(s, func(m string) string {
		var r rune
		for _, c := range m[2:6] {
			r = r*16 + rune(strings.IndexRune("0123456789abcdef", rune(strings.ToLower(string(c))[0])))
		}
		return string(r)
	})
}

func build(t *testing.T, o Options, hdr []export.Column, rows ...[]export.Cell) (workbook, export.RenderReport, []byte) {
	t.Helper()
	var b bytes.Buffer
	w, err := NewWriter(&b, o)
	if err != nil {
		t.Fatal(err)
	}
	if hdr != nil {
		if err := w.Header(hdr); err != nil {
			t.Fatal(err)
		}
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
	return open(t, b.Bytes()), rep, b.Bytes()
}

func one(t *testing.T, s string) (parsedCell, workbook, export.RenderReport) {
	wb, rep, _ := build(t, Options{}, nil, []export.Cell{export.Text(s)})
	if len(wb.cells) != 1 {
		t.Fatalf("cells = %d", len(wb.cells))
	}
	return wb.cells[0], wb, rep
}

func TestLeadCellsAreQuotePrefixedStrings(t *testing.T) {
	for _, tc := range []struct{ id, in string }{
		{"XL-01", "=1+1"},
		{"XL-02", `=HYPERLINK("http://example.invalid/","x")`},
		{"XL-03a", "＝1+1"}, {"XL-03b", "＠SUM(1,1)"},
		{"XL-04", "\t=1+1"},
		{"XL-19", "+1 555 0100"},
		{"lf", "\n+1"}, {"cr", "\r-1"}, {"zw", "​=1"}, {"minus", "−1"},
	} {
		c, wb, rep := one(t, tc.in)
		if c.typ != "inlineStr" || c.style != "1" || c.hasF {
			t.Errorf("%s: %+v", tc.id, c)
		}
		if excelText(c.text) != tc.in && !strings.ContainsAny(tc.in, "\r") {
			t.Errorf("%s: text %q != %q", tc.id, excelText(c.text), tc.in)
		}
		if rep.Neutralised != 1 {
			t.Errorf("%s: report %+v", tc.id, rep)
		}
		if strings.Contains(wb.files["xl/styles.xml"], `quotePrefix="1"`) == false {
			t.Error("no quotePrefix style")
		}
	}
}

func TestXL05EscapeSpoofing(t *testing.T) {
	c, wb, _ := one(t, "_x003D_1+1")
	if !strings.Contains(wb.files["xl/worksheets/sheet1.xml"], "<t>_x005F_x003D_1+1</t>") {
		t.Fatal(wb.files["xl/worksheets/sheet1.xml"])
	}
	if got := excelText(c.text); got != "_x003D_1+1" && got != "_x005F_x003D_1+1" {
		t.Fatal(got)
	}
	// What Excel displays: decode _x005F_ once -> "_x003D_1+1".
	if strings.Replace(c.text, "_x005F_", "_", 1) != "_x003D_1+1" {
		t.Fatal(c.text)
	}
	// Control-looking data without a closing underscore is untouched.
	c2, _, _ := one(t, "_x003D1")
	if c2.text != "_x003D1" {
		t.Fatal(c2.text)
	}
}

func TestXL06to08ControlsStayWellFormed(t *testing.T) {
	for in, want := range map[string]string{
		"a\x0Bb": "a_x000B_b", "a\x01b": "a_x0001_b", "a\rb": "a_x000D_b", "a￾b": "a_xFFFE_b", "a￿b": "a_xFFFF_b",
	} {
		c, _, _ := one(t, in)
		if c.text != want {
			t.Errorf("%q: got %q want %q", in, c.text, want)
		}
	}
}

func TestXL09XL10Injection(t *testing.T) {
	for _, in := range []string{"</t></is><f>1+1</f>", "&xxe;", `<!DOCTYPE x [<!ENTITY a "b">]>`} {
		c, wb, _ := one(t, in)
		if c.hasF || excelText(c.text) != in {
			t.Errorf("%q: %+v", in, c)
		}
		if strings.Contains(wb.files["xl/worksheets/sheet1.xml"], "<f") || strings.Contains(wb.files["xl/worksheets/sheet1.xml"], "<!DOCTYPE") {
			t.Errorf("%q: structure injected", in)
		}
	}
}

func TestXL11XL12Truncation(t *testing.T) {
	c, _, rep := one(t, strings.Repeat("a", 40000))
	if n := len(utf16.Encode([]rune(c.text))); n != 32767 || !strings.HasSuffix(c.text, "… [truncated: 40000 chars]") || rep.Truncated != 1 {
		t.Fatalf("units %d rep %+v", n, rep)
	}
	c, _, _ = one(t, strings.Repeat("\U0001F600", 20000))
	if n := len(utf16.Encode([]rune(c.text))); n > 32767 {
		t.Fatalf("units %d", n)
	}
}

func TestXL13SheetNames(t *testing.T) {
	for in, want := range map[string]string{
		"Q1/Q2:[draft]*?": "Q1_Q2__draft___", "History": "History_", "'x'": "_x_", "": "Sheet1",
		strings.Repeat("n", 40): strings.Repeat("n", 31), "a\x00b": "a_b", "50%": "50_",
	} {
		if got := ParseSheetName(in).String(); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	wb, _, _ := build(t, Options{Sheet: ParseSheetName("Q1/Q2")}, nil)
	if !strings.Contains(wb.files["xl/workbook.xml"], `name="Q1_Q2"`) {
		t.Fatal(wb.files["xl/workbook.xml"])
	}
}

func TestXL14RowCap(t *testing.T) {
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{MaxRows: 2})
	w.Row([]export.Cell{export.Int64(1)})
	w.Row([]export.Cell{export.Int64(2)})
	if err := w.Row([]export.Cell{export.Int64(3)}); !errors.Is(err, export.ErrRowCapExceeded) {
		t.Fatal(err)
	}
	if export.MaxDataRows != 1048575 {
		t.Fatal("cap constant")
	}
}

func TestXL15NonFinite(t *testing.T) {
	w, _ := NewWriter(io.Discard, Options{})
	for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if err := w.Row([]export.Cell{export.Float64(f)}); !errors.Is(err, export.ErrNonFiniteNumber) {
			t.Fatal(err)
		}
	}
}

// XL-16: static shape of every artefact.
func TestXL16WorkbookShape(t *testing.T) {
	_, _, raw := build(t, Options{Title: "=1+1"},
		[]export.Column{{Label: "=h"}, {Label: "b"}},
		[]export.Cell{export.Text(`=HYPERLINK("x")`), export.Int64(1)})
	zr, _ := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	for _, f := range zr.File {
		for _, bad := range []string{"externalLinks/", "vbaProject.bin", "connections.xml", "queryTables/", "customXml", "custom.xml"} {
			if strings.Contains(f.Name, bad) {
				t.Errorf("forbidden part %s", f.Name)
			}
		}
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if regexp.MustCompile(`<f[ >/]`).Match(b) {
			t.Errorf("%s contains a formula element", f.Name)
		}
		for _, bad := range []string{"<hyperlink", "<definedName", "macroEnabled", "<drawing", "<legacyDrawing", "<dataValidation"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s contains %s", f.Name, bad)
			}
		}
	}
	wb := open(t, raw)
	if !strings.Contains(wb.files["[Content_Types].xml"], "sheet.main+xml") {
		t.Error("content type")
	}
}

func TestXL17TitleEscaped(t *testing.T) {
	wb, _, _ := build(t, Options{Title: `=1+1 <b>&`}, nil)
	if !strings.Contains(wb.files["docProps/core.xml"], "<dc:title>=1+1 &lt;b&gt;&amp;</dc:title>") {
		t.Fatal(wb.files["docProps/core.xml"])
	}
}

func TestXL20XL21Typed(t *testing.T) {
	wb, _, _ := build(t, Options{}, nil, []export.Cell{export.Text("Smith, John"), export.Int64(-5), export.Bool(true), export.Empty(), export.Float64(2.5)})
	cs := wb.cells
	if len(cs) != 4 { // empty writes no cell
		t.Fatalf("%d cells", len(cs))
	}
	if cs[0].style != "" || cs[1].typ != "n" || cs[1].text != "-5" || cs[2].typ != "b" || cs[3].text != "2.5" {
		t.Fatalf("%+v", cs)
	}
	if cs[3].ref != "E1" {
		t.Fatalf("ref %s", cs[3].ref)
	}
}

func TestHeaderAndMismatch(t *testing.T) {
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{})
	w.Header([]export.Column{{Label: "=x"}, {Label: "y"}})
	if err := w.Header(nil); !errors.Is(err, export.ErrHeaderAfterRow) {
		t.Fatal(err)
	}
	if err := w.Row([]export.Cell{export.Int64(1)}); !errors.Is(err, export.ErrColumnMismatch) {
		t.Fatal(err)
	}
	w.Close()
	wb := open(t, b.Bytes())
	if wb.cells[0].style != "3" || wb.cells[1].style != "2" {
		t.Fatalf("%+v", wb.cells)
	}
}

func TestColName(t *testing.T) {
	for i, w := range map[int]string{0: "A", 25: "Z", 26: "AA", 701: "ZZ", 702: "AAA", 16383: "XFD"} {
		if colName(i) != w {
			t.Errorf("%d -> %s want %s", i, colName(i), w)
		}
	}
}

func FuzzAnyTextIsInertString(f *testing.F) {
	for _, s := range []string{"=1", "_x0041_", "\x00", "</t>", "‮=1", "a\r\nb", "\U0001F600", "&#x1;"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var b bytes.Buffer
		w, _ := NewWriter(&b, Options{})
		if err := w.Row([]export.Cell{export.Text(s)}); err != nil {
			t.Fatal(err)
		}
		w.Close()
		wb := open(t, b.Bytes())
		for _, c := range wb.cells {
			if c.hasF || c.typ != "inlineStr" {
				t.Fatalf("%q -> %+v", s, c)
			}
		}
	})
}
