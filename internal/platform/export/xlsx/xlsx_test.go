package xlsx

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json/v2"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
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
	wb, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return wb
}

func parse(data []byte) (workbook, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return workbook{}, err
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
					return workbook{}, fmt.Errorf("%s not well-formed: %v", f.Name, err)
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
	return wb, nil
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

// forbiddenInWorkbook lists what no produced workbook may hold (XL-16, rule 4, FF-SP10): the check is
// run on every workbook TestCorpus builds, so XL-02's "no <hyperlinks>" and XL-10's "no DTD" are enforced
// for each record, not only by the static XL-16 test.
func forbiddenInWorkbook(raw []byte) []string {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return []string{"not a zip: " + err.Error()}
	}
	var bad []string
	fRE := regexp.MustCompile(`<f[ >/]`)
	for _, f := range zr.File {
		for _, name := range []string{"externalLinks/", "vbaProject.bin", "connections.xml", "queryTables/", "customXml", "custom.xml"} {
			if strings.Contains(f.Name, name) {
				bad = append(bad, "part "+f.Name)
			}
		}
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if fRE.Match(b) {
			bad = append(bad, f.Name+": <f element")
		}
		for _, m := range []string{"<hyperlink", "<definedName", "macroEnabled", "<drawing", "<legacyDrawing", "<dataValidation", "<!DOCTYPE", "<!ENTITY", "<comment"} {
			if strings.Contains(string(b), m) {
				bad = append(bad, f.Name+": "+m)
			}
		}
		if f.Name == "[Content_Types].xml" && !strings.Contains(string(b), "sheet.main+xml") {
			bad = append(bad, "main content type is not sheet.main+xml")
		}
	}
	return bad
}

var (
	cellRE = regexp.MustCompile(`<c r="A1"([^>]*)>(.*?)</c>`)
	attrRE = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

// cellXML returns the A1 cell of a one-cell workbook in the corpus notation of §12.4: attributes
// t then s, no r, and the quotePrefix style spelled s="Q". It fails when the style index names an
// xf without quotePrefix="1".
func cellXML(wb workbook) (string, error) {
	sheet := wb.files["xl/worksheets/sheet1.xml"]
	m := cellRE.FindStringSubmatch(sheet)
	if m == nil {
		return "", fmt.Errorf("no A1 cell in %s", sheet)
	}
	var t, style string
	for _, a := range attrRE.FindAllStringSubmatch(m[1], -1) {
		switch a[1] {
		case "t":
			t = a[2]
		case "s":
			style = a[2]
		}
	}
	out := "<c"
	if t != "" {
		out += ` t="` + t + `"`
	}
	if style != "" {
		xfs := regexp.MustCompile(`(?s)<cellXfs[^>]*>(.*)</cellXfs>`).FindStringSubmatch(wb.files["xl/styles.xml"])
		if xfs == nil {
			return "", errors.New("no cellXfs")
		}
		list := regexp.MustCompile(`<xf [^>]*?(?:/>|>.*?</xf>)`).FindAllString(xfs[1], -1)
		var i int
		fmt.Sscanf(style, "%d", &i)
		if i >= len(list) || !strings.Contains(list[i], `quotePrefix="1"`) {
			return "", fmt.Errorf("style %s is not a quotePrefix xf", style)
		}
		out += ` s="Q"`
	}
	return out + ">" + m[2] + "</c>", nil
}

type countingSource struct{ n int64 }

func (countingSource) Columns() []export.Column                { return []export.Column{{Label: "a"}} }
func (c *countingSource) Count(context.Context) (int64, error) { return c.n, nil }
func (c *countingSource) Next(context.Context) ([]export.Cell, error) {
	return nil, errors.New("Next called: the cap check must come first")
}

func errCode(err error) (corpus.Result, bool) {
	switch {
	case errors.Is(err, export.ErrRowCapExceeded):
		return corpustest.Err("RowCapExceeded"), true
	case errors.Is(err, export.ErrNonFiniteNumber):
		return corpustest.Err("NonFiniteNumber"), true
	}
	return corpus.Result{}, false
}

// buildOne writes a one-cell workbook and opens it with the independent parser. It fails (so the
// record fails) when the workbook holds anything XL-16 forbids.
func buildOne(o Options, c export.Cell) (workbook, export.RenderReport, error) {
	var b bytes.Buffer
	w, err := NewWriter(&b, o)
	if err != nil {
		return workbook{}, export.RenderReport{}, err
	}
	if err := w.Row([]export.Cell{c}); err != nil {
		return workbook{}, export.RenderReport{}, err
	}
	rep, err := w.Close()
	if err != nil {
		return workbook{}, rep, err
	}
	if bad := forbiddenInWorkbook(b.Bytes()); len(bad) > 0 {
		return workbook{}, rep, fmt.Errorf("XL-16: %v", bad)
	}
	wb, err := parse(b.Bytes())
	return wb, rep, err
}

// TestCorpus runs XL-01 to XL-21 (testdata/safe-primitives/xlsx.jsonl, safe-primitives §12.4,
// FF-SP4): 27 records, 24 hostile; XL-16 is static (FF-SP10) and XL-18 is a lab record (FF-SP11).
func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/xlsx", "xlsx", func(r corpus.Record) (corpus.Result, error) {
		switch r.Call {
		case "Cell":
			var c export.Cell
			switch {
			case r.Args["float64"] != nil:
				in, err := r.Arg("float64")
				if err != nil {
					return corpus.Result{}, err
				}
				switch in.Text() {
				case "NaN":
					c = export.Float64(math.NaN())
				case "+Inf":
					c = export.Float64(math.Inf(1))
				case "-Inf":
					c = export.Float64(math.Inf(-1))
				default:
					return corpus.Result{}, fmt.Errorf("unknown float %q", in.Text())
				}
			case r.Args["int64"] != nil:
				var n int64
				if err := json.Unmarshal(r.Args["int64"], &n); err != nil {
					return corpus.Result{}, err
				}
				c = export.Int64(n)
			default:
				v, err := r.Arg("value")
				if err != nil {
					return corpus.Result{}, err
				}
				c = export.Text(v.Text())
			}
			wb, _, err := buildOne(Options{}, c)
			if res, ok := errCode(err); ok {
				return res, nil
			} else if err != nil {
				return corpus.Result{}, err
			}
			x, err := cellXML(wb)
			return corpustest.Render(x), err
		case "CellShape":
			v, err := r.Arg("value")
			if err != nil {
				return corpus.Result{}, err
			}
			var n int
			if err := json.Unmarshal(r.Args["repeat"], &n); err != nil {
				return corpus.Result{}, err
			}
			wb, rep, err := buildOne(Options{}, export.Text(strings.Repeat(v.Text(), n)))
			if err != nil {
				return corpus.Result{}, err
			}
			if len(wb.cells) != 1 {
				return corpus.Result{}, fmt.Errorf("%d cells", len(wb.cells))
			}
			text := excelText(wb.cells[0].text)
			suffix := ""
			if i := strings.LastIndex(text, "\u2026"); i >= 0 {
				suffix = text[i:]
			}
			return corpustest.Value(map[string]any{"units": len(utf16.Encode([]rune(text))), "suffix": suffix, "truncated": rep.Truncated, "wellFormed": utf8.ValidString(text) && !strings.ContainsRune(text, utf8.RuneError)})
		case "ParseSheetName":
			n, err := r.Arg("name")
			if err != nil {
				return corpus.Result{}, err
			}
			return corpustest.Render(ParseSheetName(n.Text()).String()), nil
		case "Export":
			var n int64
			if err := json.Unmarshal(r.Args["rows"], &n); err != nil {
				return corpus.Result{}, err
			}
			w, err := NewWriter(io.Discard, Options{})
			if err != nil {
				return corpus.Result{}, err
			}
			_, err = export.Run(context.Background(), &countingSource{n: n}, w, 0)
			if res, ok := errCode(err); ok {
				return res, nil
			}
			return corpus.Result{}, fmt.Errorf("export of %d rows returned %v", n, err)
		case "Title":
			v, err := r.Arg("title")
			if err != nil {
				return corpus.Result{}, err
			}
			wb, _, err := buildOne(Options{Title: v.Text()}, export.Empty())
			if err != nil {
				return corpus.Result{}, err
			}
			core := wb.files["docProps/core.xml"]
			m := regexp.MustCompile(`<dc:title>.*?</dc:title>`).FindString(core)
			if _, ok := wb.files["docProps/custom.xml"]; ok {
				return corpus.Result{}, errors.New("custom document properties present")
			}
			return corpustest.Render(m), nil
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

// FuzzAnyTextIsInertString is the FF-SP5 target for xlsx (independentParse): whatever the text, the
// workbook is well-formed to encoding/xml (an independent parser), every text cell is an inline
// string, no cell is a formula, and XL-16 holds.
func FuzzAnyTextIsInertString(f *testing.F) {
	corpustest.Seed(f, "xlsx")
	f.Fuzz(func(t *testing.T, in []byte) {
		s := string(in)
		var b bytes.Buffer
		w, _ := NewWriter(&b, Options{})
		if err := w.Row([]export.Cell{export.Text(s)}); err != nil {
			t.Fatal(err)
		}
		w.Close()
		if bad := forbiddenInWorkbook(b.Bytes()); len(bad) > 0 {
			t.Fatalf("%q -> %v", s, bad)
		}
		wb := open(t, b.Bytes())
		for _, c := range wb.cells {
			if c.hasF || c.typ != "inlineStr" {
				t.Fatalf("%q -> %+v", s, c)
			}
		}
	})
}
