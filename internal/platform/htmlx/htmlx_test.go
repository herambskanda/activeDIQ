package htmlx

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/httpx"
)

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

// facts is what the independent parser (golang.org/x/net/html, a different implementation from the
// template engine that wrote the file) finds in a document: the FF-SP10 oracle for HTML.
type facts struct {
	cspFirst     bool
	cspOK        bool // the policy is exactly the one rule 4 prescribes, with the hash of the style text
	scripts      int
	externalURLs int
	handlers     int
	images       int
	otherActive  []string
	rows         [][]string // text of every cell of every row of the table
	bdiWrapped   bool       // every non-empty cell holds exactly one <bdi> child and nothing else
	about        [][2]string
	title        string
	h1           string
}

func inspect(t testing.TB, raw []byte) facts {
	t.Helper()
	doc, err := html.Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	f := facts{bdiWrapped: true}
	var styleText string
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script":
				f.scripts++
			case "img", "picture", "source", "video", "audio", "svg", "canvas":
				f.images++
			case "link", "iframe", "frame", "object", "embed", "base", "form", "input", "button", "a", "area":
				f.otherActive = append(f.otherActive, n.Data)
			case "style":
				styleText = n.FirstChild.Data
			case "title":
				if n.FirstChild != nil {
					f.title = n.FirstChild.Data
				}
			case "h1":
				f.h1 = textOf(n)
			case "tr":
				if n.Parent.Data == "tbody" {
					var row []string
					for c := n.FirstChild; c != nil; c = c.NextSibling {
						row = append(row, textOf(c))
						if c.FirstChild != nil && (c.FirstChild.Data != "bdi" || c.FirstChild.NextSibling != nil) {
							f.bdiWrapped = false
						}
					}
					f.rows = append(f.rows, row)
				}
			case "dl":
				var k string
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					switch c.Data {
					case "dt":
						k = textOf(c)
					case "dd":
						f.about = append(f.about, [2]string{k, textOf(c)})
					}
				}
			}
			for _, a := range n.Attr {
				switch {
				case strings.HasPrefix(strings.ToLower(a.Key), "on"):
					f.handlers++
				case a.Key == "href" || a.Key == "src" || a.Key == "srcset" || a.Key == "action" || a.Key == "formaction" || a.Key == "style" || a.Key == "background" || a.Key == "poster" || a.Key == "data":
					f.externalURLs++
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	// The first element of <head> is the CSP meta.
	var head *html.Node
	var find func(n *html.Node)
	find = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "head" && head == nil {
			head = n
		}
		for c := n.FirstChild; c != nil && head == nil; c = c.NextSibling {
			find(c)
		}
	}
	find(doc)
	for c := head.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}
		if c.Data == "meta" {
			var he, content string
			for _, a := range c.Attr {
				switch a.Key {
				case "http-equiv":
					he = a.Val
				case "content":
					content = a.Val
				}
			}
			if strings.EqualFold(he, "Content-Security-Policy") {
				f.cspFirst = true
				sum := sha256.Sum256([]byte(styleText))
				want := "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; img-src data:"
				f.cspOK = content == want
			}
		}
		break
	}
	// No remote resource or import in the style block.
	for _, bad := range []string{"url(", "@import", "expression(", "javascript:", "behavior:"} {
		if strings.Contains(strings.ToLower(styleText), bad) {
			f.otherActive = append(f.otherActive, "style:"+bad)
		}
	}
	return f
}

func textOf(n *html.Node) string {
	var b strings.Builder
	var rec func(n *html.Node)
	rec = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			rec(c)
		}
	}
	rec(n)
	return b.String()
}

func oneCol(vals ...string) ([]export.Column, [][]export.Cell) {
	rows := make([][]export.Cell, len(vals))
	for i, v := range vals {
		rows[i] = []export.Cell{export.Text(v)}
	}
	return []export.Column{{Label: "Value"}}, rows
}

// TestHostileCorpus is FF-SP10 for HTML over a hostile set: whatever the value, the document keeps the
// CSP meta first with the exact policy, has no script, handler, link or external URL, and the cell
// holds the value as text.
func TestHostileCorpus(t *testing.T) {
	for _, in := range []string{
		"<script>alert(1)</script>", `<img src="https://evil.example/p.png">`, `" onmouseover="alert(1)`, "javascript:alert(1)",
		"</td></tr></table><img src=x onerror=alert(1)>", "</style><script>alert(1)</script>", "<!--", "-->", "<![CDATA[x]]>",
		"<iframe src=//evil.example>", "<svg onload=alert(1)>", "{{.X}}", "${7*7}", "<base href=//evil.example>",
		"<meta http-equiv=refresh content='0;url=//evil.example'>", "=HYPERLINK(\"http://evil.example\")", "‮⁦<bdi>",
		"</bdi><script>x</script>", "&lt;script&gt;", "&#60;script&#62;", "\x00<script>", "<style>@import 'https://evil.example/x.css'</style>",
	} {
		cols := []export.Column{{Label: in}}
		raw, _ := render(t, Options{Title: in, About: []export.AboutLine{{Label: in, Value: in}}}, cols, []export.Cell{export.Text(in)})
		f := inspect(t, raw)
		if !f.cspFirst || !f.cspOK {
			t.Errorf("%q: CSP meta first=%v exact=%v", in, f.cspFirst, f.cspOK)
		}
		if f.scripts != 0 || f.handlers != 0 || f.externalURLs != 0 || f.images != 0 || len(f.otherActive) != 0 {
			t.Errorf("%q: active content: scripts=%d handlers=%d urls=%d images=%d other=%v", in, f.scripts, f.handlers, f.externalURLs, f.images, f.otherActive)
		}
		if len(f.rows) != 1 || len(f.rows[0]) != 1 || !f.bdiWrapped {
			t.Errorf("%q: table structure changed: %v (bdi %v)", in, f.rows, f.bdiWrapped)
			continue
		}
		// The oracle's text of the cell equals the value, after the documented mapping of control characters.
		want := strings.NewReplacer("\x00", "⟨U+0000⟩").Replace(in)
		if got := f.rows[0][0]; got != want {
			t.Errorf("%q: cell text %q, want %q", in, got, want)
		}
		if len(f.about) != 1 || f.about[0][0] != want || f.about[0][1] != want {
			t.Errorf("%q: About block %v", in, f.about)
		}
		if f.h1 != strings.TrimSpace(want) && f.h1 != want {
			// the title is sanitised by the same rule
			if f.h1 != strings.NewReplacer("\x00", "�").Replace(in) {
				t.Errorf("%q: heading %q", in, f.h1)
			}
		}
	}
}

// TestStylePinned: the hash the download's CSP header pins (StyleSHA256) is the hash of the <style> text
// of every document, and the same one the meta carries.
func TestStylePinned(t *testing.T) {
	cols, rows := oneCol("v")
	raw, _ := render(t, Options{Title: "t"}, cols, rows...)
	s := string(raw)
	i, j := strings.Index(s, "<style>"), strings.Index(s, "</style>")
	if got := sha256.Sum256([]byte(s[i+len("<style>") : j])); got != StyleSHA256() {
		t.Errorf("style hash %x, StyleSHA256 %x", got, StyleSHA256())
	}
	if strings.Count(s, "<style") != 1 {
		t.Error("more than one style block")
	}
	if !strings.HasPrefix(s[strings.Index(s, "<head>")+len("<head>"):], "\n<meta http-equiv=\"Content-Security-Policy\"") {
		t.Error("the CSP meta is not the first head element in the raw bytes")
	}
	sum := StyleSHA256()
	if !strings.Contains(s, "sha256-"+strings.NewReplacer("+", "&#43;").Replace(base64.StdEncoding.EncodeToString(sum[:]))) {
		t.Error("the meta does not carry the style hash")
	}
}

// TestStructureAndTypes: rows and columns equal the model; types are classed; times show their zone.
func TestStructureAndTypes(t *testing.T) {
	loc := time.FixedZone("IST", 5*3600+1800)
	var rows [][]export.Cell
	for i := 0; i < 50; i++ {
		rows = append(rows, []export.Cell{export.Int64(int64(i)), export.Text("user" + strconv.Itoa(i)), export.Bool(i%2 == 0),
			export.Time(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)), export.Never(), export.Unknown(), export.Empty(), export.Multi("a", "b"), export.Float64(1.5)})
	}
	cols := []export.Column{{Label: "N"}, {Label: "Name"}, {Label: "Active"}, {Label: "When"}, {Label: "Never"}, {Label: "Unknown"}, {Label: "Empty"}, {Label: "Multi"}, {Label: "F"}}
	about := []export.AboutLine{{Label: "Report", Value: "R"}, {Label: "Digest (SHA-256)", Value: strings.Repeat("ab", 32)}}
	raw, rep := render(t, Options{Title: "Users", About: about, Location: loc}, cols, rows...)
	f := inspect(t, raw)
	if rep.Rows != 50 || len(f.rows) != 50 {
		t.Fatalf("rows: report %d, parsed %d", rep.Rows, len(f.rows))
	}
	for i, r := range f.rows {
		want := []string{strconv.Itoa(i), "user" + strconv.Itoa(i), strconv.FormatBool(i%2 == 0), "2026-10-01 17:30:00 IST", "Never", export.UnknownText, "", "a; b", "1.5"}
		if fmt.Sprint(r) != fmt.Sprint(want) {
			t.Fatalf("row %d = %q, want %q", i, r, want)
		}
	}
	if fmt.Sprint(f.about) != fmt.Sprint([][2]string{{"Report", "R"}, {"Digest (SHA-256)", strings.Repeat("ab", 32)}}) {
		t.Errorf("about = %v", f.about)
	}
	if f.title != "Users" || f.h1 != "Users" {
		t.Errorf("title %q, h1 %q", f.title, f.h1)
	}
	if !strings.Contains(string(raw), `<td class="n">`) || !strings.Contains(string(raw), `<td class="e"></td>`) {
		t.Error("number and empty classes missing")
	}
}

// TestRenderReport: mapped, truncated and neutralised cells are counted (O8).
func TestRenderReport(t *testing.T) {
	cols := []export.Column{{Label: "A"}}
	_, rep := render(t, Options{}, cols,
		[]export.Cell{export.Text("=1+1")}, []export.Cell{export.Text("a\x07b")}, []export.Cell{export.Text("a\xffb")},
		[]export.Cell{export.Text(strings.Repeat("x", export.MaxCellUnits+10))}, []export.Cell{export.Text("plain")})
	if rep.Rows != 5 || rep.Neutralised != 1 || rep.Mapped != 2 || rep.Truncated != 1 {
		t.Errorf("report = %+v", rep)
	}
}

func TestCRLFAndNewlines(t *testing.T) {
	cols, rows := oneCol("one\r\ntwo\nthree\rfour\tfive")
	raw, _ := render(t, Options{}, cols, rows...)
	if got := inspect(t, raw).rows[0][0]; got != "one\ntwo\nthree⟨U+000D⟩four\tfive" {
		t.Errorf("cell = %q", got)
	}
}

func TestCapsAndErrors(t *testing.T) {
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{MaxRows: 1})
	w.Header([]export.Column{{Label: "A"}})
	if err := w.Row([]export.Cell{export.Int64(1)}); err != nil {
		t.Fatal(err)
	}
	if err := w.Row([]export.Cell{export.Int64(1)}); !errors.Is(err, export.ErrRowCapExceeded) {
		t.Errorf("row 2: %v", err)
	}
	if err := w.Row([]export.Cell{export.Int64(1), export.Int64(2)}); !errors.Is(err, export.ErrRowCapExceeded) && !errors.Is(err, export.ErrColumnMismatch) {
		t.Errorf("wide row: %v", err)
	}
	w, _ = NewWriter(&b, Options{})
	w.Header([]export.Column{{Label: "A"}})
	if err := w.Row([]export.Cell{export.Float64(nan())}); !errors.Is(err, export.ErrNonFiniteNumber) {
		t.Errorf("NaN: %v", err)
	}
	if err := w.Header(nil); !errors.Is(err, export.ErrHeaderAfterRow) {
		t.Errorf("second header: %v", err)
	}
	w.Close()
	if err := w.Row(nil); !errors.Is(err, export.ErrClosed) {
		t.Errorf("after close: %v", err)
	}
	if _, err := NewWriter(&b, Options{About: make([]export.AboutLine, export.MaxAboutLines+1)}); err == nil {
		t.Error("an oversized About block was accepted")
	}
	// An empty report is still a complete document.
	raw, rep := render(t, Options{Title: "Empty"}, []export.Column{{Label: "A"}})
	if f := inspect(t, raw); len(f.rows) != 0 || !f.cspOK || rep.Rows != 0 || !strings.HasSuffix(string(raw), "</html>\n") {
		t.Errorf("empty document: %+v", f)
	}
	b.Reset()
	w, _ = NewWriter(&b, Options{})
	if _, err := w.Close(); err != nil || !strings.Contains(b.String(), "Content-Security-Policy") {
		t.Errorf("close without header: %v", err)
	}
}

func nan() float64 { z := 0.0; return z / z }

// cellOf is the inner HTML of the single data cell of a one-cell document.
func cellOf(t testing.TB, raw []byte) string {
	s := string(raw)
	i := strings.Index(s, "<tbody>")
	j := strings.Index(s[i:], `<td class="`)
	k := strings.Index(s[i+j:], `">`)
	start := i + j + k + 2
	end := strings.Index(s[start:], "</td>")
	return s[start : start+end]
}

var formatByName = map[string]httpx.Format{"csv": httpx.CSV, "xlsx": httpx.XLSX, "html": httpx.HTML, "pdf": httpx.PDF}

// attachment is HT-13 to HT-17: the download headers of httpx, the other half of the html unit.
func attachment(r corpus.Record) (corpus.Result, error) {
	base, err := r.Arg("base")
	if err != nil {
		return corpus.Result{}, err
	}
	fm, err := r.Arg("format")
	if err != nil {
		return corpus.Result{}, err
	}
	rec := httptest.NewRecorder()
	if err := httpx.Attachment(rec, base.Text(), formatByName[fm.Text()], nil); err != nil {
		return corpustest.Err("Unexpected"), nil
	}
	return corpustest.Render(rec.Header().Get("Content-Disposition")), nil
}

// TestCorpus runs every runtime record of the html unit (testdata/safe-primitives/html.jsonl; FF-SP4):
// the HTML export records HT-01, HT-04, HT-11, HT-12, HT-23, HT-24 and HT-30 to HT-34, and HT-13 to
// HT-17 of httpx.Attachment. One implementation runs the whole unit (a unit's implementation runs
// every record), and the manifest names httpx as covered by it.
func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/html", "html", func(r corpus.Record) (corpus.Result, error) {
		switch r.Call {
		case "httpx.Attachment":
			return attachment(r)
		case "Cell", "Document", "Title":
		default:
			return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
		}
		v, err := r.Arg("value")
		if err != nil {
			return corpus.Result{}, err
		}
		in := v.Text()
		opts := Options{}
		cols := []export.Column{{Label: "Value"}}
		var cells []export.Cell
		switch r.Call {
		case "Title":
			opts.Title = in
			cells = []export.Cell{export.Text("v")}
		default:
			cells = []export.Cell{export.Text(in)}
		}
		raw, rep := render(t, opts, cols, cells)
		if r.Call == "Cell" {
			return corpustest.Render(cellOf(t, raw)), nil
		}
		f := inspect(t, raw)
		m := map[string]any{"cspFirst": f.cspFirst && f.cspOK, "scripts": f.scripts, "externalURLs": f.externalURLs, "inlineHandlers": f.handlers}
		if r.Call == "Title" {
			m["title"] = f.title
			return corpustest.Value(m)
		}
		m["cell"] = cellOf(t, raw)
		want := string(r.Expect["value"])
		if strings.Contains(want, `"rows"`) {
			// header row and one data row: the template's own two <tr>
			m["rows"] = len(f.rows) + 1
			m["images"] = f.images
		}
		if strings.Contains(want, `"neutralised"`) {
			m["neutralised"] = rep.Neutralised
		}
		return corpustest.Value(m)
	})
}

// FuzzAnyTextIsInertString: any text in any position of the document leaves the policy intact, and the
// DOM holds the template's elements only.
func FuzzAnyTextIsInertString(f *testing.F) {
	corpustest.Seed(f, "html")
	for _, s := range []string{"", "x", "<script>", "\"'><", "‮", "\xff", "&amp;"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		s := string(in)
		raw, _ := render(t, Options{Title: s, About: []export.AboutLine{{Label: s, Value: s}}}, []export.Column{{Label: s}}, []export.Cell{export.Text(s)})
		fa := inspect(t, raw)
		if !fa.cspFirst || !fa.cspOK || fa.scripts != 0 || fa.handlers != 0 || fa.externalURLs != 0 || fa.images != 0 || len(fa.otherActive) != 0 || len(fa.rows) != 1 || len(fa.rows[0]) != 1 {
			t.Fatalf("input %q gave %+v", s, fa)
		}
	})
}
