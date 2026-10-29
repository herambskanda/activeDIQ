package csv

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/export/cellsafe"
)

// field renders one text value as the bytes of its CSV field (no BOM, no header).
func field(t *testing.T, d Delimiter, c export.Cell) string {
	t.Helper()
	var b bytes.Buffer
	w, err := NewWriter(&b, Options{Delimiter: d, OmitBOM: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Row([]export.Cell{c}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(b.String(), "\r\n")
}

func TestCorpus(t *testing.T) {
	cases := []struct {
		id    string
		delim Delimiter
		in    string
		want  string
	}{
		{"CSV-01", Comma, "=1+1", "\"\t=1+1\""},
		{"CSV-02", Comma, `=HYPERLINK("http://example.invalid/?q="&A1,"Click")`, "\"\t=HYPERLINK(\"\"http://example.invalid/?q=\"\"&A1,\"\"Click\"\")\""},
		{"CSV-03", Comma, `=cmd|' /C calc'!A0`, "\"\t=cmd|' /C calc'!A0\""},
		{"CSV-04", Comma, `@SUM(1+9)*cmd|' /C calc'!A0`, "\"\t@SUM(1+9)*cmd|' /C calc'!A0\""},
		{"CSV-05", Comma, `-2+3+cmd|' /C calc'!A0`, "\"\t-2+3+cmd|' /C calc'!A0\""},
		{"CSV-06a", Comma, "＝1+1", "\"\t＝1+1\""},
		{"CSV-06b", Comma, "﹦1+1", "\"\t﹦1+1\""},
		{"CSV-07", Comma, "​=1+1", "\"\t​=1+1\""},
		{"CSV-08", Comma, "\t=1+1", "\"\t\t=1+1\""},
		{"CSV-09", Comma, `a","=1+1`, `"a"",""=1+1"`},
		{"CSV-10a", Comma, "a,=1+1", `"a,=1+1"`},
		{"CSV-10b", Comma, "a;=1+1", `"a;=1+1"`},
		{"CSV-11", Comma, "a\r\n=1+1", "\"a\r\n=1+1\""},
		{"CSV-12", Comma, `"=1+1`, `"""=1+1"`},
		{"CSV-19", Semicolon, "a;=1+1", `"a;=1+1"`},
		{"CSV-20", Comma, "+1 555 0100", "\"\t+1 555 0100\""},
		{"CSV-22", Comma, "Smith, John", `"Smith, John"`},
		{"lf-lead", Comma, "\n=1", "\"\t\n=1\""},
		{"cr-lead", Comma, "\r=1", "\"\t\r=1\""},
	}
	for _, c := range cases {
		if got := field(t, c.delim, export.Text(c.in)); got != c.want {
			t.Errorf("%s: got %q want %q", c.id, got, c.want)
		}
		// CSV-23 / rule 5: the reader restores the data.
		var b bytes.Buffer
		w, _ := NewWriter(&b, Options{Delimiter: c.delim})
		w.Row([]export.Cell{export.Text(c.in)})
		w.Close()
		r, _ := NewReader(&b, Options{Delimiter: c.delim}, Limits{})
		rec, err := r.Row()
		if err != nil || len(rec) != 1 || rec[0] != c.in {
			t.Errorf("%s: round trip got %q err %v", c.id, rec, err)
		}
	}
}

func TestCSV13HeaderSepDirective(t *testing.T) {
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{})
	w.Header([]export.Column{{Label: "sep=;"}})
	w.Close()
	if got := b.String(); got != "\xEF\xBB\xBF\"sep=;\"\r\n" {
		t.Fatalf("got %q", got)
	}
}

func TestCSV14Truncation(t *testing.T) {
	long := strings.Repeat("a", 40000)
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{OmitBOM: true})
	w.Row([]export.Cell{export.Text(long)})
	rep, _ := w.Close()
	v := strings.Trim(strings.TrimSuffix(b.String(), "\r\n"), `"`)
	if n := len(utf16.Encode([]rune(v))); n != 32767 {
		t.Fatalf("units = %d", n)
	}
	if !strings.HasSuffix(v, "… [truncated: 40000 chars]") || rep.Truncated != 1 {
		t.Fatalf("suffix/report wrong: %q %+v", v[len(v)-40:], rep)
	}
	// A surrogate pair straddling the cut is never split.
	emoji := strings.Repeat("\U0001F600", 20000)
	b.Reset()
	w, _ = NewWriter(&b, Options{OmitBOM: true})
	w.Row([]export.Cell{export.Text(emoji)})
	w.Close()
	if !utf8.Valid(b.Bytes()) || len(utf16.Encode([]rune(b.String()))) > 32767+4 {
		t.Fatal("emoji cut invalid")
	}
}

func TestCSV15Multi(t *testing.T) {
	if got := field(t, Comma, export.Multi("a", "=1+1")); got != `"a; =1+1"` {
		t.Fatal(got)
	}
	if got := field(t, Comma, export.Multi("=1", "a")); got != "\"\t=1; a\"" {
		t.Fatal(got)
	}
}

func TestCSV16TabDelimiterRefused(t *testing.T) {
	if _, err := NewWriter(io.Discard, Options{Delimiter: Delimiter(9)}); !errors.Is(err, ErrDelimiterNotAllowed) {
		t.Fatal(err)
	}
}

func TestTypedCells(t *testing.T) {
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{OmitBOM: true})
	w.Header([]export.Column{{Label: "a"}, {Label: "b"}, {Label: "c"}, {Label: "d"}, {Label: "e"}})
	w.Row([]export.Cell{export.Int64(-5), export.Float64(1.5), export.Bool(true), export.Never(), export.Empty()})
	rep, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	want := "\"a\",\"b\",\"c\",\"d\",\"e\"\r\n-5,1.5,true,\"Never\",\r\n"
	if b.String() != want {
		t.Fatalf("got %q", b.String())
	}
	if rep.Rows != 1 || rep.Neutralised != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestNonFiniteAndShape(t *testing.T) {
	w, _ := NewWriter(io.Discard, Options{})
	w.Header([]export.Column{{Label: "a"}})
	if err := w.Row([]export.Cell{export.Float64(inf())}); !errors.Is(err, export.ErrNonFiniteNumber) {
		t.Fatal(err)
	}
	if err := w.Row(nil); !errors.Is(err, export.ErrColumnMismatch) {
		t.Fatal(err)
	}
}

func TestRowCap(t *testing.T) {
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{MaxRows: 3, OmitBOM: true})
	for i := 0; i < 3; i++ {
		if err := w.Row([]export.Cell{export.Int64(int64(i))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Row([]export.Cell{export.Int64(9)}); !errors.Is(err, export.ErrRowCapExceeded) {
		t.Fatal(err)
	}
	rep, _ := w.Close()
	if rep.Rows != 3 {
		t.Fatal(rep)
	}
}

func TestInvalidUTF8Mapped(t *testing.T) {
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{OmitBOM: true})
	w.Row([]export.Cell{export.Text("a\xffb")})
	rep, _ := w.Close()
	if !utf8.Valid(b.Bytes()) || rep.Mapped != 1 {
		t.Fatalf("%q %+v", b.Bytes(), rep)
	}
}

func TestNeutralisedCount(t *testing.T) {
	var b bytes.Buffer
	w, _ := NewWriter(&b, Options{})
	w.Row([]export.Cell{export.Text("=1"), export.Text("ok"), export.Text("+2")})
	rep, _ := w.Close()
	if rep.Neutralised != 2 {
		t.Fatal(rep)
	}
}

// FF-SP5 properties: Read(Write(v)) == v, and no cell starts with an un-neutralised lead.
func FuzzRoundTrip(f *testing.F) {
	for _, s := range []string{"=1+1", "\t=1", "a\r\n=1", `"=1`, "＝1", "", "​+1", "plain", "a,b;c", "\x01=1"} {
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, s string, semi bool) {
		if !utf8.ValidString(s) || utf16Len(s) > export.MaxCellUnits {
			t.Skip()
		}
		d := Comma
		if semi {
			d = Semicolon
		}
		var b bytes.Buffer
		w, _ := NewWriter(&b, Options{Delimiter: d})
		w.Row([]export.Cell{export.Text("x"), export.Text(s)})
		w.Close()
		raw := b.Bytes()
		r, _ := NewReader(bytes.NewReader(raw), Options{Delimiter: d}, Limits{})
		rec, err := r.Row()
		if err != nil || len(rec) != 2 || rec[1] != s {
			t.Fatalf("round trip: %q -> %q (%v)", s, rec, err)
		}
		// The raw (as a spreadsheet sees it) field must not classify as a lead.
		rb, _ := NewReader(bytes.NewReader(raw), Options{Delimiter: d}, Limits{})
		_ = rb
		if cellsafe.Classify(s) == cellsafe.FormulaLead {
			i := bytes.Index(raw, []byte(",\"")) // second field start
			if d == Semicolon {
				i = bytes.Index(raw, []byte(";\""))
			}
			if i < 0 || raw[i+2] != '\t' {
				t.Fatalf("lead %q not neutralised: %q", s, raw)
			}
		}
	})
}

func utf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

func TestReaderLimitsAndSyntax(t *testing.T) {
	r, _ := NewReader(strings.NewReader("\"abcdef\"\r\n"), Options{}, Limits{MaxFieldBytes: 3})
	if _, err := r.Row(); !errors.Is(err, ErrFieldTooLong) {
		t.Fatal(err)
	}
	r, _ = NewReader(strings.NewReader("\"a\"x\r\n"), Options{}, Limits{})
	if _, err := r.Row(); !errors.Is(err, ErrSyntax) {
		t.Fatal(err)
	}
	r, _ = NewReader(strings.NewReader("a,b,c\r\n"), Options{}, Limits{MaxFields: 2})
	if _, err := r.Row(); !errors.Is(err, ErrTooManyCells) {
		t.Fatal(err)
	}
	r, _ = NewReader(strings.NewReader("a\r\nb\r\nc\r\n"), Options{}, Limits{MaxRows: 2})
	r.Row()
	r.Row()
	if _, err := r.Row(); !errors.Is(err, ErrTooManyRows) {
		t.Fatal(err)
	}
}

func inf() float64 { var z float64; return 1 / z }
