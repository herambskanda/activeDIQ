package csv

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/export/cellsafe"
)

// TestCorpus runs CSV-01 to CSV-23 (testdata/safe-primitives/csv.jsonl, safe-primitives §12.3,
// FF-SP4): 26 records, 21 hostile; CSV-17 and CSV-18 are lab records (FF-SP11). Every Field record is
// also read back by Reader, so rule 5 (Read(Write(v)) == v) holds for each corpus input.
func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/csv", "csv", func(r corpus.Record) (corpus.Result, error) {
		d := Comma
		if _, ok := r.Args["delimiter"]; ok {
			in, err := r.Arg("delimiter")
			if err != nil {
				return corpus.Result{}, err
			}
			switch in.Text() {
			case "comma":
			case "semicolon":
				d = Semicolon
			case "tab":
				d = Delimiter(9) // there is no Tab constant (CSV-16): the nearest spelling is an unknown value
			default:
				return corpus.Result{}, fmt.Errorf("unknown delimiter %q", in.Text())
			}
		}
		switch r.Call {
		case "Field":
			v, err := r.Arg("value")
			if err != nil {
				return corpus.Result{}, err
			}
			got, err := fieldOf(d, export.Text(v.Text()))
			if err != nil {
				return corpus.Result{}, err
			}
			if back, err := readBack(d, got); err != nil || back != v.Text() {
				return corpus.Result{}, fmt.Errorf("round trip: %q -> %q (%v)", v.Text(), back, err)
			}
			return corpustest.Render(got), nil
		case "FieldShape":
			v, err := r.Arg("value")
			if err != nil {
				return corpus.Result{}, err
			}
			n, err := repeatCount(r)
			if err != nil {
				return corpus.Result{}, err
			}
			var b bytes.Buffer
			w, _ := NewWriter(&b, Options{OmitBOM: true})
			if err := w.Row([]export.Cell{export.Text(strings.Repeat(v.Text(), n))}); err != nil {
				return corpus.Result{}, err
			}
			rep, _ := w.Close()
			cell := strings.Trim(strings.TrimSuffix(b.String(), "\r\n"), `"`)
			suffix := ""
			if i := strings.LastIndex(cell, "\u2026"); i >= 0 {
				suffix = cell[i:]
			}
			return corpustest.Value(map[string]any{"units": utf16Len(cell), "suffix": suffix, "truncated": rep.Truncated})
		case "Multi":
			var vals []map[string]string
			if err := json.Unmarshal(r.Args["values"], &vals); err != nil {
				return corpus.Result{}, err
			}
			cell := make([]string, len(vals))
			for i, m := range vals {
				cell[i] = m["utf8"]
			}
			got, err := fieldOf(d, export.Multi(cell...))
			return corpustest.Render(got), err
		case "Header":
			l, err := r.Arg("label")
			if err != nil {
				return corpus.Result{}, err
			}
			var b bytes.Buffer
			w, err := NewWriter(&b, Options{Delimiter: d})
			if err != nil {
				return corpus.Result{}, err
			}
			if err := w.Header([]export.Column{{Label: l.Text()}}); err != nil {
				return corpus.Result{}, err
			}
			if _, err := w.Close(); err != nil {
				return corpus.Result{}, err
			}
			return corpustest.BytesHex(b.Bytes()), nil
		case "TypedField":
			var n int64
			if err := json.Unmarshal(r.Args["int64"], &n); err != nil {
				return corpus.Result{}, err
			}
			got, err := fieldOf(d, export.Int64(n))
			return corpustest.Render(got), err
		case "NewWriter":
			if _, err := NewWriter(io.Discard, Options{Delimiter: d}); errors.Is(err, ErrDelimiterNotAllowed) {
				return corpustest.Err("DelimiterNotAllowed"), nil
			} else if err != nil {
				return corpus.Result{}, err
			}
			return corpustest.Render("accepted"), nil
		case "Read":
			f, err := r.Arg("field")
			if err != nil {
				return corpus.Result{}, err
			}
			rd, err := NewReader(strings.NewReader(f.Text()+"\r\n"), Options{Delimiter: d}, Limits{})
			if err != nil {
				return corpus.Result{}, err
			}
			rec, err := rd.Row()
			if err != nil || len(rec) != 1 {
				return corpus.Result{}, fmt.Errorf("read %q: %q %v", f.Text(), rec, err)
			}
			return corpustest.Render(rec[0]), nil
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

func repeatCount(r corpus.Record) (int, error) {
	var n int
	err := json.Unmarshal(r.Args["repeat"], &n)
	return n, err
}

// fieldOf renders one cell as the bytes of its CSV field (no BOM, no header, no record terminator).
func fieldOf(d Delimiter, c export.Cell) (string, error) {
	var b bytes.Buffer
	w, err := NewWriter(&b, Options{Delimiter: d, OmitBOM: true})
	if err != nil {
		return "", err
	}
	if err := w.Row([]export.Cell{c}); err != nil {
		return "", err
	}
	if _, err := w.Close(); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\r\n"), nil
}

// readBack parses one field with Reader (the inverse of the neutraliser, rule 5).
func readBack(d Delimiter, fieldBytes string) (string, error) {
	r, err := NewReader(strings.NewReader(fieldBytes+"\r\n"), Options{Delimiter: d}, Limits{})
	if err != nil {
		return "", err
	}
	rec, err := r.Row()
	if err != nil || len(rec) != 1 {
		return "", fmt.Errorf("%q %v", rec, err)
	}
	return rec[0], nil
}

// Leads beyond the §12.3 table: LF and CR leads are neutralised too, and still round-trip.
func TestFieldEdges(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"\n=1", "\"\t\n=1\""},
		{"\r=1", "\"\t\r=1\""},
	} {
		got, err := fieldOf(Comma, export.Text(c.in))
		if err != nil || got != c.want {
			t.Errorf("%q: got %q (%v) want %q", c.in, got, err, c.want)
		}
		if back, err := readBack(Comma, got); err != nil || back != c.in {
			t.Errorf("%q: round trip %q (%v)", c.in, back, err)
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
	if got, _ := fieldOf(Comma, export.Multi("a", "=1+1")); got != `"a; =1+1"` {
		t.Fatal(got)
	}
	if got, _ := fieldOf(Comma, export.Multi("=1", "a")); got != "\"\t=1; a\"" {
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

// FuzzRoundTrip is the FF-SP5 target for csv: the properties roundtrip (Read(Write(v)) == v for both
// delimiters) and noFormulaLead (the field, as a spreadsheet sees it, never starts with a
// formula lead: when the value classifies as a lead the field's first byte after the quote is TAB).
func FuzzRoundTrip(f *testing.F) {
	corpustest.Seed(f, "csv")
	f.Fuzz(func(t *testing.T, in []byte) {
		s := string(in)
		if !utf8.ValidString(s) || utf16Len(s) > export.MaxCellUnits {
			t.Skip()
		}
		for _, d := range []Delimiter{Comma, Semicolon} {
			got, err := fieldOf(d, export.Text(s))
			if err != nil {
				t.Fatal(err)
			}
			if back, err := readBack(d, got); err != nil || back != s {
				t.Fatalf("round trip: %q -> %q (%v)", s, back, err)
			}
			if cellsafe.Classify(s) == cellsafe.FormulaLead && !strings.HasPrefix(got, "\"\t") {
				t.Fatalf("lead %q not neutralised: %q", s, got)
			}
			// What the spreadsheet reads: the unquoted field. It is either TAB-led (neutralised) or not a lead.
			inner := strings.ReplaceAll(got[1:len(got)-1], `""`, `"`)
			if !strings.HasPrefix(inner, "\t") && cellsafe.Classify(inner) == cellsafe.FormulaLead {
				t.Fatalf("field %q reaches the spreadsheet as a lead", got)
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
