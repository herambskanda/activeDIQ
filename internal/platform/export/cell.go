package export

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Caps (O7). Named constants; provisional until load tests.
const (
	// MaxDataRows is the Excel sheet maximum less the header row.
	MaxDataRows = 1_048_575
	// MaxCellUnits is the Excel cell limit in UTF-16 code units.
	MaxCellUnits = 32_767
	// MaxColumns is the Excel column limit.
	MaxColumns = 16_384
)

// Typed errors shared by the encoders. Callers match with errors.Is; none echoes cell data.
var (
	// ErrRowCapExceeded: the export has more rows than the cap. Raised before writing when the source
	// can count, otherwise when the row after the cap arrives; the output is then abandoned.
	ErrRowCapExceeded = errors.New("export: RowCapExceeded")
	// ErrNonFiniteNumber: a Float64 cell is NaN or infinite; spreadsheets cannot represent it.
	ErrNonFiniteNumber = errors.New("export: NonFiniteNumber")
	// ErrColumnMismatch: a row has a different number of cells than the header.
	ErrColumnMismatch = errors.New("export: row width differs from header")
	// ErrTooManyColumns: more columns than a spreadsheet holds.
	ErrTooManyColumns = errors.New("export: too many columns")
	// ErrHeaderAfterRow: Header was called after a row, or twice.
	ErrHeaderAfterRow = errors.New("export: Header must come first and only once")
	// ErrClosed: the writer was already closed.
	ErrClosed = errors.New("export: writer closed")
)

// RenderReport is what every encoder returns on Close (O8). The export audit event records it.
type RenderReport struct {
	// Rows is the number of data rows written (header excluded).
	Rows int64
	// Neutralised counts text cells (header labels included) that classified as a formula lead.
	Neutralised int64
	// Mapped counts values changed to stay valid (invalid UTF-8 replaced by U+FFFD).
	Mapped int64
	// Truncated counts cells cut to the cell limit.
	Truncated int64
}

// Add accumulates o into r.
func (r *RenderReport) Add(o RenderReport) {
	r.Rows += o.Rows
	r.Neutralised += o.Neutralised
	r.Mapped += o.Mapped
	r.Truncated += o.Truncated
}

type kind uint8

const (
	kEmpty kind = iota
	kText
	kInt
	kFloat
	kBool
	kTime
	kNever
	kMulti
	kUnknown
)

// Cell is one typed value. The zero Cell is Empty. Build cells with the constructors only.
type Cell struct {
	k     kind
	s     string
	multi []string
	i     int64
	f     float64
	b     bool
	t     time.Time
}

// Empty is a blank cell.
func Empty() Cell { return Cell{} }

// Text is a string value, stored raw (O2).
func Text(s string) Cell { return Cell{k: kText, s: s} }

// Int64 is an integer.
func Int64(v int64) Cell { return Cell{k: kInt, i: v} }

// Float64 is a finite number; NaN and ±Inf are refused by the encoder.
func Float64(v float64) Cell { return Cell{k: kFloat, f: v} }

// Bool is a boolean.
func Bool(v bool) Cell { return Cell{k: kBool, b: v} }

// Time is an instant, always written in UTC (durations and instants are computed in UTC).
func Time(v time.Time) Cell { return Cell{k: kTime, t: v} }

// NeverText is the label a Never cell shows.
const NeverText = "Never"

// Never marks an attribute whose value means "never" (for example lastLogon 0): it is text, not a date.
func Never() Cell { return Cell{k: kNever} }

// UnknownText is the label an Unknown cell shows.
const UnknownText = "Unknown (input missing)"

// Unknown marks a derived value whose input is missing (FR-09). It is text in the file, never blank and
// never "Never": a reader can tell "not collected" from "no value" from "never".
func Unknown() Cell { return Cell{k: kUnknown} }

// Multi is a multi-valued attribute; encoders join it with "; " into one cell.
func Multi(vs ...string) Cell { return Cell{k: kMulti, multi: append([]string(nil), vs...)} }

// Kind is the closed set of cell kinds an encoder switches on.
type Kind uint8

const (
	KindEmpty Kind = Kind(kEmpty)
	KindText  Kind = Kind(kText)
	KindInt   Kind = Kind(kInt)
	KindFloat Kind = Kind(kFloat)
	KindBool  Kind = Kind(kBool)
	KindTime  Kind = Kind(kTime)
)

// Resolved is a Cell reduced to what an encoder writes: text kinds (Text, Never, Multi) become
// KindText with the joined string, so each encoder has five cases, not eight.
type Resolved struct {
	Kind  Kind
	Text  string
	Int   int64
	Float float64
	Bool  bool
	Time  time.Time
}

// Resolve reduces the cell. It returns ErrNonFiniteNumber for NaN and ±Inf.
func (c Cell) Resolve() (Resolved, error) {
	switch c.k {
	case kEmpty:
		return Resolved{Kind: KindEmpty}, nil
	case kText:
		return Resolved{Kind: KindText, Text: c.s}, nil
	case kNever:
		return Resolved{Kind: KindText, Text: NeverText}, nil
	case kUnknown:
		return Resolved{Kind: KindText, Text: UnknownText}, nil
	case kMulti:
		return Resolved{Kind: KindText, Text: strings.Join(c.multi, "; ")}, nil
	case kInt:
		return Resolved{Kind: KindInt, Int: c.i}, nil
	case kFloat:
		if math.IsNaN(c.f) || math.IsInf(c.f, 0) {
			return Resolved{}, ErrNonFiniteNumber
		}
		return Resolved{Kind: KindFloat, Float: c.f}, nil
	case kBool:
		return Resolved{Kind: KindBool, Bool: c.b}, nil
	case kTime:
		return Resolved{Kind: KindTime, Time: c.t.UTC()}, nil
	}
	return Resolved{}, fmt.Errorf("export: unknown cell kind %d", c.k)
}

// FormatFloat is the invariant-culture spelling of a finite float.
func FormatFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// TimeLayout is the invariant spelling of a Time cell in text outputs.
const TimeLayout = "2006-01-02T15:04:05Z"

// AboutLine is one label and one value of an export's About block (reports-2a §8.3): the facts about
// a file (report, scope, filters, freshness, who and when, row count, digest). XLSX writes it as a first
// sheet, PDF and HTML as a header. Labels and values are data and go through the same rules as cells.
type AboutLine struct{ Label, Value string }

// MaxAboutLines bounds an About block.
const MaxAboutLines = 100

// Column is a header cell. The label is data and goes through the same cell rules as a value.
type Column struct{ Label string }

// Encoder is what Run drives. Both export/csv and export/xlsx writers satisfy it.
type Encoder interface {
	Header(cols []Column) error
	Row(cells []Cell) error
	Close() (RenderReport, error)
}

// Sanitize makes a text value valid UTF-8, replacing each invalid byte with U+FFFD. The change is
// visible and counted (O3), never silent deletion.
func Sanitize(s string) (string, bool) {
	if utf8.ValidString(s) {
		return s, false
	}
	return strings.ToValidUTF8(s, "�"), true
}

// LimitCell cuts s to the cell limit on a scalar boundary and ends it with the visible marker
// "… [truncated: N chars]", N being the original length in scalars (O7). The result is at most
// maxUnits UTF-16 code units, marker included.
func LimitCell(s string, maxUnits int) (string, bool) {
	if utf16Len(s) <= maxUnits {
		return s, false
	}
	marker := "… [truncated: " + strconv.Itoa(utf8.RuneCountInString(s)) + " chars]"
	budget := maxUnits - utf16Len(marker)
	if budget < 0 {
		budget = 0
	}
	units := 0
	cut := 0
	for i, r := range s {
		n := utf16.RuneLen(r)
		if units+n > budget {
			cut = i
			break
		}
		units += n
		cut = i + utf8.RuneLen(r)
	}
	return s[:cut] + marker, true
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}
