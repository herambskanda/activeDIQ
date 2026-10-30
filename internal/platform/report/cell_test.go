package report_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

// AC 4: an unknown derived state has a digest tag distinct from null (absent, never) and from the
// empty string.
func TestUnknownCellHasItsOwnDigestTag(t *testing.T) {
	u := report.Unknown()
	if !u.IsUnknown() || u.Tag() != "u" {
		t.Fatalf("unknown = %v %q", u.Kind(), u.Tag())
	}
	others := map[string]report.Cell{
		"absent (null)": report.Absent(), "zero Cell": {}, "empty string": report.TextCell(""),
		"never": report.Never(), "empty list": report.ListCell(), "empty enum-like text": report.EnumCell("unknown_input_missing"),
	}
	for name, c := range others {
		if c.DigestTag() == u.DigestTag() {
			t.Errorf("unknown shares its digest tag with %s", name)
		}
	}
	if len(u.DigestValue()) != 0 {
		t.Fatalf("unknown digest value = %q, want length 0", u.DigestValue())
	}
	if report.Absent().DigestTag() == report.Never().DigestTag() || report.Absent().DigestTag() == report.TextCell("").DigestTag() {
		t.Fatal("absent is not distinct from never and from the empty string")
	}
	// Every kind has its own tag.
	seen := map[byte]report.CellKind{}
	for k := report.CellAbsent; k <= report.CellUnknown; k++ {
		c := cellOfKind(k)
		if prev, dup := seen[c.DigestTag()]; dup {
			t.Fatalf("kinds %d and %d share digest tag %d", prev, k, c.DigestTag())
		}
		seen[c.DigestTag()] = k
	}
}

func cellOfKind(k report.CellKind) report.Cell {
	switch k {
	case report.CellText:
		return report.TextCell("x")
	case report.CellInt:
		return report.IntCell(1)
	case report.CellBool:
		return report.BoolCell(true)
	case report.CellTime:
		return report.TimeCell(time.Unix(0, 0))
	case report.CellEnum:
		return report.EnumCell("e")
	case report.CellGUID:
		return report.GUIDCell(oid(1))
	case report.CellTextList:
		return report.ListCell("a")
	case report.CellNever:
		return report.Never()
	case report.CellUnknown:
		return report.Unknown()
	}
	return report.Absent()
}

func TestCellJSONRoundTrip(t *testing.T) {
	cells := []report.Cell{report.Absent(), report.Unknown(), report.Never(), report.TextCell(""), report.TextCell("é"),
		report.IntCell(9007199254740993), report.BoolCell(false), report.TimeCell(time.Date(2026, 10, 30, 1, 2, 3, 400, time.UTC)),
		report.EnumCell("locked"), report.GUIDCell(oid(7)), report.ListCell("a", "b")}
	for _, c := range cells {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var back report.Cell
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("%s: %v", b, err)
		}
		if back.Kind() != c.Kind() || !bytes.Equal(back.DigestValue(), c.DigestValue()) {
			t.Fatalf("%s did not round trip", b)
		}
	}
	if b, _ := json.Marshal(report.Unknown()); string(b) != `["u"]` {
		t.Fatalf("unknown = %s", b)
	}
	if b, _ := json.Marshal(report.IntCell(9007199254740993)); string(b) != `["i","9007199254740993"]` {
		t.Fatalf("int = %s", b)
	}
	for _, bad := range []string{`[]`, `["x"]`, `["u","extra"]`, `["s"]`, `["i","1.5"]`, `["g","nope"]`, `"u"`} {
		var c report.Cell
		if err := json.Unmarshal([]byte(bad), &c); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
