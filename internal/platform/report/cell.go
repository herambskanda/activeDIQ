package report

import (
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// CellKind is the kind of a stored cell. The zero value is CellAbsent, so a zero Cell is "no
// value", never an invented one.
type CellKind uint8

const (
	CellAbsent   CellKind = iota // the rule gives no value
	CellText                     // UTF-8 text
	CellInt                      // integer
	CellBool                     // boolean
	CellTime                     // instant, UTC whole seconds
	CellEnum                     // an enum's stable ID
	CellGUID                     // object GUID
	CellTextList                 // list of text
	CellNever                    // the attribute's value means "never" (for example lastLogon 0)
	CellUnknown                  // a derived state whose input is missing (FR-09)
	cellEnd
)

// Cell is one stored value of a report row. JSON form: [tag] or [tag, value] (contract §6.2).
// Absent, never and unknown are three different things and have three different digest tags: a run
// whose inputs were missing never shares a digest with one where the value was absent.
type Cell struct {
	kind CellKind
	s    string
	i    int64
	b    bool
	t    time.Time
	g    authz.ObjectID
	l    []string
}

// Absent is the cell for "the rule gives no value".
func Absent() Cell { return Cell{} }

// Never is the cell for an attribute whose value means "never".
func Never() Cell { return Cell{kind: CellNever} }

// Unknown is the cell for a derived value whose input is missing. It is never inferred from,
// and never equal to, an absent or empty value.
func Unknown() Cell { return Cell{kind: CellUnknown} }

// TextCell is a text cell. The empty string is a value, distinct from Absent.
func TextCell(s string) Cell { return Cell{kind: CellText, s: s} }

// IntCell is an integer cell.
func IntCell(i int64) Cell { return Cell{kind: CellInt, i: i} }

// BoolCell is a boolean cell.
func BoolCell(b bool) Cell { return Cell{kind: CellBool, b: b} }

// TimeCell is a time cell, held in UTC with whole seconds.
func TimeCell(t time.Time) Cell { return Cell{kind: CellTime, t: t.UTC().Truncate(time.Second)} }

// EnumCell is an enum cell holding the stable ID.
func EnumCell(id string) Cell { return Cell{kind: CellEnum, s: id} }

// GUIDCell is a GUID cell.
func GUIDCell(g authz.ObjectID) Cell { return Cell{kind: CellGUID, g: g} }

// ListCell is a text-list cell.
func ListCell(vs ...string) Cell {
	return Cell{kind: CellTextList, l: append([]string{}, vs...)}
}

// Kind returns the cell's kind.
func (c Cell) Kind() CellKind { return c.kind }

// IsUnknown reports whether the cell is Unknown.
func (c Cell) IsUnknown() bool { return c.kind == CellUnknown }

var cellTags = [cellEnd]string{"a", "s", "i", "b", "t", "e", "g", "l", "n", "u"}

// Tag is the one-letter JSON tag of the cell's kind.
func (c Cell) Tag() string { return cellTags[c.kind%cellEnd] }

// DigestTag is the one-byte type tag the canonical digest writes before the length and bytes
// (spec §8.3). Each kind has its own, so Unknown differs from Absent, Never and the empty string.
func (c Cell) DigestTag() byte { return byte(c.kind) }

// DigestValue is the typed text form the digest hashes after the tag: UTF-8 text as stored,
// base-10 integer, "true"/"false", RFC 3339 UTC time with whole seconds, the enum's ID, the
// canonical GUID. A list is each element as a 4-byte big-endian length then its bytes. Absent,
// Never and Unknown have length 0.
func (c Cell) DigestValue() []byte {
	switch c.kind {
	case CellText, CellEnum:
		return []byte(c.s)
	case CellInt:
		return strconv.AppendInt(nil, c.i, 10)
	case CellBool:
		return strconv.AppendBool(nil, c.b)
	case CellTime:
		return []byte(c.t.Format(time.RFC3339))
	case CellGUID:
		return []byte(GUIDString(c.g))
	case CellTextList:
		var out []byte
		for _, e := range c.l {
			out = binary.BigEndian.AppendUint32(out, uint32(len(e)))
			out = append(out, e...)
		}
		return out
	}
	return nil
}

// MarshalJSON writes [tag] or [tag, value]. An integer is a decimal string so 64-bit values stay exact.
func (c Cell) MarshalJSON() ([]byte, error) {
	tag := c.Tag()
	switch c.kind {
	case CellText, CellEnum:
		return json.Marshal([]any{tag, c.s}, wireOpts)
	case CellInt:
		return json.Marshal([]any{tag, strconv.FormatInt(c.i, 10)}, wireOpts)
	case CellBool:
		return json.Marshal([]any{tag, c.b}, wireOpts)
	case CellTime:
		return json.Marshal([]any{tag, c.t.Format(time.RFC3339)}, wireOpts)
	case CellGUID:
		return json.Marshal([]any{tag, GUIDString(c.g)}, wireOpts)
	case CellTextList:
		return json.Marshal([]any{tag, c.l}, wireOpts)
	}
	return json.Marshal([]any{tag}, wireOpts)
}

// UnmarshalJSON reads what MarshalJSON writes and refuses any other shape.
func (c *Cell) UnmarshalJSON(b []byte) error {
	var parts []jsontext.Value
	if err := json.Unmarshal(b, &parts); err != nil || len(parts) == 0 || len(parts) > 2 {
		return verr(CodeBadValue, "cell")
	}
	var tag string
	if err := json.Unmarshal(parts[0], &tag); err != nil {
		return verr(CodeBadValue, "cell")
	}
	kind := cellEnd
	for k, t := range cellTags {
		if t == tag {
			kind = CellKind(k)
		}
	}
	if kind == cellEnd {
		return verr(CodeBadValue, "cell")
	}
	hasValue := kind != CellAbsent && kind != CellNever && kind != CellUnknown
	if hasValue != (len(parts) == 2) {
		return verr(CodeBadValue, "cell")
	}
	var out Cell
	var err error
	switch kind {
	case CellText, CellEnum:
		var s string
		err = json.Unmarshal(parts[1], &s)
		out = Cell{kind: kind, s: s}
	case CellInt:
		var s string
		if err = json.Unmarshal(parts[1], &s); err == nil {
			var i int64
			i, err = strconv.ParseInt(s, 10, 64)
			out = IntCell(i)
		}
	case CellBool:
		var x bool
		err = json.Unmarshal(parts[1], &x)
		out = BoolCell(x)
	case CellTime:
		var s string
		if err = json.Unmarshal(parts[1], &s); err == nil {
			var t time.Time
			t, err = time.Parse(time.RFC3339, s)
			out = TimeCell(t)
		}
	case CellGUID:
		var s string
		if err = json.Unmarshal(parts[1], &s); err == nil {
			var g authz.ObjectID
			g, err = authz.ParseObjectID(s)
			out = GUIDCell(g)
		}
	case CellTextList:
		var l []string
		err = json.Unmarshal(parts[1], &l)
		out = ListCell(l...)
	default:
		out = Cell{kind: kind}
	}
	if err != nil {
		return verr(CodeBadValue, "cell")
	}
	*c = out
	return nil
}
