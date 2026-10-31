package report

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// ValueType is the type of a column and of a value.
type ValueType uint8

// Value types. The zero value is invalid so a forgotten type never validates.
const (
	TypeInvalid ValueType = iota
	TypeText
	TypeInt
	TypeBool
	TypeTime
	TypeEnum
	TypeGUID
	TypeTextList
)

func (t ValueType) String() string {
	switch t {
	case TypeText:
		return "text"
	case TypeInt:
		return "int"
	case TypeBool:
		return "bool"
	case TypeTime:
		return "time"
	case TypeEnum:
		return "enum"
	case TypeGUID:
		return "guid"
	case TypeTextList:
		return "textList"
	}
	return "invalid"
}

// Op is a comparison operator: a closed vocabulary (P5 rule 13). The zero value is not an operator.
type Op uint8

const (
	opInvalid Op = iota
	OpEq
	OpNe
	OpLt
	OpLe
	OpGt
	OpGe
	OpIn
	OpPresent
	OpAbsent
	OpContains // text: literal substring (LikePattern at compile time, P5 rule 4)
	OpPrefix   // text: literal prefix
	OpWithinLastDays
	OpOlderThanDays
	OpWithinNextDays
	opEnd
)

var opNames = [...]string{
	OpEq: "eq", OpNe: "ne", OpLt: "lt", OpLe: "le", OpGt: "gt", OpGe: "ge", OpIn: "in",
	OpPresent: "present", OpAbsent: "absent", OpContains: "contains", OpPrefix: "prefix",
	OpWithinLastDays: "within_last_days", OpOlderThanDays: "older_than_days", OpWithinNextDays: "within_next_days",
}

func (o Op) String() string {
	if o > opInvalid && o < opEnd {
		return opNames[o]
	}
	return "invalid"
}

// Valid reports whether o is a defined operator.
func (o Op) Valid() bool { return o > opInvalid && o < opEnd }

// ParseOp returns the operator named s, or false.
func ParseOp(s string) (Op, bool) {
	for o := opInvalid + 1; o < opEnd; o++ {
		if opNames[o] == s {
			return o, true
		}
	}
	return opInvalid, false
}

// relative reports whether o takes a whole number of days compared with the run's bound now.
func (o Op) relative() bool {
	return o == OpWithinLastDays || o == OpOlderThanDays || o == OpWithinNextDays
}

// takesNoValue reports whether o takes no value.
func (o Op) takesNoValue() bool { return o == OpPresent || o == OpAbsent }

// SortDir is a sort direction. Anything else is refused (SQL-06).
type SortDir uint8

const (
	dirInvalid SortDir = iota
	Asc
	Desc
)

func (d SortDir) String() string {
	switch d {
	case Asc:
		return "asc"
	case Desc:
		return "desc"
	}
	return "invalid"
}

// Valid reports whether d is a defined direction.
func (d SortDir) Valid() bool { return d == Asc || d == Desc }

// ParseSortDir returns the direction named s, or false.
func ParseSortDir(s string) (SortDir, bool) {
	switch s {
	case "asc":
		return Asc, true
	case "desc":
		return Desc, true
	}
	return dirInvalid, false
}

// SortKey is one key of a sort.
type SortKey struct {
	Column ColumnID
	Dir    SortDir
}

// MaxTextValue is the longest text value a filter may carry, in bytes.
const MaxTextValue = 1024

// Value is one typed value. Its fields are unexported: build it with TextV, IntV, BoolV, TimeV,
// EnumV or GUIDV. The zero Value has TypeInvalid and never validates.
type Value struct {
	t    ValueType
	s    string
	i    int64
	b    bool
	tm   time.Time
	guid authz.ObjectID
}

// TextV is a text value.
func TextV(s string) Value { return Value{t: TypeText, s: s} }

// IntV is an integer value.
func IntV(i int64) Value { return Value{t: TypeInt, i: i} }

// BoolV is a boolean value.
func BoolV(b bool) Value { return Value{t: TypeBool, b: b} }

// TimeV is a time value, held in UTC with whole seconds.
func TimeV(t time.Time) Value { return Value{t: TypeTime, tm: t.UTC().Truncate(time.Second)} }

// EnumV is the stable ID of an enum value.
func EnumV(id string) Value { return Value{t: TypeEnum, s: id} }

// GUIDV is an object GUID value.
func GUIDV(g authz.ObjectID) Value { return Value{t: TypeGUID, guid: g} }

// Type returns the value's type.
func (v Value) Type() ValueType { return v.t }

// Text returns the text of a TypeText value, or the ID of a TypeEnum value.
func (v Value) Text() string { return v.s }

// Int returns the integer of a TypeInt value.
func (v Value) Int() int64 { return v.i }

// Bool returns the boolean of a TypeBool value.
func (v Value) Bool() bool { return v.b }

// Time returns the time of a TypeTime value.
func (v Value) Time() time.Time { return v.tm }

// GUID returns the GUID of a TypeGUID value.
func (v Value) GUID() authz.ObjectID { return v.guid }

// check refuses a value that cannot be bound safely: NUL or invalid UTF-8 in text (SQL-10, SQL-11),
// an oversize text, a zero GUID, or no type at all.
func (v Value) check(path string) error {
	switch v.t {
	case TypeText, TypeEnum:
		if len(v.s) > MaxTextValue || !utf8.ValidString(v.s) || strings.ContainsRune(v.s, 0) {
			return verr(CodeBadValue, path)
		}
		if v.t == TypeEnum && v.s == "" {
			return verr(CodeBadValue, path)
		}
	case TypeGUID:
		if v.guid.IsZero() {
			return verr(CodeBadValue, path)
		}
	case TypeInt, TypeBool, TypeTime:
	default:
		return verr(CodeBadValue, path)
	}
	return nil
}

// wireOpts keeps the encoding the v1 package wrote: a nil slice or map is null, not []/{}, and map
// members are sorted and <, >, &, U+2028 and U+2029 are escaped, so the bytes (and the query hash
// over them) are the ones v1 produced.
var wireOpts = json.JoinOptions(json.FormatNilSliceAsNull(true), json.FormatNilMapAsNull(true), json.Deterministic(true),
	jsontext.EscapeForHTML(true), jsontext.EscapeForJS(true))

// MarshalJSON writes {"text":"x"}, {"int":5}, {"bool":true}, {"time":"…Z"}, {"enum":"id"} or
// {"guid":"…"}.
func (v Value) MarshalJSON() ([]byte, error) {
	switch v.t {
	case TypeText:
		return json.Marshal(map[string]string{"text": v.s}, wireOpts)
	case TypeEnum:
		return json.Marshal(map[string]string{"enum": v.s}, wireOpts)
	case TypeInt:
		return json.Marshal(map[string]int64{"int": v.i}, wireOpts)
	case TypeBool:
		return json.Marshal(map[string]bool{"bool": v.b}, wireOpts)
	case TypeTime:
		return json.Marshal(map[string]string{"time": v.tm.Format(time.RFC3339)}, wireOpts)
	case TypeGUID:
		return json.Marshal(map[string]string{"guid": GUIDString(v.guid)}, wireOpts)
	}
	return nil, fmt.Errorf("report: cannot marshal a value of type %s", v.t)
}

// UnmarshalJSON reads exactly one of the keys MarshalJSON writes. Any other shape is refused.
func (v *Value) UnmarshalJSON(b []byte) error {
	var m map[string]jsontext.Value
	if err := json.Unmarshal(b, &m); err != nil || len(m) != 1 {
		return verr(CodeBadValue, "value")
	}
	for k, raw := range m {
		var out Value
		var err error
		switch k {
		case "text":
			var s string
			err = json.Unmarshal(raw, &s)
			out = TextV(s)
		case "enum":
			var s string
			err = json.Unmarshal(raw, &s)
			out = EnumV(s)
		case "int":
			var i int64
			err = json.Unmarshal(raw, &i)
			out = IntV(i)
		case "bool":
			var x bool
			err = json.Unmarshal(raw, &x)
			out = BoolV(x)
		case "time":
			var s string
			if err = json.Unmarshal(raw, &s); err == nil {
				var t time.Time
				t, err = time.Parse(time.RFC3339, s)
				out = TimeV(t)
			}
		case "guid":
			var s string
			if err = json.Unmarshal(raw, &s); err == nil {
				var g authz.ObjectID
				g, err = authz.ParseObjectID(s)
				out = GUIDV(g)
			}
		default:
			return verr(CodeBadValue, "value")
		}
		if err != nil {
			return verr(CodeBadValue, "value")
		}
		*v = out
	}
	return nil
}

// GUIDString is the canonical lower-case 8-4-4-4-12 form of g (the inverse of authz.ParseObjectID).
func GUIDString(g authz.ObjectID) string {
	b := [16]byte(g)
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	b[4], b[5] = b[5], b[4]
	b[6], b[7] = b[7], b[6]
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, x := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hexd[x>>4], hexd[x&15])
	}
	return string(out)
}
