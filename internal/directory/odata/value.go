package odata

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// Provisional caps (V5); they only tighten after lab vector OD-L6.
const (
	MaxString = 1024 // bytes
	MaxIn     = 15
	MaxAnd    = 8
	MaxDepth  = 4
	MaxURL    = 2048
)

// Value is one typed literal. The set is closed: String, GUIDText, GUID, Bool, Int, Time.
type Value interface {
	literal() string
}

// String is a validated Edm.String value.
type String struct{ s string }

// GUIDText is a GUID carried in an Edm.String property: rendered quoted.
type GUIDText struct{ g guid.GUID }

// GUID is an Edm.Guid value: rendered unquoted.
type GUID struct{ g guid.GUID }

// Bool is an Edm.Boolean value.
type Bool struct{ b bool }

// Int is an Edm.Int64 value.
type Int struct{ i int64 }

// Time is an Edm.DateTimeOffset value, always UTC.
type Time struct{ t time.Time }

// Str validates s (V3, V4, V5) and wraps it. Nothing is trimmed, folded or replaced.
func Str(s string) (String, error) {
	if len(s) > MaxString {
		return String{}, fail(TooLong)
	}
	if !utf8.ValidString(s) {
		return String{}, fail(InvalidUTF8)
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return String{}, fail(ControlChar)
		}
	}
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' && isHex(s[i+1]) && isHex(s[i+2]) {
			return String{}, fail(PercentTriplet)
		}
	}
	return String{s}, nil
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func GUIDOf(g guid.GUID) GUID         { return GUID{g} }
func GUIDTextOf(g guid.GUID) GUIDText { return GUIDText{g} }
func BoolOf(b bool) Bool              { return Bool{b} }
func IntOf(i int64) Int               { return Int{i} }

// TimeOf accepts years 0001 to 9999 (the range every Graph service parses).
func TimeOf(t time.Time) (Time, error) {
	u := t.UTC()
	if u.Year() < 1 || u.Year() > 9999 {
		return Time{}, fail(InvalidValue)
	}
	return Time{u}, nil
}

// quote is V1: the one place a quote is doubled.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (v String) literal() string   { return quote(v.s) }
func (v GUIDText) literal() string { return quote(v.g.String()) }
func (v GUID) literal() string     { return v.g.String() }
func (v Bool) literal() string     { return strconv.FormatBool(v.b) }
func (v Int) literal() string      { return strconv.FormatInt(v.i, 10) }
func (v Time) literal() string {
	if v.t.IsZero() {
		return "0001-01-01T00:00:00Z"
	}
	return v.t.Format(time.RFC3339Nano)
}

// Name is an OData identifier. It is validated when the request is rendered, so an invalid Name is
// an error at URL, never a malformed URL. Converting a non-constant string to Name outside this
// package is an FF-SP2 finding (analyzer odataname).
type Name string

const maxName = 128

func (n Name) valid(dotted bool) bool {
	parts := []string{string(n)}
	if dotted {
		parts = strings.Split(string(n), ".")
	}
	for _, p := range parts {
		if p == "" || len(p) > maxName {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' && i > 0) {
				return false
			}
		}
	}
	return true
}

// Prop is a declared property with its Edm type. Declarations live in package graphschema.
type Prop[V Value] struct{ name Name }

// AnyProp is a Prop of any type, for $select, $expand and $orderby.
type AnyProp interface{ propName() Name }

func (p Prop[V]) propName() Name { return p.name }

func StringProp(n Name) Prop[String]       { return Prop[String]{n} }   // Edm.String
func GUIDStringProp(n Name) Prop[GUIDText] { return Prop[GUIDText]{n} } // Edm.String carrying a GUID
func GUIDProp(n Name) Prop[GUID]           { return Prop[GUID]{n} }     // Edm.Guid
func BoolProp(n Name) Prop[Bool]           { return Prop[Bool]{n} }
func IntProp(n Name) Prop[Int]             { return Prop[Int]{n} }
func TimeProp(n Name) Prop[Time]           { return Prop[Time]{n} }
