// Package dn is P2 of the safe primitives (knowledge/development/architecture/safe-primitives.md §4):
// a typed distinguished name that is parsed, built and rendered per RFC 4514 with Microsoft's AD
// reserved characters, and ObjectRef, the typed way to name an existing object on the wire.
//
// A DN is never assembled from strings. Child escapes a value; Parse reads RFC 4514 text with the
// escape rules intact, so an escaped comma stays inside its value and cannot widen a scope.
// Equal and IsDescendantOf are for display, de-duplication and grouping only: they are weaker than
// AD's matching and must never decide identity or authorisation (§4.4). Identity is objectGUID.
package dn

import (
	"bytes"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Parse caps (provisional, §4.3).
const (
	MaxDNLen = 16 << 10
	MaxRDNs  = 64
)

// DNString is a rendered DN. It exists for display and for the connector; string operations on it
// outside this package and the connector are rejected by the dnstring analyzer (§4.6).
type DNString string

// Display returns the text for UI use. It is not a request value and not an identity.
func (d DNString) Display() string { return string(d) }

// RDNType is the closed set of attribute types a DN we build may use (schema rDNAttID), plus OID
// for numeric types seen in DC output.
type RDNType uint8

const (
	typeInvalid RDNType = iota
	CN
	OU
	DC
	O
	L
	ST
	C
	STREET
	UID
	OID
)

var typeNames = [...]string{CN: "CN", OU: "OU", DC: "DC", O: "O", L: "L", ST: "ST", C: "C", STREET: "STREET", UID: "UID"}

// String is the canonical upper-case name; OID types render as "OID" here and by number in a DN.
func (t RDNType) String() string {
	if t == OID {
		return "OID"
	}
	if int(t) < len(typeNames) && typeNames[t] != "" {
		return typeNames[t]
	}
	return ""
}

// ParseRDNType maps a name (any case) to the enum. Anything else, including text that is not a
// bare name, is UnknownRDNType: the type is an enum, not text.
func ParseRDNType(name string) (RDNType, error) {
	for t, n := range typeNames {
		if n != "" && strings.EqualFold(n, name) {
			return RDNType(t), nil
		}
	}
	return typeInvalid, fail(UnknownRDNType, -1)
}

// RDN is one attribute-value pair; AD disallows multi-valued RDNs, so there is exactly one.
type RDN struct {
	typ    RDNType
	oid    string
	val    string
	opaque []byte
}

func (r RDN) Type() RDNType { return r.typ }

// OID is the dotted numeric type when Type() == OID, else "".
func (r RDN) OID() string { return r.oid }

// Value is the unescaped value; empty for an opaque RDN.
func (r RDN) Value() string { return r.val }

// Opaque returns a copy of the BER bytes of a `#hex` value (OID types only), or nil.
func (r RDN) Opaque() []byte { return append([]byte(nil), r.opaque...) }

func (r RDN) equal(o RDN) bool {
	return r.typ == o.typ && r.oid == o.oid && bytes.Equal(r.opaque, o.opaque) && strings.EqualFold(r.val, o.val)
}

// DN is an ordered list of RDNs, leaf first, as in the text form. The zero value is the empty DN.
// A DN is immutable.
type DN struct{ rdns []RDN }

// Len is the number of RDNs.
func (d DN) Len() int { return len(d.rdns) }

// RDNs returns a copy of the RDN list, leaf first.
func (d DN) RDNs() []RDN { return append([]RDN(nil), d.rdns...) }

// Parent drops the leaf RDN. The empty DN is its own parent.
func (d DN) Parent() DN {
	if len(d.rdns) <= 1 {
		return DN{}
	}
	return DN{rdns: d.rdns[1:]}
}

// defaultMax is the schema rangeUpper we enforce without a schema: cn and ou are 64 characters.
// Child limits come from the schema at connect through ChildMax.
func defaultMax(t RDNType) int {
	if t == CN || t == OU {
		return 64
	}
	return 0
}

// Child returns parent with a new leaf RDN. The value is any non-empty UTF-8 text without NUL;
// every special character is escaped on Render. CN and OU values are capped at 64 UTF-16 units.
func Child(parent DN, t RDNType, value string) (DN, error) {
	return ChildMax(parent, t, value, defaultMax(t))
}

// ChildMax is Child with a schema-derived limit in UTF-16 code units (0 = none).
func ChildMax(parent DN, t RDNType, value string, max int) (DN, error) {
	if t == typeInvalid || t == OID || int(t) >= len(typeNames) {
		return DN{}, fail(UnknownRDNType, -1)
	}
	if value == "" {
		return DN{}, fail(EmptyRDNValue, -1)
	}
	if strings.IndexByte(value, 0) >= 0 {
		return DN{}, fail(NulInString, -1)
	}
	if !utf8.ValidString(value) {
		return DN{}, fail(InvalidUTF8, -1)
	}
	if max > 0 {
		n := 0
		for _, r := range value {
			n += utf16.RuneLen(r)
			if n > max {
				return DN{}, fail(ValueTooLong, -1)
			}
		}
	}
	if len(parent.rdns)+1 > MaxRDNs {
		return DN{}, fail(TooLong, -1)
	}
	rdns := make([]RDN, 0, len(parent.rdns)+1)
	rdns = append(rdns, RDN{typ: t, val: value})
	rdns = append(rdns, parent.rdns...)
	d := DN{rdns: rdns}
	if len(d.Render()) > MaxDNLen {
		return DN{}, fail(TooLong, -1)
	}
	return d, nil
}

// Equal compares types case-insensitively and unescaped values with Unicode simple case folding.
// Weaker than AD's matching by design (§4.4): display, dedup and grouping only.
func Equal(a, b DN) bool {
	if len(a.rdns) != len(b.rdns) {
		return false
	}
	for i := range a.rdns {
		if !a.rdns[i].equal(b.rdns[i]) {
			return false
		}
	}
	return true
}

// IsDescendantOf reports whether c lies strictly below a, comparing RDN by RDN. Same caveats as Equal.
func IsDescendantOf(c, a DN) bool {
	if len(c.rdns) <= len(a.rdns) {
		return false
	}
	off := len(c.rdns) - len(a.rdns)
	for i := range a.rdns {
		if !c.rdns[off+i].equal(a.rdns[i]) {
			return false
		}
	}
	return true
}

func (d DN) Equal(o DN) bool          { return Equal(d, o) }
func (d DN) IsDescendantOf(a DN) bool { return IsDescendantOf(d, a) }
