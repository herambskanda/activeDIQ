// Package guid is the one codec for objectGUID (safe-primitives §5.1): the 16-octet LDAP value
// (Data1, Data2 and Data3 little-endian, MS-DTYP 2.3.4) to and from the canonical dashed text.
// Objects are keyed by GUID, so a GUID that is not exactly what the directory sent is refused.
package guid

import (
	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
)

// Error codes.
const (
	BadLength = codec.BadLength // the octet string is not 16 bytes
	BadFormat = codec.BadFormat // the text is not the dashed form, optionally in braces
	NilGUID   = "NilGUID"       // all zero: never an object identity
)

// Size is the length of the octet string.
const Size = 16

// GUID is a GUID in the octet-string order AD stores it (the mixed-endian layout).
type GUID [Size]byte

// maxText is the longest accepted text: braces plus 36 characters. Longer input is refused
// without being read (R5: no work proportional to hostile input).
const maxText = 38

// FromBytes decodes an objectGUID value.
func FromBytes(b []byte) (GUID, error) {
	var g GUID
	if len(b) != Size {
		return g, codec.New(BadLength)
	}
	copy(g[:], b)
	if g == (GUID{}) {
		return GUID{}, codec.New(NilGUID)
	}
	return g, nil
}

// Bytes returns the octet string to send to a directory.
func (g GUID) Bytes() []byte {
	b := make([]byte, Size)
	copy(b, g[:])
	return b
}

// textOrder[i] is the octet-string index of the i-th byte in the canonical text order.
var textOrder = [Size]int{3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15}

const lowerHex = "0123456789abcdef"

// String is the canonical form: lower case, dashed, no braces.
func (g GUID) String() string {
	var out [36]byte
	o := 0
	for i, idx := range textOrder {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[o] = '-'
			o++
		}
		out[o] = lowerHex[g[idx]>>4]
		out[o+1] = lowerHex[g[idx]&0xf]
		o += 2
	}
	return string(out[:])
}

// ObjectRef is the extended-DN reference "<GUID=hex>" over the 16 octets as stored, the form every
// DC accepts (MS-ADTS alternative DN forms). The dn package wraps it in its ObjectRef type.
func (g GUID) ObjectRef() string {
	out := make([]byte, 0, len("<GUID=>")+2*Size)
	out = append(out, "<GUID="...)
	for _, c := range g {
		out = append(out, lowerHex[c>>4], lowerHex[c&0xf])
	}
	return string(append(out, '>'))
}

// Parse reads the dashed text form, with or without surrounding braces, in any case. The undashed
// form, look-alike dashes, whitespace, wildcards and anything but ASCII hex are BadFormat, as is
// the nil GUID's NilGUID.
func Parse(text string) (GUID, error) {
	n := len(text)
	if n > maxText {
		return GUID{}, codec.New(BadFormat)
	}
	switch {
	case n == 36:
	case n == 38 && text[0] == '{' && text[37] == '}':
		text = text[1:37]
	default:
		return GUID{}, codec.New(BadFormat)
	}
	var g GUID
	i := 0 // index into textOrder
	for p := 0; p < 36; {
		if p == 8 || p == 13 || p == 18 || p == 23 {
			if text[p] != '-' {
				return GUID{}, codec.New(BadFormat)
			}
			p++
			continue
		}
		hi, ok1 := hexVal(text[p])
		lo, ok2 := hexVal(text[p+1])
		if !ok1 || !ok2 {
			return GUID{}, codec.New(BadFormat)
		}
		g[textOrder[i]] = hi<<4 | lo
		i++
		p += 2
	}
	if g == (GUID{}) {
		return GUID{}, codec.New(NilGUID)
	}
	return g, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
