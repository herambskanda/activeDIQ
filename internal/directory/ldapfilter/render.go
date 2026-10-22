package ldapfilter

import (
	"strings"
	"unicode/utf8"
)

const (
	oidBitAnd  = "1.2.840.113556.1.4.803"
	oidBitOr   = "1.2.840.113556.1.4.804"
	oidInChain = "1.2.840.113556.1.4.1941"
	hexDigits  = "0123456789abcdef"
)

// FilterString is rendered filter text. Render is its only producer; code that holds one did not
// build it by hand.
type FilterString string

func (f FilterString) String() string { return string(f) }

func checkText(b []byte) error {
	if !utf8.Valid(b) {
		return fail(InvalidUTF8)
	}
	for _, c := range b {
		if c == 0 {
			return fail(NulInString)
		}
	}
	return nil
}

// escape appends b escaped per §3.2: the RFC 4515 set (* ( ) \ NUL), "/" (Microsoft), every control
// octet, DEL and every octet >= 0x80, lower-case hex.
func escape(dst *strings.Builder, b []byte) {
	for _, c := range b {
		if c < 0x20 || c >= 0x7f || c == '*' || c == '(' || c == ')' || c == '\\' || c == '/' {
			dst.WriteByte('\\')
			dst.WriteByte(hexDigits[c>>4])
			dst.WriteByte(hexDigits[c&0xf])
			continue
		}
		dst.WriteByte(c)
	}
}

// escapeAll escapes every octet, for binary values.
func escapeAll(dst *strings.Builder, b []byte) {
	for _, c := range b {
		dst.WriteByte('\\')
		dst.WriteByte(hexDigits[c>>4])
		dst.WriteByte(hexDigits[c&0xf])
	}
}

func writeValue(dst *strings.Builder, v Value) {
	switch v.kind {
	case kBytes, kGUID, kSID:
		escapeAll(dst, v.raw)
	default:
		escape(dst, v.raw)
	}
}

type renderer struct {
	sc    *Schema
	out   strings.Builder
	nodes int
}

// Render validates f against the schema and returns its canonical RFC 4515 text. The first problem
// is returned as an *Error and nothing is rendered.
func Render(f Filter, sc *Schema) (FilterString, error) {
	if f == nil {
		return "", fail(InvalidFilter)
	}
	r := &renderer{sc: sc}
	if err := r.node(f, 1); err != nil {
		return "", err
	}
	if r.out.Len() > MaxFilterBytes {
		return "", fail(FilterTooLong)
	}
	return FilterString(r.out.String()), nil
}

func (r *renderer) attr(a AttrName) (AttrInfo, error) {
	if a.name == "" {
		return AttrInfo{}, fail(InvalidAttributeName)
	}
	info, ok := r.sc.lookup(a.name)
	switch {
	case !ok:
		return AttrInfo{}, fail(UnknownAttribute)
	case info.Secret:
		return AttrInfo{}, fail(SecretAttribute)
	case info.Constructed:
		return AttrInfo{}, fail(ConstructedNotFilterable)
	}
	return info, nil
}

func (r *renderer) node(f Filter, depth int) error {
	if depth > MaxDepth {
		return fail(TooDeep)
	}
	if r.nodes++; r.nodes > MaxNodes {
		return fail(TooManyNodes)
	}
	if r.out.Len() > MaxFilterBytes {
		return fail(FilterTooLong)
	}
	return f.render(r, depth)
}
