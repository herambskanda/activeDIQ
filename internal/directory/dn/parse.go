package dn

import (
	"strings"
	"unicode/utf8"
)

// Mode selects how strict Parse is. Strict is for DC output; Lenient is for admin input and
// additionally trims unescaped spaces around ',' and '='.
type Mode uint8

const (
	Strict Mode = iota
	Lenient
)

// Parse reads RFC 4514 text. Multi-valued RDNs, RFC 1779 quoting and alternative forms
// (<GUID=…>, <SID=…>) are errors; the latter go through ParseObjectRef. The empty string is an
// error: a base of "" is the root DSE, not a DN.
func Parse[S ~string](text S, mode Mode) (DN, error) { return parse(string(text), mode) }

func parse(s string, mode Mode) (DN, error) {
	if len(s) > MaxDNLen {
		return DN{}, fail(TooLong, 0)
	}
	if s == "" {
		return DN{}, fail(EmptyRDN, 0)
	}
	if mode == Lenient {
		s = strings.TrimLeft(s, " ")
	}
	if s != "" && s[0] == '<' {
		if isAltForm(s) {
			return DN{}, fail(UseObjectRef, 0)
		}
		return DN{}, fail(UnescapedSpecial, 0)
	}
	p := parser{s: s, lenient: mode == Lenient}
	var rdns []RDN
	for {
		r, more, err := p.rdn()
		if err != nil {
			return DN{}, err
		}
		rdns = append(rdns, r)
		if len(rdns) > MaxRDNs {
			return DN{}, fail(TooLong, p.i)
		}
		if !more {
			return DN{rdns: rdns}, nil
		}
	}
}

func isAltForm(s string) bool {
	for _, k := range []string{"<GUID=", "<SID=", "<WKGUID="} {
		if len(s) >= len(k) && strings.EqualFold(s[:len(k)], k) {
			return true
		}
	}
	return false
}

type parser struct {
	s       string
	i       int
	lenient bool
}

func (p *parser) skipSpaces() {
	for p.i < len(p.s) && p.s[p.i] == ' ' {
		p.i++
	}
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// rdn reads one RDN and its trailing comma. more reports that another RDN must follow.
func (p *parser) rdn() (r RDN, more bool, err error) {
	s := p.s
	if p.lenient {
		p.skipSpaces()
	}
	start := p.i
	for p.i < len(s) && s[p.i] != '=' && s[p.i] != ',' {
		p.i++
	}
	if p.i == start && (p.i >= len(s) || s[p.i] == ',') {
		return r, false, fail(EmptyRDN, start)
	}
	if p.i >= len(s) || s[p.i] == ',' {
		return r, false, fail(MissingEquals, p.i)
	}
	typeText := s[start:p.i]
	if p.lenient {
		typeText = strings.TrimRight(typeText, " ")
	}
	if strings.IndexByte(typeText, ' ') >= 0 {
		return r, false, fail(UnexpectedSpace, start)
	}
	if err := setType(&r, typeText, start); err != nil {
		return r, false, err
	}
	p.i++ // '='
	if p.lenient {
		p.skipSpaces()
	} else if p.i < len(s) && s[p.i] == ' ' {
		return r, false, fail(UnexpectedSpace, p.i)
	}
	if p.i >= len(s) || s[p.i] == ',' {
		return r, false, fail(EmptyRDNValue, p.i)
	}
	if s[p.i] == '#' {
		return p.opaque(r)
	}
	var buf []byte
	protected := 0 // buf[:protected] ends in an escaped char, so trailing-space trimming stops there
	first := true
	ended := false
loop:
	for p.i < len(s) {
		c := s[p.i]
		switch c {
		case '\\':
			p.i++
			if p.i >= len(s) {
				return r, false, fail(DanglingEscape, p.i-1)
			}
			d := s[p.i]
			if strings.IndexByte(` #"+,;<=>\`, d) >= 0 {
				buf = append(buf, d)
				p.i++
			} else if isHex(d) && p.i+1 < len(s) && isHex(s[p.i+1]) {
				buf = append(buf, unhex(d)<<4|unhex(s[p.i+1]))
				p.i += 2
			} else {
				return r, false, fail(InvalidEscape, p.i-1)
			}
			protected = len(buf)
		case ',':
			p.i++
			ended = true
			break loop
		case '+':
			return r, false, fail(MultiValuedRDN, p.i)
		case '"':
			if first {
				return r, false, fail(QuotedValueNotSupported, p.i)
			}
			return r, false, fail(UnescapedSpecial, p.i)
		case '<', '>', ';':
			return r, false, fail(UnescapedSpecial, p.i)
		case 0:
			return r, false, fail(NulInString, p.i)
		default:
			buf = append(buf, c)
			p.i++
		}
		first = false
	}
	end := len(buf)
	for end > protected && buf[end-1] == ' ' {
		end--
	}
	if end != len(buf) {
		if !p.lenient {
			return r, false, fail(UnexpectedSpace, p.i)
		}
		buf = buf[:end]
	}
	if len(buf) == 0 {
		return r, false, fail(EmptyRDNValue, p.i)
	}
	for _, c := range buf {
		if c == 0 {
			return r, false, fail(NulInString, p.i)
		}
	}
	if !utf8.Valid(buf) {
		return r, false, fail(InvalidUTF8, p.i)
	}
	r.val = string(buf)
	if ended && p.i >= len(s) {
		return r, false, fail(EmptyRDN, p.i)
	}
	return r, ended, nil
}

// opaque reads `#hexstring` for an OID-typed RDN and keeps it as bytes.
func (p *parser) opaque(r RDN) (RDN, bool, error) {
	s := p.s
	if r.typ != OID {
		return r, false, fail(HexValueForbidden, p.i)
	}
	p.i++
	start := p.i
	for p.i < len(s) && s[p.i] != ',' {
		if !isHex(s[p.i]) {
			if s[p.i] == ' ' && p.lenient {
				break
			}
			return r, false, fail(InvalidEscape, p.i)
		}
		p.i++
	}
	h := s[start:p.i]
	if h == "" || len(h)%2 != 0 {
		return r, false, fail(InvalidEscape, start)
	}
	b := make([]byte, len(h)/2)
	for i := range b {
		b[i] = unhex(h[2*i])<<4 | unhex(h[2*i+1])
	}
	r.opaque = b
	p.skipSpaces() // lenient only reaches here with spaces
	if p.i < len(s) {
		if s[p.i] != ',' {
			if s[p.i] == '+' {
				return r, false, fail(MultiValuedRDN, p.i)
			}
			return r, false, fail(UnescapedSpecial, p.i)
		}
		p.i++ // ','
		if p.i >= len(s) {
			return r, false, fail(EmptyRDN, p.i)
		}
		return r, true, nil
	}
	return r, false, nil
}

// knownOIDs maps the numeric attribute types AD resolves to a typed RDN.
var knownOIDs = map[string]RDNType{
	"2.5.4.3": CN, "2.5.4.11": OU, "0.9.2342.19200300.100.1.25": DC, "2.5.4.10": O,
	"2.5.4.7": L, "2.5.4.8": ST, "2.5.4.6": C, "2.5.4.9": STREET, "0.9.2342.19200300.100.1.1": UID,
}

func setType(r *RDN, text string, pos int) error {
	if text == "" {
		return fail(EmptyRDN, pos)
	}
	if text[0] >= '0' && text[0] <= '9' {
		arcStart := true
		for i := 0; i < len(text); i++ {
			c := text[i]
			switch {
			case c == '.':
				if arcStart {
					return fail(UnknownRDNType, pos)
				}
				arcStart = true
			case c >= '0' && c <= '9':
				if arcStart && c == '0' && i+1 < len(text) && text[i+1] != '.' {
					return fail(UnknownRDNType, pos) // RFC 4512 numericoid: no leading zeros
				}
				arcStart = false
			default:
				return fail(UnknownRDNType, pos)
			}
		}
		if arcStart {
			return fail(UnknownRDNType, pos)
		}
		if t, ok := knownOIDs[text]; ok {
			// AD resolves these to the same attribute as the short name, so they must compare
			// equal to it (scope/readability checks rely on Equal/IsDescendantOf).
			r.typ = t
			return nil
		}
		r.typ, r.oid = OID, text
		return nil
	}
	t, err := ParseRDNType(text)
	if err != nil {
		return fail(UnknownRDNType, pos)
	}
	r.typ = t
	return nil
}
