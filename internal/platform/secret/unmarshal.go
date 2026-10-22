package secret

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"reflect"
	"strings"
	"unicode/utf8"
)

// MarshalJSONTo fails with Unserializable (v2 encoding).
func (Secret) MarshalJSONTo(*jsontext.Encoder) error { return New(Unserializable) }

// UnmarshalJSONFrom decodes a JSON string straight into a fresh, pre-sized byte slice.
//
// It reads the raw value with ReadValue, which aliases the caller's buffer, and unescapes it
// itself. It never calls ReadToken (a string token is a Go string nobody can zero) and never uses
// a library string decoder. NUL, invalid UTF-8 and unpaired \uD800-style escapes are refused, so a
// password nobody typed is never set (R3). JSON null leaves the Secret empty.
func (s *Secret) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	start := d.InputOffset()
	v, err := d.ReadValue()
	if err != nil {
		return classifyRead(err)
	}
	switch k := v.Kind(); k {
	case 'n':
		s.Destroy()
		return nil
	case '"':
	default:
		return &jsonv2.SemanticError{ByteOffset: start, JSONKind: k, GoType: reflect.TypeFor[Secret]()}
	}
	out, err := unescape(v)
	if err != nil {
		return err
	}
	s.Destroy()
	*s = adopt(out)
	return nil
}

// classifyRead maps the decoder's own refusals to typed errors. The decoder's text may quote the
// offending escape, so it is never passed on.
func classifyRead(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "surrogate"):
		return New(InvalidUTF16)
	case strings.Contains(msg, "invalid UTF-8"):
		return New(InvalidUTF8)
	}
	return New(MalformedJSON)
}

// unescape turns a JSON string literal (quotes included) into UTF-8 bytes. The output is never
// longer than the input, so one allocation of len(lit) is enough and append never grows it.
func unescape(lit []byte) ([]byte, error) {
	if len(lit) < 2 || lit[0] != '"' || lit[len(lit)-1] != '"' {
		return nil, New(MalformedJSON)
	}
	in := lit[1 : len(lit)-1]
	out := make([]byte, 0, len(in))
	fail := func(code string) ([]byte, error) {
		clear(out[:cap(out)])
		return nil, New(code)
	}
	for i := 0; i < len(in); {
		c := in[i]
		switch {
		case c == 0:
			return fail(NulInSecret)
		case c != '\\':
			r, n := utf8.DecodeRune(in[i:])
			if r == utf8.RuneError && n <= 1 {
				return fail(InvalidUTF8)
			}
			out = append(out, in[i:i+n]...)
			i += n
			continue
		}
		if i+1 >= len(in) {
			return fail(MalformedJSON)
		}
		e := in[i+1]
		i += 2
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(in, i)
			if !ok {
				return fail(MalformedJSON)
			}
			i += 4
			switch {
			case r == 0:
				return fail(NulInSecret)
			case r >= 0xDC00 && r <= 0xDFFF:
				return fail(InvalidUTF16)
			case r >= 0xD800 && r <= 0xDBFF:
				if i+1 >= len(in) || in[i] != '\\' || in[i+1] != 'u' {
					return fail(InvalidUTF16)
				}
				lo, ok := hex4(in, i+2)
				if !ok {
					return fail(MalformedJSON)
				}
				if lo < 0xDC00 || lo > 0xDFFF {
					return fail(InvalidUTF16)
				}
				i += 6
				r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
			}
			out = utf8.AppendRune(out, rune(r))
		default:
			return fail(MalformedJSON)
		}
	}
	return out, nil
}

func hex4(b []byte, i int) (r uint32, ok bool) {
	if i+4 > len(b) {
		return 0, false
	}
	for _, c := range b[i : i+4] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | uint32(c)
	}
	return r, true
}
