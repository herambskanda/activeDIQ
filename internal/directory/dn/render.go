package dn

import (
	"strings"
	"unicode/utf8"
)

const upperHex = "0123456789ABCDEF"

// Render is the canonical text (§4.2): backslash for , + " \ < > ; leading # and edge spaces,
// upper-case hex for C0 controls, DEL, '=' and '/', everything else raw UTF-8. An opaque `#hex`
// RDN (OID types, DC output only) renders as `#hex` and makes the DN non-requestable.
func (d DN) Render() DNString {
	var b strings.Builder
	for i, r := range d.rdns {
		if i > 0 {
			b.WriteByte(',')
		}
		if r.typ == OID {
			b.WriteString(r.oid)
		} else {
			b.WriteString(r.typ.String())
		}
		b.WriteByte('=')
		if r.opaque != nil {
			b.WriteByte('#')
			for _, c := range r.opaque {
				b.WriteByte(upperHex[c>>4])
				b.WriteByte(upperHex[c&0xf])
			}
			continue
		}
		escapeValue(&b, r.val)
	}
	return DNString(b.String())
}

func (d DN) String() string { return string(d.Render()) }

func escapeValue(b *strings.Builder, v string) {
	last := len(v) - 1
	for i := 0; i < len(v); {
		r, n := utf8.DecodeRuneInString(v[i:])
		switch {
		case r == ' ' && (i == 0 || i+n-1 == last):
			b.WriteString(`\ `)
		case r == '#' && i == 0:
			b.WriteString(`\#`)
		case r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';':
			b.WriteByte('\\')
			b.WriteByte(byte(r))
		case r < 0x20 || r == 0x7f || r == '=' || r == '/':
			b.WriteByte('\\')
			b.WriteByte(upperHex[r>>4])
			b.WriteByte(upperHex[r&0xf])
		default:
			b.WriteString(v[i : i+n])
		}
		i += n
	}
}

// CanonicalString is the RFC 4514 text with every RDN-value escape applied; it lets a DN be the
// value of a DN-syntax filter term (ldapfilter.DN).
func (d DN) CanonicalString() string { return string(d.Render()) }
