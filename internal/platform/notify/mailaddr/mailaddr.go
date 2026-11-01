// Package mailaddr is the one e-mail address parser of the platform (TM-D30 SX-7). An address is
// parsed strictly as a single addr-spec, and the canonical string it yields is the only string that
// is classified against the allowed recipient domains and the only string put on an SMTP RCPT TO.
// Classification and delivery therefore cannot disagree about what an address is (no parser
// differential).
//
// What is accepted: a dot-atom local part over a conservative subset of ASCII atext (RFC 5322
// §3.2.3; the legacy routing characters "%" and "!" are refused) and a DNS
// domain of at least two labels. The domain is converted with IDNA ToASCII (UTS 46, strict) and
// lowercased, so a Unicode lookalike classifies by its punycode form and is therefore not the
// ASCII domain it resembles.
//
// What is refused, with ErrInvalid: a display name, a quoted local part, a comment, a source route,
// an IP-literal or all-numeric domain, a second "@", CR, LF, NUL or any other control or space
// character, a non-ASCII local part (SMTPUTF8 is not offered), and anything over the RFC 5321
// length limits. Surrounding whitespace is not trimmed: it is refused.
package mailaddr

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
)

// ErrInvalid is returned for every refusal. It carries no part of the input: the input may be an
// attacker's string and the error is logged.
var ErrInvalid = errors.New("mailaddr: not a valid e-mail address")

// Limits of RFC 5321 §4.5.3.1.
const (
	maxLocal  = 64
	maxDomain = 253
	maxTotal  = 254
)

// Address is a parsed address in canonical form. The zero value is not valid.
type Address struct {
	local  string
	domain string
}

// Parse parses s as one addr-spec.
func Parse(s string) (Address, error) {
	if len(s) == 0 || len(s) > maxTotal*4 { // the cap bounds IDNA work on hostile input
		return Address{}, ErrInvalid
	}
	if strings.Count(s, "@") != 1 {
		return Address{}, ErrInvalid
	}
	local, dom, _ := strings.Cut(s, "@")
	if !validLocal(local) {
		return Address{}, ErrInvalid
	}
	d, err := NormalizeDomain(dom)
	if err != nil {
		return Address{}, err
	}
	a := Address{local: local, domain: d}
	if len(a.String()) > maxTotal {
		return Address{}, ErrInvalid
	}
	return a, nil
}

// NormalizeDomain returns the canonical form of a domain: IDNA ToASCII, lower case, at least two
// labels, a non-numeric last label. It is also how an allowed-domain entry is canonicalised, so an
// entry and an address domain compare as strings. A leading dot, a wildcard or an "@" is refused:
// a subdomain matches only through its own entry.
func NormalizeDomain(s string) (string, error) {
	if s == "" || len(s) > maxDomain*4 {
		return "", ErrInvalid
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c <= ' ' || c == 0x7f: // controls, space, CR, LF, NUL
			return "", ErrInvalid
		case c == '@' || c == '*' || c == '[' || c == ']' || c == ':' || c == '/' || c == '\\' || c == '<' || c == '>' || c == '"' || c == '(' || c == ')' || c == ',' || c == ';' || c == '%':
			return "", ErrInvalid
		}
	}
	// A trailing dot is a different string for the same name; refuse it rather than strip it.
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return "", ErrInvalid
	}
	d, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", ErrInvalid
	}
	d = strings.ToLower(d)
	if len(d) == 0 || len(d) > maxDomain || !asciiHostname(d) {
		return "", ErrInvalid
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 || allDigits(labels[len(labels)-1]) {
		return "", ErrInvalid // a single label, or an IPv4-looking name
	}
	return d, nil
}

func asciiHostname(d string) bool {
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// validLocal reports whether s is a dot-atom over letters, digits and a conservative subset of
// atext. "%" and "!" (the percent hack and UUCP bang paths, which some relays still read as routing)
// and the characters that mean something to a shell or an alias file are left out on purpose.
func validLocal(s string) bool {
	if s == "" || len(s) > maxLocal || s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.':
		case strings.IndexByte("_-+='&", c) >= 0: // a conservative subset of atext
		default:
			return false
		}
	}
	return true
}

// String is the canonical form: the local part as given, the domain in lower-case ASCII. This is
// the string for RCPT TO and the string that is classified. The zero Address returns "".
func (a Address) String() string {
	if a.domain == "" {
		return ""
	}
	return a.local + "@" + a.domain
}

// Domain is the canonical (punycode, lower-case) domain.
func (a Address) Domain() string { return a.domain }

// Local is the local part.
func (a Address) Local() string { return a.local }

// IsZero reports whether a is the zero Address.
func (a Address) IsZero() bool { return a.domain == "" }
