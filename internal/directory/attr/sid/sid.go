// Package sid is the one codec for objectSid, sIDHistory and tokenGroups values (safe-primitives
// §5.2): the MS-DTYP 2.4.2.2 binary form and the 2.4.2.1 text form. Both are strict: the declared
// length is checked, never assumed, and text that Windows would parse but that has more than one
// spelling (leading zeros, hex authority below 2^32) is refused so a SID has one text.
package sid

import (
	"encoding/binary"
	"strconv"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
)

// Error codes.
const (
	BadFormat             = codec.BadFormat
	UnsupportedRevision   = "UnsupportedRevision"
	TooManySubAuthorities = "TooManySubAuthorities"
	Truncated             = "Truncated"
	TrailingBytes         = "TrailingBytes"
	SubAuthorityOverflow  = "SubAuthorityOverflow"
	LeadingZero           = "LeadingZero"
	NonCanonicalAuthority = "NonCanonicalAuthority"
	NoSubAuthority        = "NoSubAuthority"
)

const (
	revision   = 1
	maxSubs    = 15
	headerLen  = 8
	maxTextLen = 4 + 14 + maxSubs*11 // "S-1-" + "0x"+12 hex + 15 x ("-" + 10 digits)
)

// SID is a security identifier. The zero value is not a valid SID.
type SID struct {
	authority uint64 // 48 bits
	subs      [maxSubs]uint32
	n         uint8
}

// FromBytes decodes the binary form. The length is the one the value declares: a short value is
// Truncated and a long one TrailingBytes.
func FromBytes(b []byte) (SID, error) {
	var s SID
	if len(b) < headerLen {
		return s, codec.New(Truncated)
	}
	if b[0] != revision {
		return s, codec.New(UnsupportedRevision)
	}
	if b[1] > maxSubs {
		return s, codec.New(TooManySubAuthorities)
	}
	n := int(b[1])
	if n == 0 {
		return s, codec.New(NoSubAuthority)
	}
	want := headerLen + 4*n
	if len(b) < want {
		return s, codec.New(Truncated)
	}
	if len(b) > want {
		return s, codec.New(TrailingBytes)
	}
	for _, c := range b[2:8] {
		s.authority = s.authority<<8 | uint64(c)
	}
	for i := 0; i < n; i++ {
		s.subs[i] = binary.LittleEndian.Uint32(b[headerLen+4*i:])
	}
	s.n = uint8(n)
	return s, nil
}

// Bytes returns the binary form; filters use it escaped byte by byte, never the text.
func (s SID) Bytes() []byte {
	b := make([]byte, headerLen+4*int(s.n))
	b[0] = revision
	b[1] = s.n
	for i := 0; i < 6; i++ {
		b[2+i] = byte(s.authority >> (8 * (5 - i)))
	}
	for i := 0; i < int(s.n); i++ {
		binary.LittleEndian.PutUint32(b[headerLen+4*i:], s.subs[i])
	}
	return b
}

// String is the canonical text: upper-case S, decimal authority below 2^32, "0x" and twelve
// lower-case hex digits at or above it, decimal sub-authorities.
func (s SID) String() string {
	out := make([]byte, 0, maxTextLen)
	out = append(out, "S-1-"...)
	if s.authority < 1<<32 {
		out = strconv.AppendUint(out, s.authority, 10)
	} else {
		out = append(out, "0x"...)
		h := strconv.AppendUint(nil, s.authority, 16)
		for i := len(h); i < 12; i++ {
			out = append(out, '0')
		}
		out = append(out, h...)
	}
	for i := 0; i < int(s.n); i++ {
		out = append(out, '-')
		out = strconv.AppendUint(out, uint64(s.subs[i]), 10)
	}
	return string(out)
}

// DomainSID is the SID without its last sub-authority (the domain of an account or group SID).
// ok is false for a SID with a single sub-authority, which has no domain part.
func (s SID) DomainSID() (SID, bool) {
	if s.n < 2 {
		return SID{}, false
	}
	d := s
	d.n--
	d.subs[d.n] = 0
	return d, true
}

// RID is the last sub-authority; ok is false for a SID with a single sub-authority.
func (s SID) RID() (uint32, bool) {
	if s.n < 2 {
		return 0, false
	}
	return s.subs[s.n-1], true
}

// Parse reads the text form. Only "S-1-" is a revision (S or s); the authority is decimal below
// 2^32 and "0x" plus exactly twelve hex digits at or above it; there is at least one sub-authority.
func Parse(text string) (SID, error) {
	var s SID
	if len(text) > maxTextLen {
		return s, codec.New(BadFormat)
	}
	if len(text) < 2 || (text[0] != 'S' && text[0] != 's') || text[1] != '-' {
		return s, codec.New(BadFormat)
	}
	rest := text[2:]
	// revision
	rev, rest, more := cut(rest)
	if !allDigits(rev) || rev == "" {
		return s, codec.New(BadFormat)
	}
	if rev != "1" {
		return s, codec.New(UnsupportedRevision)
	}
	if !more {
		return s, codec.New(BadFormat)
	}
	// authority
	var auth string
	auth, rest, more = cut(rest)
	a, err := parseAuthority(auth)
	if err != nil {
		return s, err
	}
	s.authority = a
	if !more {
		return s, codec.New(NoSubAuthority)
	}
	for more {
		var sub string
		sub, rest, more = cut(rest)
		if s.n == maxSubs {
			return SID{}, codec.New(TooManySubAuthorities)
		}
		v, err := parseSub(sub)
		if err != nil {
			return SID{}, err
		}
		s.subs[s.n] = v
		s.n++
	}
	return s, nil
}

// cut splits at the first dash; more reports that a dash was found.
func cut(s string) (head, tail string, more bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func parseAuthority(s string) (uint64, error) {
	if len(s) >= 2 && s[0] == '0' && s[1] == 'x' {
		h := s[2:]
		if len(h) != 12 {
			return 0, codec.New(BadFormat)
		}
		var v uint64
		for i := 0; i < len(h); i++ {
			d, ok := hexDigit(h[i])
			if !ok {
				return 0, codec.New(BadFormat)
			}
			v = v<<4 | uint64(d)
		}
		if v < 1<<32 {
			return 0, codec.New(NonCanonicalAuthority) // hex is only for 2^32 and above
		}
		return v, nil
	}
	if s == "" || !allDigits(s) {
		return 0, codec.New(BadFormat)
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, codec.New(LeadingZero)
	}
	if len(s) > 10 {
		return 0, codec.New(NonCanonicalAuthority)
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	if v >= 1<<32 {
		return 0, codec.New(NonCanonicalAuthority) // decimal is only below 2^32
	}
	return v, nil
}

func parseSub(s string) (uint32, error) {
	if s == "" || !allDigits(s) {
		return 0, codec.New(BadFormat)
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, codec.New(LeadingZero)
	}
	if len(s) > 10 {
		return 0, codec.New(SubAuthorityOverflow)
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	if v > 1<<32-1 {
		return 0, codec.New(SubAuthorityOverflow)
	}
	return uint32(v), nil
}

func hexDigit(c byte) (byte, bool) {
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
