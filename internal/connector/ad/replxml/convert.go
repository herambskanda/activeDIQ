package replxml

import "time"

func isXMLSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func trim(s string) string {
	for len(s) > 0 && isXMLSpace(s[0]) {
		s = s[1:]
	}
	for len(s) > 0 && isXMLSpace(s[len(s)-1]) {
		s = s[:len(s)-1]
	}
	return s
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

// parseGUID accepts only the canonical 36-character dashed form, read left to right (rule 9).
func parseGUID(s string) (Guid, *DecodeError) {
	s = trim(s)
	if len(s) != 36 {
		return Guid{}, fail(CodeBadGUID)
	}
	var g Guid
	o := 0
	for i := 0; i < 36; {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return Guid{}, fail(CodeBadGUID)
			}
			i++
			continue
		}
		hi, ok1 := hexVal(s[i])
		lo, ok2 := hexVal(s[i+1])
		if !ok1 || !ok2 {
			return Guid{}, fail(CodeBadGUID)
		}
		g.b[o] = hi<<4 | lo
		o++
		i += 2
	}
	g.set = true
	return g, nil
}

func digits(s string, n int) (int, bool) {
	v := 0
	for i := 0; i < n; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	return v, true
}

// filetimeZero is FILETIME 0.
const filetimeZero = "1601-01-01T00:00:00Z"

// parseTime accepts only YYYY-MM-DDThh:mm:ss[.f{1,7}]Z in UTC with a real calendar date and year
// 1601 or later. Anything else is bad_time: never zero, never now (X5).
func parseTime(s string) (Time, *DecodeError) {
	s = trim(s)
	if s == filetimeZero {
		return Time{Kind: TimeZero}, nil
	}
	if len(s) < 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[len(s)-1] != 'Z' {
		return Time{}, fail(CodeBadTime)
	}
	y, ok1 := digits(s[0:], 4)
	mo, ok2 := digits(s[5:], 2)
	d, ok3 := digits(s[8:], 2)
	h, ok4 := digits(s[11:], 2)
	mi, ok5 := digits(s[14:], 2)
	se, ok6 := digits(s[17:], 2)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
		return Time{}, fail(CodeBadTime)
	}
	ns := 0
	if rest := s[19 : len(s)-1]; rest != "" {
		if rest[0] != '.' || len(rest) < 2 || len(rest) > 8 {
			return Time{}, fail(CodeBadTime)
		}
		frac, ok := digits(rest[1:], len(rest)-1)
		if !ok {
			return Time{}, fail(CodeBadTime)
		}
		for i := len(rest) - 1; i < 9; i++ {
			frac *= 10
		}
		ns = frac
	}
	if y < 1601 || mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59 {
		return Time{}, fail(CodeBadTime)
	}
	t := time.Date(y, time.Month(mo), d, h, mi, se, ns, time.UTC)
	if t.Day() != d || int(t.Month()) != mo { // 31 February and friends
		return Time{}, fail(CodeBadTime)
	}
	return Time{Kind: TimeAt, At: t}, nil
}

func parseUint(s string, bits int) (uint64, *DecodeError) {
	s = trim(s)
	maxDigits := 10
	if bits == 64 {
		maxDigits = 20
	}
	if s == "" || len(s) > maxDigits {
		return 0, fail(CodeBadNumber)
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fail(CodeBadNumber)
		}
		dgt := uint64(c - '0')
		if bits == 64 {
			if v > (^uint64(0)-dgt)/10 {
				return 0, fail(CodeBadNumber)
			}
		} else if v*10+dgt > 0xFFFFFFFF {
			return 0, fail(CodeBadNumber)
		}
		v = v*10 + dgt
	}
	return v, nil
}

// reader converts the raw fields of a parsed document; the first error wins.
type reader struct {
	p   *parsed
	err *DecodeError
}

func (r *reader) has(name string) (string, bool) {
	s, ok := r.p.text[name]
	return s, ok && r.err == nil
}

func (r *reader) guid(name string) Guid {
	s, ok := r.has(name)
	if !ok {
		return Guid{}
	}
	g, e := parseGUID(s)
	r.err = e
	return g
}

func (r *reader) time(name string) Time {
	s, ok := r.has(name)
	if !ok {
		return Time{}
	}
	t, e := parseTime(s)
	r.err = e
	return t
}

func (r *reader) u32(name string) U32 {
	s, ok := r.has(name)
	if !ok {
		return U32{}
	}
	v, e := parseUint(s, 32)
	r.err = e
	return U32{V: uint32(v), Set: e == nil}
}

func (r *reader) u64(name string) U64 {
	s, ok := r.has(name)
	if !ok {
		return U64{}
	}
	v, e := parseUint(s, 64)
	r.err = e
	return U64{V: v, Set: e == nil}
}

func (r *reader) text(name string) string {
	s, _ := r.has(name)
	return s
}
