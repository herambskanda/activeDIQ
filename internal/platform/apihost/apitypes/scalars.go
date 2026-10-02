package apitypes

import (
	"encoding/json/jsontext"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// readString reads one JSON string token. A wrong JSON type is a type violation.
func readString(d *jsontext.Decoder) (string, error) {
	tok, err := d.ReadToken()
	if err != nil {
		return "", err
	}
	if tok.Kind() != '"' {
		return "", violation(d, CodeType, "expected a string")
	}
	return tok.String(), nil
}

// UUID is a 128-bit identifier (format: uuid). Either case decodes; lowercase is always encoded
// (RFC 9562 §4).
type UUID [16]byte

// ParseUUID parses the canonical 8-4-4-4-12 form, either case.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("not a UUID")
	}
	j := 0
	for i := 0; i < 36; {
		if s[i] == '-' {
			i++
			continue
		}
		hi, ok1 := unhex(s[i])
		lo, ok2 := unhex(s[i+1])
		if !ok1 || !ok2 {
			return UUID{}, fmt.Errorf("not a UUID")
		}
		u[j] = hi<<4 | lo
		j++
		i += 2
	}
	return u, nil
}

func unhex(c byte) (byte, bool) {
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

// String returns the lowercase canonical form.
func (u UUID) String() string {
	const hexd = "0123456789abcdef"
	var b [36]byte
	j := 0
	for i, x := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			b[j] = '-'
			j++
		}
		b[j], b[j+1] = hexd[x>>4], hexd[x&0xf]
		j += 2
	}
	return string(b[:])
}

// IsZero reports the nil UUID. omitzero uses it.
func (u UUID) IsZero() bool { return u == UUID{} }

func (u *UUID) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	s, err := readString(d)
	if err != nil {
		return err
	}
	v, perr := ParseUUID(s)
	if perr != nil {
		return violation(d, CodeFormat, "expected a UUID")
	}
	*u = v
	return nil
}

func (u UUID) MarshalJSONTo(e *jsontext.Encoder) error {
	return e.WriteToken(jsontext.String(u.String()))
}

// Date is a calendar date (format: date), full-date only.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// ParseDate parses YYYY-MM-DD and refuses a date that does not exist.
func ParseDate(s string) (Date, error) {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return Date{}, fmt.Errorf("not a date")
	}
	for i, c := range []byte(s) {
		if i != 4 && i != 7 && (c < '0' || c > '9') {
			return Date{}, fmt.Errorf("not a date")
		}
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return Date{}, err
	}
	return Date{t.Year(), t.Month(), t.Day()}, nil
}

func (dt Date) String() string { return fmt.Sprintf("%04d-%02d-%02d", dt.Year, int(dt.Month), dt.Day) }

// IsZero reports the zero Date. omitzero uses it.
func (dt Date) IsZero() bool { return dt == Date{} }

func (dt *Date) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	s, err := readString(d)
	if err != nil {
		return err
	}
	v, perr := ParseDate(s)
	if perr != nil {
		return violation(d, CodeFormat, "expected a date, YYYY-MM-DD")
	}
	*dt = v
	return nil
}

func (dt Date) MarshalJSONTo(e *jsontext.Encoder) error {
	return e.WriteToken(jsontext.String(dt.String()))
}

// Timestamp is an instant (format: date-time). RFC 3339 with any offset decodes to UTC and encodes
// with Z. time.Time never appears in a contract type.
type Timestamp struct{ t time.Time }

// NewTimestamp returns the instant of t in UTC.
func NewTimestamp(t time.Time) Timestamp { return Timestamp{t.UTC()} }

// Time returns the instant, in UTC.
func (ts Timestamp) Time() time.Time { return ts.t }

// IsZero reports the zero Timestamp. omitzero uses it.
func (ts Timestamp) IsZero() bool { return ts.t.IsZero() }

// ParseTimestamp parses RFC 3339.
func ParseTimestamp(s string) (Timestamp, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return Timestamp{}, err
	}
	return Timestamp{t.UTC()}, nil
}

func (ts Timestamp) String() string { return ts.t.UTC().Format(time.RFC3339Nano) }

func (ts *Timestamp) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	s, err := readString(d)
	if err != nil {
		return err
	}
	v, perr := ParseTimestamp(s)
	if perr != nil {
		return violation(d, CodeFormat, "expected an RFC 3339 date-time")
	}
	*ts = v
	return nil
}

func (ts Timestamp) MarshalJSONTo(e *jsontext.Encoder) error {
	return e.WriteToken(jsontext.String(ts.String()))
}

// Int64String carries an integer outside JavaScript's safe range as a string: ^-?[0-9]{1,19}$
// that fits in int64.
type Int64String int64

// ParseInt64String parses the wire form.
func ParseInt64String(s string) (Int64String, error) {
	digits := strings.TrimPrefix(s, "-")
	if len(digits) == 0 || len(digits) > 19 {
		return 0, fmt.Errorf("not an int64 string")
	}
	for _, c := range []byte(digits) {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not an int64 string")
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return Int64String(n), nil
}

func (n *Int64String) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	s, err := readString(d)
	if err != nil {
		return err
	}
	v, perr := ParseInt64String(s)
	if perr != nil {
		return violation(d, CodeFormat, "expected a 64-bit integer as a string")
	}
	*n = v
	return nil
}

func (n Int64String) MarshalJSONTo(e *jsontext.Encoder) error {
	return e.WriteToken(jsontext.String(strconv.FormatInt(int64(n), 10)))
}
