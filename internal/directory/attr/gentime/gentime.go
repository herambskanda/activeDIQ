// Package gentime is the one codec for Generalized Time (syntax 2.5.5.11, oMSyntax 24;
// safe-primitives §5.4) and, separately, UTC-Time (oMSyntax 23, two-digit years).
//
// Decode accepts the full RFC 4517 §3.3.13 grammar (hour-only, minutes, a fraction with "." or ",",
// "Z" or a ±hh[mm] offset) and returns a UTC instant. A zone is mandatory (local time is
// ambiguous), a leap second is refused rather than shifted, and the input is ASCII only and at most
// 64 characters. Encode always writes AD's observed form, YYYYMMDDHHMMSS.0Z in UTC, truncating
// sub-seconds so ">=" window filters stay inclusive.
package gentime

import (
	"math/bits"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
)

// Error codes.
const (
	BadFormat             = codec.BadFormat
	TooLong               = "TooLong"
	MissingTimeZone       = "MissingTimeZone"
	BadMonth              = "BadMonth"
	BadDay                = "BadDay"
	BadHour               = "BadHour"
	BadMinute             = "BadMinute"
	BadSecond             = "BadSecond"
	LeapSecondUnsupported = "LeapSecondUnsupported"
	BadOffset             = "BadOffset"
	BadFraction           = "BadFraction"
	OutOfRange            = "OutOfRange" // the UTC instant is outside years 0000 to 9999
)

const maxLen = 64

// Parse decodes a Generalized Time value to a UTC instant.
func Parse(s string) (time.Time, error) {
	return parse(s, false)
}

// ParseUTCTime decodes a UTC-Time value (YYMMDDhhmm[ss] then Z or ±hhmm). Years 50 to 99 are 19yy
// and 00 to 49 are 20yy, the X.509 pivot (RFC 5280 §4.1.2.5.1); AD's use of the two-digit form is
// not documented [UNVERIFIED], so the pivot is the convention, not an observed behaviour.
func ParseUTCTime(s string) (time.Time, error) {
	return parse(s, true)
}

// OMSyntax values of the two time syntaxes that share syntax OID 2.5.5.11.
const (
	OMSyntaxUTCTime         = 23
	OMSyntaxGeneralizedTime = 24
)

// UnknownSyntax is returned by Decode for an oMSyntax that is not a time syntax.
const UnknownSyntax = "UnknownSyntax"

// Decode picks the decoder from the attribute's oMSyntax (schema), as the two forms overlap
// lexically: "261002101112Z" is a valid Generalized Time (year 2610) as well as a UTC-Time (2026).
// Never choose by looking at the text.
func Decode(omSyntax int, s string) (time.Time, error) {
	switch omSyntax {
	case OMSyntaxGeneralizedTime:
		return Parse(s)
	case OMSyntaxUTCTime:
		return ParseUTCTime(s)
	}
	return time.Time{}, codec.New(UnknownSyntax)
}

type cursor struct {
	s string
	p int
}

func (c *cursor) digits(n int) (int, bool) {
	if c.p+n > len(c.s) {
		return 0, false
	}
	v := 0
	for i := 0; i < n; i++ {
		ch := c.s[c.p+i]
		if ch < '0' || ch > '9' {
			return 0, false
		}
		v = v*10 + int(ch-'0')
	}
	c.p += n
	return v, true
}

func (c *cursor) peekDigit() bool {
	return c.p < len(c.s) && c.s[c.p] >= '0' && c.s[c.p] <= '9'
}

func (c *cursor) done() bool { return c.p >= len(c.s) }

func parse(s string, utcTime bool) (time.Time, error) {
	if len(s) > maxLen {
		return time.Time{}, codec.New(TooLong)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e { // NUL, controls and every non-ASCII byte
			return time.Time{}, codec.New(BadFormat)
		}
	}
	c := &cursor{s: s}
	var year int
	var ok bool
	if utcTime {
		yy, ok := c.digits(2)
		if !ok {
			return time.Time{}, codec.New(BadFormat)
		}
		year = 2000 + yy
		if yy >= 50 {
			year = 1900 + yy
		}
	} else if year, ok = c.digits(4); !ok {
		return time.Time{}, codec.New(BadFormat)
	}
	month, ok1 := c.digits(2)
	day, ok2 := c.digits(2)
	hour, ok3 := c.digits(2)
	if !ok1 || !ok2 || !ok3 {
		return time.Time{}, codec.New(BadFormat)
	}
	// unit is the length of the last time component present: a fraction applies to it.
	unit := time.Hour
	minute, second := 0, 0
	if utcTime { // minutes are mandatory, seconds optional, and there is no fraction
		m, ok := c.digits(2)
		if !ok {
			return time.Time{}, codec.New(BadFormat)
		}
		minute = m
		if c.peekDigit() {
			sec, ok := c.digits(2)
			if !ok {
				return time.Time{}, codec.New(BadFormat)
			}
			second = sec
		}
	} else if c.peekDigit() {
		m, ok := c.digits(2)
		if !ok {
			return time.Time{}, codec.New(BadFormat)
		}
		minute, unit = m, time.Minute
		if c.peekDigit() {
			sec, ok := c.digits(2)
			if !ok {
				return time.Time{}, codec.New(BadFormat)
			}
			second, unit = sec, time.Second
		}
	}
	var fracNS int64
	if !utcTime && !c.done() && (s[c.p] == '.' || s[c.p] == ',') {
		c.p++
		start := c.p
		for c.peekDigit() {
			c.p++
		}
		if c.p == start {
			return time.Time{}, codec.New(BadFraction)
		}
		fracNS = fraction(s[start:c.p], int64(unit))
	}
	if c.done() {
		return time.Time{}, codec.New(MissingTimeZone)
	}
	offset, err := zone(c)
	if err != nil {
		return time.Time{}, err
	}
	if !c.done() {
		return time.Time{}, codec.New(BadFormat)
	}
	// Calendar checks after the whole value has been read, so malformed text is BadFormat first.
	switch {
	case month < 1 || month > 12:
		return time.Time{}, codec.New(BadMonth)
	case day < 1 || day > daysIn(year, month):
		return time.Time{}, codec.New(BadDay)
	case hour > 23:
		return time.Time{}, codec.New(BadHour)
	case minute > 59:
		return time.Time{}, codec.New(BadMinute)
	case second == 60:
		return time.Time{}, codec.New(LeapSecondUnsupported)
	case second > 60:
		return time.Time{}, codec.New(BadSecond)
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC)
	t = t.Add(time.Duration(fracNS)).Add(-offset)
	if y := t.Year(); y < 0 || y > 9999 {
		return time.Time{}, codec.New(OutOfRange)
	}
	return t, nil
}

// zone reads "Z" or ("+"|"-") hh [mm] and returns the offset east of UTC.
func zone(c *cursor) (time.Duration, error) {
	switch c.s[c.p] {
	case 'Z':
		c.p++
		return 0, nil
	case '+', '-':
		sign := time.Duration(1)
		if c.s[c.p] == '-' {
			sign = -1
		}
		c.p++
		hh, ok := c.digits(2)
		if !ok || hh > 23 {
			return 0, codec.New(BadOffset)
		}
		mm := 0
		if !c.done() {
			if mm, ok = c.digits(2); !ok || mm > 59 {
				return 0, codec.New(BadOffset)
			}
		}
		return sign * (time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute), nil
	}
	return 0, codec.New(BadFormat)
}

// fraction returns floor(0.digits * unit) in nanoseconds with exact integer arithmetic. At most 18
// digits are read: the rest is below a nanosecond for any unit up to an hour.
func fraction(digits string, unit int64) int64 {
	if len(digits) > 18 {
		digits = digits[:18]
	}
	var num, den uint64 = 0, 1
	for i := 0; i < len(digits); i++ {
		num = num*10 + uint64(digits[i]-'0')
		den *= 10
	}
	hi, lo := bits.Mul64(num, uint64(unit))
	q, _ := bits.Div64(hi, lo, den) // hi < den because unit < 2^64 and num < den
	return int64(q)
}

func daysIn(year, month int) int {
	return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// Format encodes t as YYYYMMDDHHMMSS.0Z in UTC, truncating sub-seconds. A time whose UTC year is
// outside 0000 to 9999 is OutOfRange: the form has four digits.
func Format(t time.Time) (string, error) {
	t = t.UTC()
	if y := t.Year(); y < 0 || y > 9999 {
		return "", codec.New(OutOfRange)
	}
	return t.Format("20060102150405") + ".0Z", nil
}
