// Package codec holds what every attribute codec under internal/directory/attr shares: the typed
// error with a stable code (safe-primitives §5 "Error X") and the RFC 4517 §3.3.16 integer grammar.
//
// A decode failure never carries the offending value: the value came from a directory or an admin
// and may be hostile, secret-adjacent or huge, so it is neither stored in the error nor printed.
package codec

import "errors"

// Error is a codec failure with a stable, documented code. Nothing was sent anywhere.
type Error struct{ Code string }

func (e *Error) Error() string { return "attr: " + e.Code }

// New returns the error with the given code.
func New(code string) error { return &Error{Code: code} }

// Code returns the stable code of err, or "" when err is not a codec error.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Codes shared by more than one codec.
const (
	BadFormat  = "BadFormat"
	BadInteger = "BadInteger"
	Overflow   = "Overflow"
	BadLength  = "BadLength"
)

// ParseInteger parses s under RFC 4517 §3.3.16 ("-" LDIGIT *DIGIT / number: no plus sign, no leading
// zero, no "-0", ASCII digits only) into a signed integer of the given bit size (32 or 64). The
// grammar is checked before the range, so a malformed value is BadInteger and a well-formed value
// outside the range is Overflow. It reads s once and allocates nothing.
func ParseInteger(s string, bits int) (int64, error) {
	if bits != 32 && bits != 64 {
		panic("codec.ParseInteger: bits must be 32 or 64")
	}
	i, neg := 0, false
	if len(s) > 0 && s[0] == '-' {
		neg = true
		i = 1
	}
	digits := s[i:]
	if len(digits) == 0 {
		return 0, New(BadInteger)
	}
	if digits[0] == '0' && (len(digits) > 1 || neg) { // leading zero, or -0
		return 0, New(BadInteger)
	}
	for j := 0; j < len(digits); j++ {
		if digits[j] < '0' || digits[j] > '9' {
			return 0, New(BadInteger)
		}
	}
	// The magnitude limit: 2^63 for a negative 64-bit value, 2^63-1 for a positive one, and 2^31 / 2^31-1 for 32.
	var limit uint64 = 1<<63 - 1
	if bits == 32 {
		limit = 1<<31 - 1
	}
	if neg {
		limit++
	}
	var n uint64
	for j := 0; j < len(digits); j++ {
		d := uint64(digits[j] - '0')
		if n > (limit-d)/10 { // n*10+d would exceed the limit
			return 0, New(Overflow)
		}
		n = n*10 + d
	}
	if neg {
		return int64(-n), nil // n == 2^63 wraps to -2^63, which is the right value
	}
	return int64(n), nil
}
