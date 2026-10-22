// Package secret holds Secret, the one type secret material travels in (safe-primitives §5.6, R7).
//
// A Secret is built from bytes, never from a Go string, because a Go string cannot be zeroed. It
// prints as [REDACTED] under every fmt verb and in structured logs, it refuses to be serialised, it
// compares in constant time, and it has no method that returns a string. The bytes leave it only
// through Expose, to a callback that must not keep them.
//
// JSON decoding is encoding/json/v2 only: Secret implements UnmarshalJSONFrom (unmarshal.go) and
// deliberately has no v1 UnmarshalJSON or MarshalJSON.
package secret

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
)

// Redacted is what a Secret prints as.
const Redacted = "[REDACTED]"

// Error codes of this package. They are stable: the corpus and API problem types key on them.
const (
	NulInSecret    = "NulInSecret"
	InvalidUTF8    = "InvalidUTF8"
	InvalidUTF16   = "InvalidUTF16"
	EmptySecret    = "EmptySecret"
	TooLong        = "TooLong"
	Unserializable = "Unserializable"
	MalformedJSON  = "MalformedJSON"
)

// Error is a failure with a stable code. It never carries the secret or any part of it.
type Error struct{ Code string }

func (e *Error) Error() string { return "secret: " + e.Code }

// New returns the error with the given code.
func New(code string) error { return &Error{Code: code} }

// Code returns the stable code of err, or "" when err is not a secret error.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Secret is secret bytes. The zero value is the empty secret. Copying a Secret copies the slice
// header, not the bytes: Destroy zeroes the shared backing array.
type Secret struct{ b []byte }

// FromBytes copies b into a new Secret. The caller still owns, and should zero, b.
func FromBytes(b []byte) Secret {
	if len(b) == 0 {
		return Secret{}
	}
	return Secret{b: append(make([]byte, 0, len(b)), b...)}
}

// adopt wraps a buffer the package allocated itself.
func adopt(b []byte) Secret { return Secret{b: b} }

// IsEmpty reports whether the Secret holds no bytes.
func (s Secret) IsEmpty() bool { return len(s.b) == 0 }

// Expose calls fn with the secret bytes. fn must not retain, copy into a string, or log them.
func (s Secret) Expose(fn func(b []byte)) { fn(s.b) }

// Equal compares in constant time for equal lengths. Lengths are not secret here.
func (s Secret) Equal(o Secret) bool { return subtle.ConstantTimeCompare(s.b, o.b) == 1 }

// Destroy zeroes the backing array and empties the Secret.
func (s *Secret) Destroy() {
	clear(s.b)
	s.b = nil
}

// Format prints [REDACTED] for every verb, %#v and %+v included.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Redacted)) }

// LogValue makes slog print [REDACTED] without going through Format.
func (s Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalText fails: a Secret is never serialised (v1 encoding/json, XML and YAML reach this).
func (s Secret) MarshalText() ([]byte, error) { return nil, New(Unserializable) }

// MarshalBinary fails: neither gob nor any binary encoder may carry a Secret.
func (s Secret) MarshalBinary() ([]byte, error) { return nil, New(Unserializable) }
