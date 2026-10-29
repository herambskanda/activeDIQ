package apitypes

import (
	"fmt"
	"log/slog"
)

// CookieValue is the value of a cookie parameter. A cookie can carry a bearer handle (the pending
// sign-in), so it prints as [REDACTED] under every fmt verb, in slog and in JSON, and the text leaves
// it only through Reveal, called where the value is checked. The zero value is an absent cookie.
type CookieValue struct{ v string }

// NewCookieValue wraps a raw cookie value.
func NewCookieValue(v string) CookieValue { return CookieValue{v: v} }

// Reveal returns the raw value. Call it only to parse or check the cookie; never log or wrap it.
func (c CookieValue) Reveal() string { return c.v }

// IsZero reports an absent (or empty) cookie.
func (c CookieValue) IsZero() bool { return c.v == "" }

const cookieRedacted = "[REDACTED]"

// Format prints [REDACTED] for every verb, %+v and %#v included.
func (c CookieValue) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(cookieRedacted)) }

// String is redacted.
func (c CookieValue) String() string { return cookieRedacted }

// GoString is redacted.
func (c CookieValue) GoString() string { return cookieRedacted }

// LogValue makes slog print [REDACTED].
func (c CookieValue) LogValue() slog.Value { return slog.StringValue(cookieRedacted) }

// MarshalText is redacted so no encoder (JSON v1/v2, YAML) carries the value.
func (c CookieValue) MarshalText() ([]byte, error) { return []byte(cookieRedacted), nil }
