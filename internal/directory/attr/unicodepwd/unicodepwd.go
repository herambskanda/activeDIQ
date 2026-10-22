// Package unicodepwd is the encode-only codec for the unicodePwd attribute (safe-primitives §5.6).
//
// AD never returns unicodePwd, so there is no decoder. The value is the UTF-16LE of '"' + password +
// '"'; the quotes are not part of the password and nothing inside the password is stripped or
// unquoted. The only way to a modify that carries it is Replace or Change, and both demand a
// SecureConn, the proof that the connection is encrypted and authenticated (secureconn.go).
//
// The password is read from a secret.Secret (bytes, never a Go string) and written into one
// pre-sized buffer; the caller zeroes the returned Modify with Destroy once it is sent.
package unicodepwd

import (
	"encoding/json/jsontext"
	"fmt"
	"log/slog"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// Attribute is the LDAP attribute name; this package is its only home outside the connector.
const Attribute = "unicodePwd"

// MaxUnits is the cap on the password in UTF-16 code units, quotes excluded. Provisional: the
// Windows maximum is [UNVERIFIED] (safe-primitives §5.6 PW-09).
const MaxUnits = 256

// Codes of this package. The secret package's codes (InvalidUTF8, NulInSecret, EmptySecret, TooLong)
// are returned as they are.
const (
	EncryptionRequired    = "EncryptionRequired"
	SecureConnStale       = "SecureConnStale"
	TLSVerificationFailed = "TLSVerificationFailed"
	PolicyViolation       = "PolicyViolation"
)

// Code returns the stable code of a secret or codec error, or "".
func Code(err error) string {
	if c := secret.Code(err); c != "" {
		return c
	}
	return codec.Code(err)
}

// Encode returns the unicodePwd value for s: UTF-16LE of '"' + s + '"'.
func Encode(s secret.Secret) ([]byte, error) {
	var out []byte
	var err error
	s.Expose(func(pw []byte) { out, err = encode(pw) })
	return out, err
}

func encode(pw []byte) ([]byte, error) {
	if len(pw) == 0 {
		return nil, secret.New(secret.EmptySecret)
	}
	// One validating pass counts the UTF-16 units, so the buffer is exact and never grown.
	units := 0
	for i := 0; i < len(pw); {
		r, n := utf8.DecodeRune(pw[i:])
		switch {
		case r == 0:
			return nil, secret.New(secret.NulInSecret)
		case r == utf8.RuneError && n <= 1: // also catches encoded surrogates (ed a0 80)
			return nil, secret.New(secret.InvalidUTF8)
		}
		units++
		if r >= 0x10000 {
			units++
		}
		i += n
	}
	if units > MaxUnits {
		return nil, secret.New(secret.TooLong)
	}
	out := make([]byte, 0, 2*(units+2))
	out = append(out, '"', 0)
	for i := 0; i < len(pw); {
		r, n := utf8.DecodeRune(pw[i:])
		i += n
		if r >= 0x10000 {
			r -= 0x10000
			hi, lo := 0xD800+uint16(r>>10), 0xDC00+uint16(r&0x3FF)
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
			continue
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return append(out, '"', 0), nil
}

// Op is the modify operation of a Change entry.
type Op string

const (
	OpReplace Op = "replace"
	OpDelete  Op = "delete"
	OpAdd     Op = "add"
)

// Modification is one entry of an LDAP modify: the attribute, the operation and the encoded values.
// The values are an encoded password, so they are held as Secrets in an unexported field: they print
// as nothing under any fmt verb or slog handler, never serialise, and leave only through Expose.
type Modification struct {
	Op   Op
	Attr string
	vals []secret.Secret
}

// Expose calls fn with the encoded values for the wire write. fn must not retain or log them.
func (m Modification) Expose(fn func(values [][]byte)) {
	out := make([][]byte, 0, len(m.vals))
	var walk func(i int)
	walk = func(i int) {
		if i == len(m.vals) {
			fn(out)
			return
		}
		m.vals[i].Expose(func(b []byte) {
			out = append(out, b)
			walk(i + 1)
		})
	}
	walk(0)
}

// Format prints the entry without its values: they are an encoded password.
func (m Modification) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "{%s %s [%d value(s) redacted]}", m.Op, m.Attr, len(m.vals))
}

// LogValue keeps the values out of structured logs.
func (m Modification) LogValue() slog.Value {
	return slog.StringValue(fmt.Sprintf("%s %s [%d value(s) redacted]", m.Op, m.Attr, len(m.vals)))
}

// MarshalJSONTo fails with Unserializable: a pending password write is never persisted (v2 JSON).
func (Modification) MarshalJSONTo(*jsontext.Encoder) error { return secret.New(secret.Unserializable) }

// MarshalText fails with Unserializable (v1 encoding/json, XML and YAML reach this).
func (Modification) MarshalText() ([]byte, error) { return nil, secret.New(secret.Unserializable) }

// MarshalBinary fails with Unserializable (gob and other binary encoders).
func (Modification) MarshalBinary() ([]byte, error) { return nil, secret.New(secret.Unserializable) }

// Modify is the modify request body the connector sends. Destroy it after sending. It remembers
// the SecureConn it was built for: call Verify immediately before writing it (PW-17).
type Modify struct {
	Mods []Modification
	conn SecureConn
}

// Verify re-checks the connection the Modify was built for. A reconnect since Replace or Change is
// SecureConnStale. The connector must call it right before sending.
func (m *Modify) Verify() error { return m.conn.Verify() }

// Format prints the modify without its values.
func (m Modify) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "unicodepwd.Modify{%d modification(s), values redacted}", len(m.Mods))
}

// LogValue keeps the values out of structured logs.
func (m Modify) LogValue() slog.Value {
	return slog.StringValue(fmt.Sprintf("unicodepwd.Modify{%d modification(s), values redacted}", len(m.Mods)))
}

// MarshalJSONTo fails with Unserializable (v2 JSON).
func (Modify) MarshalJSONTo(*jsontext.Encoder) error { return secret.New(secret.Unserializable) }

// MarshalText fails with Unserializable.
func (Modify) MarshalText() ([]byte, error) { return nil, secret.New(secret.Unserializable) }

// MarshalBinary fails with Unserializable.
func (Modify) MarshalBinary() ([]byte, error) { return nil, secret.New(secret.Unserializable) }

// Destroy zeroes every encoded value.
func (m *Modify) Destroy() {
	for _, mod := range m.Mods {
		for i := range mod.vals {
			mod.vals[i].Destroy()
		}
	}
	m.Mods = nil
}

// encodeSecret encodes s into a Secret and zeroes the intermediate buffer.
func encodeSecret(s secret.Secret) (secret.Secret, error) {
	b, err := Encode(s)
	if err != nil {
		return secret.Secret{}, err
	}
	v := secret.FromBytes(b)
	clear(b)
	return v, nil
}

// Replace is the admin reset: the attribute is replaced with one value. Without a valid SecureConn
// it fails before anything is built (PW-10, PW-17).
func Replace(s secret.Secret, conn SecureConn) (*Modify, error) {
	if err := conn.Verify(); err != nil {
		return nil, err
	}
	v, err := encodeSecret(s)
	if err != nil {
		return nil, err
	}
	return &Modify{Mods: []Modification{{Op: OpReplace, Attr: Attribute, vals: []secret.Secret{v}}}, conn: conn}, nil
}

// Change is the user change: delete the old value and add the new one, in one modify.
func Change(oldPw, newPw secret.Secret, conn SecureConn) (*Modify, error) {
	if err := conn.Verify(); err != nil {
		return nil, err
	}
	o, err := encodeSecret(oldPw)
	if err != nil {
		return nil, err
	}
	n, err := encodeSecret(newPw)
	if err != nil {
		o.Destroy()
		return nil, err
	}
	return &Modify{Mods: []Modification{
		{Op: OpDelete, Attr: Attribute, vals: []secret.Secret{o}},
		{Op: OpAdd, Attr: Attribute, vals: []secret.Secret{n}},
	}, conn: conn}, nil
}

// LDAP result codes the DC uses for a password policy refusal.
const (
	resultConstraintViolation = 19
	resultUnwillingToPerform  = 53
)

// ClassifyResult turns a modify answer into PolicyViolation when the DC refused the password on
// policy grounds (19 or 53 with the Win32 error 0000052D, ERROR_PASSWORD_RESTRICTION), carrying the
// DC's diagnostic. Any other answer is not this package's to classify (nil). The diagnostic is the
// DC's text, never the request: the request bytes are not an input here, so they cannot be logged.
func ClassifyResult(code int, diagnostic string) error {
	if code != resultConstraintViolation && code != resultUnwillingToPerform {
		return nil
	}
	if !containsFold(diagnostic, "0000052D") {
		return nil
	}
	return fmt.Errorf("%w: %s", codec.New(PolicyViolation), sanitize(diagnostic))
}

func containsFold(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'a' && a <= 'z' {
				a -= 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// sanitize keeps printable ASCII and caps the length: the diagnostic is remote text.
func sanitize(s string) string {
	out := make([]byte, 0, min(len(s), 200))
	for i := 0; i < len(s) && len(out) < 200; i++ {
		if s[i] >= 0x20 && s[i] < 0x7f {
			out = append(out, s[i])
		}
	}
	return string(out)
}
