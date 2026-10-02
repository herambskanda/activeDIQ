// Package secret is a stand-in for internal/platform/secret (T-0071) in the generator's fixture. It
// has what the generated code uses and what ADR-0004 rule 4 asks of the real type: a v2
// UnmarshalJSONFrom that reads through ReadValue, a Destroy, a MarshalJSONTo that refuses to encode,
// and no v1 JSON method.
package secret

import (
	"encoding/json/jsontext"
	"errors"
)

// Secret holds secret bytes.
type Secret struct{ b []byte }

// UnmarshalJSONFrom reads a JSON string into fresh bytes the caller can destroy.
func (s *Secret) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	v, err := d.ReadValue()
	if err != nil {
		return err
	}
	if v.Kind() != '"' {
		return errors.New("secret: expected a string")
	}
	s.b = append([]byte(nil), v[1:len(v)-1]...)
	return nil
}

// MarshalJSONTo always fails: a secret is never serialised.
func (Secret) MarshalJSONTo(*jsontext.Encoder) error { return errors.New("secret: unserializable") }

// Destroy zeroes the bytes.
func (s *Secret) Destroy() {
	clear(s.b)
	s.b = nil
}

// Len is the byte length; Destroyed reports whether Destroy ran (or nothing was held).
func (s *Secret) Len() int { return len(s.b) }

// Bytes returns the held bytes, for tests.
func (s *Secret) Bytes() []byte { return s.b }
