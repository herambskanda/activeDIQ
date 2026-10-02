package secret

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
)

type Secret struct{ b []byte }

func (s *Secret) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	v, err := d.ReadValue() // aliases the caller's buffer: allowed
	s.b = append(s.b[:0], v...)
	return err
}

type Other struct{ b []byte }

func (s *Secret) bad(d *jsontext.Decoder) error {
	return nil
}

// The Secret's own decoder may call the decode functions on itself.
func inner(d *jsontext.Decoder, s *Secret) error { return json.UnmarshalDecode(d, s) }
