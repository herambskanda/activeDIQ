package secret

import "encoding/json/jsontext"

type tokDecoder struct{ S Secret }

func (t *tokDecoder) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	tok, err := d.ReadToken() // want `ReadToken inside a Secret decoder`
	_ = tok.String()          // want `String inside a Secret decoder`
	return err
}
