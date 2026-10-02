package m

import (
	"encoding/json/jsontext"
	"encoding/json/v2"

	"internal/platform/secret"
)

type HandInput struct{ Password secret.Secret }

// The same call in a hand-written file is reported.
func (in *Input) handUnmarshal(d *jsontext.Decoder) error {
	return json.UnmarshalDecode(d, &in.Password) // want `decodes into a type that contains a Secret`
}

func (in *HandInput) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	return json.UnmarshalDecode(d, &in.Password) // want `decodes into a type that contains a Secret`
}
