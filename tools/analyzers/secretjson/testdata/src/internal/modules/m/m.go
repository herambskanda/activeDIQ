package m

import (
	enc "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"

	"internal/platform/secret"
	"internal/platform/secret/secretjson"
)

type Input struct {
	Name     string
	Password secret.Secret
}

type Plain struct{ Name string }

func f(body []byte, d *jsontext.Decoder) {
	var in Input
	var p Plain
	enc.Unmarshal(body, &in)     // want `decodes into a type that contains a Secret`
	json.Unmarshal(body, &in)    // want `decodes into a type that contains a Secret`
	json.UnmarshalDecode(d, &in) // want `decodes into a type that contains a Secret`
	json.Unmarshal(body, &p)
	secretjson.Decode(body, &in) // want `secretjson.Decode is called outside apihost`
}
