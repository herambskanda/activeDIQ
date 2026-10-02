package secretjson

import (
	"encoding/json/v2"

	"internal/platform/secret"
)

func Decode(body []byte, v any) error {
	var s secret.Secret
	_ = s
	return json.Unmarshal(body, v)
}
