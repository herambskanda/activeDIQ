package apihost

import "internal/platform/secret/secretjson"

type req struct{ Password secretType }
type secretType = struct{}

func handle(body []byte, v *struct{}) error { return secretjson.Decode(body, v) }
