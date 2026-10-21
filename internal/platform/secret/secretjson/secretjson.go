// Package secretjson is the one decode path for API request bodies (ADR-0004 rule 6 step 3,
// safe-primitives §5.6). apihost is its only caller; the secretjson analyzer (FF-SP2) enforces that.
//
// Decode reads straight from the caller's buffer, so a Secret decoded from it never becomes a Go
// string. The caller owns the buffer and zeroes it when the request ends.
package secretjson

import "encoding/json/v2"

// Decode is json.Unmarshal with unknown members rejected and nothing else changed: names match
// case-sensitively, duplicates and invalid UTF-8 are refused, as the v2 defaults say. The strict
// options reach nested values through the generated decoders (ADR-0004 rule 4).
func Decode(buf []byte, v any) error {
	return json.Unmarshal(buf, v, json.RejectUnknownMembers(true))
}
