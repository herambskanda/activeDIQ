package report

import (
	"bytes"
	"testing"
)

// The json/v2 port must keep the bytes v1 wrote (the query hash is taken over them): <, >, & and U+2028 are escaped.
func TestWireBytesKeepV1Form(t *testing.T) {
	for name, m := range map[string]interface{ MarshalJSON() ([]byte, error) }{
		"cell text":  TextCell("a<b>&c\u2028"),
		"cell list":  ListCell("x<y", "z"),
		"value text": TextV("a<b>&c"),
		"expr cmp":   Cmp{Column: "c<", Op: OpEq, Value: TextV("v")},
	} {
		b, err := m.MarshalJSON()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, raw := range []string{"<", ">", "&", "\u2028"} {
			if bytes.Contains(b, []byte(raw)) {
				t.Errorf("%s: %q is not escaped in %s", name, raw, b)
			}
		}
	}
}
