package secretjson

import (
	"strings"
	"testing"
)

// The corpus for attr.unicodepwd (decode path PW-15, PW-16, PW-J01..J14 and the encode vectors) runs
// in internal/directory/attr/unicodepwd, the one declared implementation of the unit (FF-SP4).

type body struct {
	Password string `json:"password"`
	Nested   *body  `json:"nested"`
}

func TestDecodeRejectsUnknownMembersNestedAndDuplicates(t *testing.T) {
	for in, want := range map[string]string{
		`{"password":"x","extra":1}`:        "unknown object member",
		`{"nested":{"password":"x","z":1}}`: "unknown object member",
		`{"password":"x","password":"y"}`:   "duplicate object member",
		`{"Password":"x"}`:                  "unknown object member",
	} {
		var v body
		if err := Decode([]byte(in), &v); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Decode(%s) = %v, want %q", in, err, want)
		}
	}
	var v body
	if err := Decode([]byte(`{"password":"x"}`), &v); err != nil || v.Password != "x" {
		t.Fatalf("well-formed body: %v %+v", err, v)
	}
}
