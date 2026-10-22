package policyjson

import (
	"strings"
	"testing"
)

func TestFromYAML(t *testing.T) {
	out, err := FromYAML([]byte("anonymous:\n  - operation: a\n    host: sspr\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"host": "sspr"`) || !strings.HasSuffix(string(out), "}\n") {
		t.Errorf("out = %s", out)
	}
	if _, err := FromYAML([]byte("anonymous: [")); err == nil {
		t.Error("invalid yaml must fail")
	}
	if _, err := FromYAML([]byte("a:\n  1: x\n")); err == nil {
		t.Error("non-string key must fail")
	}
	if _, err := FromYAML([]byte("anonymous: []\n---\nstepUp: []\n")); err == nil {
		t.Error("a second document must fail")
	}
	out, err = FromYAML([]byte("anonymous:\n  - operation: a\n    host:\n"))
	if err != nil || !strings.Contains(string(out), `"host": null`) {
		t.Errorf("empty host must convert to null for ParsePolicy to reject: %v %s", err, out)
	}
}
