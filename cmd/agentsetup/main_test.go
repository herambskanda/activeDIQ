package main

import (
	"strings"
	"testing"
)

func TestParseVerbRefusesAnyExtraArgument(t *testing.T) {
	for _, a := range [][]string{nil, {}, {"grant-channel", "x"}, {"prepare-datadir", "--data-dir", `C:\x`}, {"unknown"}, {""}, {"grant-channel", ""}} {
		if v, ok := parseVerb(a); ok {
			t.Errorf("parseVerb(%q) = %q, true; want refusal", a, v)
		}
	}
	for v := range verbs {
		if got, ok := parseVerb([]string{v}); !ok || got != v {
			t.Errorf("parseVerb(%q) refused", v)
		}
	}
}

func TestParseRepin(t *testing.T) {
	pin := "sha256:" + strings.Repeat("ab", 32)
	if got, ok := parseRepin([]string{"repin", pin}); !ok || got != pin {
		t.Fatalf("valid repin refused: %q %v", got, ok)
	}
	for _, a := range [][]string{nil, {"repin"}, {"repin", ""}, {"repin", "x"}, {"repin", pin, "extra"}, {"repin", strings.ToUpper(pin)}, {"repin", pin + "0"}, {"grant-channel", pin}, {"repin", `C:\x`}} {
		if _, ok := parseRepin(a); ok {
			t.Errorf("parseRepin(%q) accepted", a)
		}
	}
	if _, ok := parseVerb([]string{"repin"}); ok {
		t.Error("repin must not be a bare verb")
	}
}

func TestRepinReportsFailureOnce(t *testing.T) {
	var msgs []string
	code := repin(t.TempDir(), "sha256:"+strings.Repeat("ab", 32), func(m string, failed bool) {
		if !failed {
			t.Error("success reported")
		}
		msgs = append(msgs, m)
	})
	if code != 1 || len(msgs) != 1 {
		t.Fatalf("code = %d, audit = %q", code, msgs)
	}
}
