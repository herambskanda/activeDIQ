package main

import "testing"

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
