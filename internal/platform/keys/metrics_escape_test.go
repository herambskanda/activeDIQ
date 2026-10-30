package keys

import "testing"

func TestEscapeLabelPrometheusFormat(t *testing.T) {
	for in, want := range map[string]string{
		`plain`: `plain`,
		`a"b`:   `a\"b`,
		`a\b`:   `a\\b`,
		"a\nb":  `a\nb`,
		"é\x01": "é\x01", // only \ " and LF are escaped; %q would have rewritten these
	} {
		if got := escapeLabel(in); got != want {
			t.Errorf("escapeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
