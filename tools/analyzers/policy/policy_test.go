package policy

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		rel, pat string
		want     bool
	}{
		{"internal/platform/proc", "internal/platform/proc", true},
		{"internal/platform/proc/inner", "internal/platform/proc", true},
		{"internal/platform/procfoo", "internal/platform/proc", false},
		{"internal/platform/export/csv", "**/export/csv", true},
		{"internal/reports/export/csv/x", "**/export/csv", true},
		{"export/csv", "**/export/csv", true},
		{"internal/export/csvx", "**/export/csv", false},
		{"internal/platform/tlsconfig", "**/tlsconfig", true},
	}
	for _, c := range cases {
		if got := Match(c.rel, c.pat); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.rel, c.pat, got, c.want)
		}
	}
}

func TestToolTier(t *testing.T) {
	for rel, want := range map[string]bool{"tools/fitness/x": true, "lab/seed": true, "internal/tools": false, "toolsx": false} {
		if IsToolTier(rel) != want {
			t.Errorf("IsToolTier(%q) != %v", rel, want)
		}
	}
}
