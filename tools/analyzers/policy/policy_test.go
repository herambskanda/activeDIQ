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

func TestTestSupport(t *testing.T) {
	for rel, want := range map[string]bool{
		"internal/platform/store/storetest": true,
		"internal/platform/jobs/jobstest":   true,
		"internal/platform/jobs":            false,
		"internal/platform/store":           false,
		"internal/platform/store/footest":   false,
		"internal/modules/storetest":        false,
	} {
		if IsTestSupport(rel) != want {
			t.Errorf("IsTestSupport(%q) != %v", rel, want)
		}
	}
}

func TestIsSQLForwarder(t *testing.T) {
	for _, c := range []struct {
		rel, recv string
		want      bool
	}{
		{"internal/platform/store", "tx", true},
		{"internal/platform/store", "other", false},
		{"internal/platform/store/storetest", "tx", false},
		{"internal/modules/m", "tx", false},
	} {
		if got := IsSQLForwarder(c.rel, c.recv); got != c.want {
			t.Errorf("IsSQLForwarder(%q, %q) = %v, want %v", c.rel, c.recv, got, c.want)
		}
	}
}
