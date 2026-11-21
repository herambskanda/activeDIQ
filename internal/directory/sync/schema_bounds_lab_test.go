//go:build lab

package sync_test

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// T-1250 AC1: every mapper bound on an attribute a non-admin can write is at or above the schema's
// rangeUpper, read from the schema NC of the running Samba lab (make lab-up). Samba's schema is the
// Samba schema: this proves the check mechanism and Samba's values only. Windows Server's rangeUpper
// is read by the windowslab twin of this test (schema_bounds_windows_lab_test.go, T-1880); Samba must not stand in for it.
func Test_lab_mapper_bounds_cover_the_schema_range_upper(t *testing.T) {
	env := readEnvFile(t, labDir(".lab.env"))
	c := env["LAB_CONTAINER"]
	hits := 0
	for _, a := range boundsAttrs {
		out, err := exec.Command("docker", "exec", c, "ldbsearch", "-H", "/var/lib/samba/private/sam.ldb",
			"-b", "CN=Schema,CN=Configuration,DC=lab,DC=activediq,DC=test", "-s", "one",
			schemaFilter(t, a), "rangeUpper").CombinedOutput()
		if err != nil {
			t.Fatalf("ldbsearch %s: %v\n%s", a, err, out)
		}
		upper := 0
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(l, "rangeUpper: "); ok {
				n, err := strconv.Atoi(strings.TrimSpace(v))
				if err != nil {
					t.Fatalf("%s: unparsable rangeUpper %q: %v", a, v, err)
				}
				upper = n
			}
		}
		if upper == 0 {
			t.Logf("%s: no rangeUpper in the Samba schema; skipped (Windows: schema_bounds_windows_lab_test.go)", a)
			continue
		}
		hits++
		if err := mapsAtRangeUpper(a, upper); err != nil {
			t.Errorf("%s: a value of its rangeUpper (%d chars) is refused: %v", a, upper, err)
		}
	}
	// A wrong base DN or a renamed schema makes every lookup empty; that must fail, not pass unchecked.
	// Samba's schema carries rangeUpper for 7 of the 9 attributes (T-1250 run 2026-11-07).
	if hits < minSambaHits {
		t.Fatalf("only %d of %d attributes had a rangeUpper in the schema, want at least %d: the lookup is checking nothing", hits, len(boundsAttrs), minSambaHits)
	}
}

const minSambaHits = 7
