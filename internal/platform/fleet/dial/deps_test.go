package dial

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoStoreOrSQL is rule 7 for this package (blueprint §2): the component side links no store, no
// key-sealing code and no SQL driver, on either component OS.
func TestNoStoreOrSQL(t *testing.T) {
	// Each OS passes its own constant setting: ADR-0002 erratum E-2 allows the environment to be
	// forwarded to a child only with constant strings appended.
	linux := exec.Command("go", "list", "-deps", ".")
	linux.Env = append(linux.Environ(), "GOOS=linux")
	windows := exec.Command("go", "list", "-deps", ".")
	windows.Env = append(windows.Environ(), "GOOS=windows")
	for _, tc := range []struct {
		goos string
		cmd  *exec.Cmd
	}{{"linux", linux}, {"windows", windows}} {
		goos := tc.goos
		out, err := tc.cmd.Output()
		if err != nil {
			t.Fatalf("go list (%s): %v", goos, err)
		}
		for _, p := range strings.Fields(string(out)) {
			for _, bad := range []string{"internal/platform/store", "internal/platform/keys", "database/sql", "jackc/pgx", "fleet/fleetsql"} {
				if strings.Contains(p, bad) {
					t.Errorf("GOOS=%s: fleet/dial links %s", goos, p)
				}
			}
		}
	}
}
