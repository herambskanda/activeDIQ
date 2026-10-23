package dial

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoStoreOrSQL is rule 7 for this package (blueprint §2): the component side links no store, no
// key-sealing code and no SQL driver, on either component OS.
func TestNoStoreOrSQL(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		cmd := exec.Command("go", "list", "-deps", ".")
		cmd.Env = append(cmd.Environ(), "GOOS="+goos)
		out, err := cmd.Output()
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
