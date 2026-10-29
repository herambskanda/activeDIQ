//go:build linux

package prochardening

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBinariesRefuseGOTRACEBACKCrash builds each product main and checks it exits 2 under
// GOTRACEBACK=crash, before reading any configuration (acceptance 1, TM-TB16-T6).
func TestBinariesRefuseGOTRACEBACKCrash(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	dir := t.TempDir()
	for _, c := range []string{"server", "connector", "edge", "agent"} {
		bin := filepath.Join(dir, c)
		if out, err := exec.Command("go", "build", "-o", bin, "../../../cmd/"+c).CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", c, err, out)
		}
		cmd := exec.Command(bin)
		cmd.Env = append(os.Environ(), "GOTRACEBACK=crash")
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 2 || !strings.Contains(string(out), "GOTRACEBACK") {
			t.Errorf("%s: err=%v out=%s; want exit 2 mentioning GOTRACEBACK", c, err, out)
		}
	}
}
