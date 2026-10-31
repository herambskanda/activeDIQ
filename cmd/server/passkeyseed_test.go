package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// T-0855 acceptance 4. `account add-passkey` stores a credential's public key without a registration
// ceremony, so it must exist only in a `-tags lab` build. The test builds the server both ways with the
// real toolchain and inspects the binaries: a production build that ever links the command (a lost build
// tag, a hook set from a shared file) fails here, and the lab build is the control that proves the
// inspection can see the command at all.

const (
	seedSymbol = "server.LabAddPasskey"
	seedName   = "add-passkey"
)

func buildServer(t *testing.T, tags string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "server")
	args := []string{"build", "-o", out}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command("go", append(args, "github.com/skenzeriq/activediq/cmd/server")...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %q: %v\n%s", tags, err, b)
	}
	return out
}

func symbols(t *testing.T, bin string) string {
	t.Helper()
	b, err := exec.Command("go", "tool", "nm", bin).Output()
	if err != nil {
		t.Fatalf("go tool nm: %v", err)
	}
	return string(b)
}

func runAccountCmd(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"account"}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")} // no database, no key: the command must fail before needing either
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return out.String(), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), 0
}

func TestProductionBinaryHasNoPasskeySeeding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the server twice")
	}
	prod := buildServer(t, "")
	if strings.Contains(symbols(t, prod), seedSymbol) {
		t.Fatalf("the production binary contains %s", seedSymbol)
	}
	if raw, err := os.ReadFile(prod); err != nil {
		t.Fatal(err)
	} else if bytes.Contains(raw, []byte(seedName)) {
		t.Fatalf("the production binary contains the string %q", seedName)
	}
	out, code := runAccountCmd(t, prod, seedName, "--account", "x")
	if code != 2 || !strings.Contains(out, "init-local") || strings.Contains(out, seedName) {
		t.Fatalf("production `account %s` = exit %d, %q; want the generic usage (exit 2) with no mention of the command", seedName, code, out)
	}

	// Control: the lab build has it, so a clean production result above is not a blind inspection.
	lab := buildServer(t, "lab")
	if !strings.Contains(symbols(t, lab), seedSymbol) {
		t.Fatalf("the lab binary does not contain %s: the production check above proves nothing", seedSymbol)
	}
	out, code = runAccountCmd(t, lab, seedName)
	if code != 1 || !strings.Contains(out, seedName) {
		t.Fatalf("lab `account %s` = exit %d, %q; want its own usage (exit 1)", seedName, code, out)
	}
}
