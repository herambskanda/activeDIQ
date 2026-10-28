//go:build windows

package ownerfile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// T-0577 AC1/AC2 on Windows: run in the Windows lab. Logs icacls of the state directory.
func TestWindowsEnsureDirAndReadFile(t *testing.T) {
	d := filepath.Join(t.TempDir(), "state")
	if err := EnsureDir(d); err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command("icacls", d).CombinedOutput()
	t.Logf("icacls state dir\n%s", out)
	if err := EnsureDir(d); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	// A plain directory inherits the parent ACL (not protected): refused.
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.Mkdir(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(plain); !errors.Is(err, ErrDirUnsafe) {
		t.Fatalf("inherited-ACL dir: got %v", err)
	}
	// Reparse point at the path: refused, target contents never read.
	f, err := OpenAppend(filepath.Join(d, "target"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("secret")
	f.Close()
	link := filepath.Join(d, "baseline.json")
	if err := os.Symlink(filepath.Join(d, "target"), link); err != nil {
		t.Skipf("symlink needs privilege: %v", err)
	}
	if b, err := ReadFile(link); !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("reparse: got %q, %v", b, err)
	}
}
