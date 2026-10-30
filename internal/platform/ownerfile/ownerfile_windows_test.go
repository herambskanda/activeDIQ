//go:build windows

package ownerfile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// widen grants a well-known SID (by string, so the test is locale independent) access through
// icacls. Test-only; production code uses the typed ACL API.
func widen(t *testing.T, path, sid, perm string) {
	t.Helper()
	if out, err := exec.Command("icacls", path, "/grant", "*"+sid+":"+perm).CombinedOutput(); err != nil {
		t.Fatalf("icacls grant: %v\n%s", err, out)
	}
}

func writeOwned(t *testing.T, p, body string) {
	t.Helper()
	f, err := OpenAppend(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

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
	writeOwned(t, filepath.Join(d, "target"), "secret")
	link := filepath.Join(d, "baseline.json")
	if err := os.Symlink(filepath.Join(d, "target"), link); err != nil {
		t.Skipf("symlink needs privilege: %v", err)
	}
	if b, err := ReadFile(link); !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("reparse: got %q, %v", b, err)
	}
}

// AC1: a state directory wider than service identity + SYSTEM is refused with the typed error,
// including the ProgramData default shape (BUILTIN\Users may create files).
func TestWindowsWiderDirRefused(t *testing.T) {
	for name, tc := range map[string]struct{ sid, perm string }{
		"users-read":      {"S-1-5-32-545", "(OI)(CI)(RX)"},
		"users-modify":    {"S-1-5-32-545", "(OI)(CI)(M)"},
		"everyone-full":   {"S-1-1-0", "(OI)(CI)(F)"},
		"authenticated-w": {"S-1-5-11", "(OI)(CI)(W)"},
	} {
		t.Run(name, func(t *testing.T) {
			d := filepath.Join(t.TempDir(), "state")
			if err := EnsureDir(d); err != nil {
				t.Fatal(err)
			}
			widen(t, d, tc.sid, tc.perm)
			if err := EnsureDir(d); !errors.Is(err, ErrDirUnsafe) {
				t.Fatalf("EnsureDir: got %v, want ErrDirUnsafe", err)
			}
			if err := CheckDir(d); !errors.Is(err, ErrDirUnsafe) {
				t.Fatalf("CheckDir: got %v, want ErrDirUnsafe", err)
			}
		})
	}
}

// AC2: positive read, widened file, swap-after-Check to a link to a foreign file, junction.
func TestWindowsReadFileCases(t *testing.T) {
	d := filepath.Join(t.TempDir(), "state")
	if err := EnsureDir(d); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "baseline.json")
	writeOwned(t, p, `{"ok":1}`)
	if b, err := ReadFile(p); err != nil || string(b) != `{"ok":1}` {
		t.Fatalf("legit read: %q, %v", b, err)
	}
	widen(t, p, "S-1-1-0", "(R)")
	if b, err := ReadFile(p); !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("widened file: %q, %v", b, err)
	}

	foreign := filepath.Join(t.TempDir(), "foreign.json")
	if err := os.WriteFile(foreign, []byte("FORGED"), 0o666); err != nil {
		t.Fatal(err)
	}
	widen(t, foreign, "S-1-1-0", "(F)")
	swapped := filepath.Join(d, "swapped.json")
	writeOwned(t, swapped, "legit")
	if err := Check(swapped); err != nil {
		t.Fatalf("Check of own file: %v", err)
	}
	if err := os.Remove(swapped); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, swapped); err != nil {
		t.Skipf("symlink needs privilege: %v", err)
	}
	if b, err := ReadFile(swapped); !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("swap after Check: got %q, %v", b, err)
	}

	jn := filepath.Join(d, "junction.json")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", jn, t.TempDir()).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	if b, err := ReadFile(jn); err == nil || len(b) != 0 {
		t.Fatalf("junction: got %q, %v", b, err)
	}
}
