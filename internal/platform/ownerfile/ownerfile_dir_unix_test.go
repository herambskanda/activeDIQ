//go:build unix

package ownerfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// trustedParent returns a directory that passes the parent check whatever the umask of the test run.
func trustedParent(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if err := os.Chmod(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// goodDir creates a state directory under a trusted parent and puts the files in it.
func goodDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(trustedParent(t), "state")
	d, err := CreateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for n, b := range files {
		if err := d.WriteFile(n, []byte(b)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDirCreateWriteRead(t *testing.T) {
	dir := goodDir(t, map[string]string{"a": "one"})
	d, err := OpenDir(dir) // positive control: the verification accepts a correct directory
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if b, err := d.ReadFile("a"); err != nil || string(b) != "one" {
		t.Fatalf("got %q, %v", b, err)
	}
	if err := d.WriteFile("a", []byte("two")); err != nil { // replace
		t.Fatal(err)
	}
	if b, _ := d.ReadFile("a"); string(b) != "two" {
		t.Fatalf("got %q", b)
	}
	if _, err := d.ReadFile("missing"); !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrUnsafe) {
		t.Fatalf("missing: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
	for _, bad := range []string{"", ".", "..", "../x", "a/b", `a\b`} {
		if _, err := d.ReadFile(bad); err == nil {
			t.Fatalf("ReadFile(%q) accepted", bad)
		}
		if err := d.WriteFile(bad, nil); err == nil {
			t.Fatalf("WriteFile(%q) accepted", bad)
		}
	}
}

// T-1315 AC3 (Unix half): whatever the umask, the temp file exists as 0600 from the first instant;
// the file and the directory it ends up in carry no group or other bit.
func TestDirWriteFileIsOwnerOnlyUnderOpenUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := goodDir(t, map[string]string{"key.pem": "secret"})
	if st, _ := os.Stat(filepath.Join(dir, "key.pem")); st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", st.Mode())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", st.Mode())
	}
}

// T-1315 AC1: the state directory is swapped for a symlink to a directory holding a complete, correctly
// permissioned set of foreign files. Opening by path is refused; a directory that was already open
// keeps reading the original inode and never the foreign one.
func TestDirSwappedForSymlinkNeverReadsForeignContents(t *testing.T) {
	dir := goodDir(t, map[string]string{"pin": "REAL"})
	foreign := goodDir(t, map[string]string{"pin": "FORGED"})

	held, err := OpenDir(dir) // opened before the swap
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	if err := os.Rename(dir, dir+".away"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, dir); err != nil {
		t.Fatal(err)
	}

	if d, err := OpenDir(dir); err == nil {
		d.Close()
		t.Fatal("OpenDir followed a symlinked state directory")
	} else if !errors.Is(err, ErrDirUnsafe) {
		t.Fatalf("want ErrDirUnsafe, got %v", err)
	}
	if d, err := CreateDir(dir); err == nil {
		d.Close()
		t.Fatal("CreateDir followed a symlinked state directory")
	}
	b, err := held.ReadFile("pin")
	if err != nil || string(b) != "REAL" {
		t.Fatalf("held handle read %q, %v; want REAL (never FORGED)", b, err)
	}
	// Writes through the held handle land in the original directory, not in the foreign one.
	if err := held.WriteFile("pin", []byte("NEW")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(foreign, "pin")); string(b) != "FORGED" {
		t.Fatalf("foreign directory modified: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir+".away", "pin")); string(b) != "NEW" {
		t.Fatalf("original directory not written: %q", b)
	}
}

// A file swapped for a symlink to the service's own 0600 file is refused (no-follow), not read.
func TestDirReadFileRefusesSymlinkAndWider(t *testing.T) {
	dir := goodDir(t, map[string]string{"own": "x", "wide": "y"})
	if err := os.Symlink(filepath.Join(dir, "own"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "wide"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if b, err := d.ReadFile("link"); !errors.Is(err, ErrUnsafe) || !errors.Is(err, ErrNotRegular) || len(b) != 0 {
		t.Fatalf("symlink: %q, %v", b, err)
	}
	if b, err := d.ReadFile("wide"); !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("0644: %q, %v", b, err)
	}
	if b, err := d.ReadFile("own"); err != nil || string(b) != "x" {
		t.Fatalf("control: %q, %v", b, err)
	}
}

// T-1315 AC2 (Unix half): a parent that others can write to or rename entries in, or that is a link, is
// refused by OpenDir and CreateDir, and CreateDir creates nothing.
func TestDirRefusesUntrustedParent(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, parent string) string{
		"group-writable": func(t *testing.T, p string) string { chmod(t, p, 0o770); return p },
		"other-writable": func(t *testing.T, p string) string { chmod(t, p, 0o707); return p },
		"sticky-world-writable": func(t *testing.T, p string) string {
			chmod(t, p, 0o700|os.ModeSticky|0o077) // like /tmp
			return p
		},
		"symlink": func(t *testing.T, p string) string {
			link := filepath.Join(trustedParent(t), "parent-link")
			if err := os.Symlink(p, link); err != nil {
				t.Fatal(err)
			}
			return link
		},
	} {
		t.Run(name, func(t *testing.T) {
			real := trustedParent(t)
			// Positive control on the same layout: before the mutation the directory is created.
			ctl, err := CreateDir(filepath.Join(real, "control"))
			if err != nil {
				t.Fatalf("control: %v", err)
			}
			ctl.Close()

			parent := mutate(t, real)
			for _, open := range []func(string, ...DirOption) (*Dir, error){OpenDir, CreateDir} {
				d, err := open(filepath.Join(parent, "state"))
				if err == nil {
					d.Close()
					t.Fatal("untrusted parent accepted")
				}
				if !errors.Is(err, ErrParentUnsafe) {
					t.Fatalf("want ErrParentUnsafe, got %v", err)
				}
			}
			chmod(t, real, 0o700)
			if _, err := os.Lstat(filepath.Join(real, "state")); err == nil {
				t.Fatal("CreateDir created the directory under an untrusted parent")
			}
		})
	}
}

func chmod(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

func TestDirRefusesWiderOrPreexistingDirectory(t *testing.T) {
	parent := trustedParent(t)
	dir := filepath.Join(parent, "state")
	if err := os.Mkdir(dir, 0o755); err != nil { // squatted: wider than owner-only
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, open := range []func(string, ...DirOption) (*Dir, error){OpenDir, CreateDir} {
		if d, err := open(dir); !errors.Is(err, ErrDirUnsafe) {
			if d != nil {
				d.Close()
			}
			t.Fatalf("want ErrDirUnsafe, got %v", err)
		}
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o755 {
		t.Fatalf("a pre-existing directory was repaired: %v", st.Mode())
	}
	if _, err := OpenDir(filepath.Join(parent, "none")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}

func TestForAccountRefusedOnUnix(t *testing.T) {
	if _, err := CreateDir(filepath.Join(trustedParent(t), "state"), ForAccount("someone")); !errors.Is(err, ErrAccountUnsupported) {
		t.Fatalf("err = %v, want ErrAccountUnsupported", err)
	}
}
