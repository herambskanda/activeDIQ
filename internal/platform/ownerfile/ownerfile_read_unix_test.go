//go:build unix

package ownerfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// T-0577 AC2: a path swapped for a link after an earlier check is refused and no foreign bytes are read.
func TestReadFileRefusesSymlinkAndWider(t *testing.T) {
	d := t.TempDir()
	foreign := filepath.Join(d, "foreign")
	if err := os.WriteFile(foreign, []byte("FORGED"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(foreign, 0o666); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "baseline.json")
	if err := os.Symlink(foreign, link); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFile(link)
	if !errors.Is(err, ErrUnsafe) || !errors.Is(err, ErrNotRegular) || len(b) != 0 {
		t.Fatalf("symlink: got %q, %v", b, err)
	}
	if b, err := ReadFile(foreign); !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("0666: got %q, %v", b, err)
	}
}

// A symlink to the service's OWN 0600 file passes the owner and mode check on its target, so only
// O_NOFOLLOW refuses it: this case pins the no-follow behaviour itself (T-0845).
func TestReadFileRefusesSymlinkToOwnFile(t *testing.T) {
	d := t.TempDir()
	own := filepath.Join(d, "own")
	if err := os.WriteFile(own, []byte("STALE"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "baseline.json")
	if err := os.Symlink(own, link); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(link); !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("got %q, %v", b, err)
	}
}

func TestReadFileOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b")
	if err := os.WriteFile(p, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(p); err != nil || string(b) != "ok" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := ReadFile(p + ".none"); !errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrUnsafe) {
		t.Fatalf("got %v", err)
	}
}

// T-0577 AC1.
func TestEnsureDir(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "state")
	if err := EnsureDir(d); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(d); st.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", st.Mode())
	}
	if err := EnsureDir(d); err != nil { // idempotent
		t.Fatal(err)
	}
	for _, m := range []os.FileMode{0o755, 0o770, 0o701} {
		if err := os.Chmod(d, m); err != nil {
			t.Fatal(err)
		}
		if err := EnsureDir(d); !errors.Is(err, ErrDirUnsafe) {
			t.Fatalf("%v: got %v", m, err)
		}
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(d, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(link); !errors.Is(err, ErrDirUnsafe) {
		t.Fatalf("symlink dir: got %v", err)
	}
}

// A FIFO planted at the path must be refused, never block open(2).
func TestReadFileRefusesFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	ch := make(chan error, 1)
	go func() { _, err := ReadFile(p); ch <- err }()
	select {
	case err := <-ch:
		if !errors.Is(err, ErrUnsafe) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked on FIFO")
	}
}
