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

func TestOpenAppendCreatesRestricted(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.log")
	f, err := OpenAppend(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := Check(p); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAppendRefusesWiderExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.log")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAppend(p); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("got %v", err)
	}
}

func TestCheckRefusesSymlink(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "t")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	l := filepath.Join(d, "l")
	if err := os.Symlink(target, l); err != nil {
		t.Fatal(err)
	}
	if err := Check(l); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("got %v", err)
	}
	if _, err := OpenAppend(l); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("open: %v", err)
	}
}

func TestCheckMissingIsNotUnsafe(t *testing.T) {
	err := Check(filepath.Join(t.TempDir(), "nope"))
	if err == nil || errors.Is(err, ErrUnsafe) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

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
	if !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("symlink: got %q, %v", b, err)
	}
	if b, err := ReadFile(foreign); !errors.Is(err, ErrUnsafe) || len(b) != 0 {
		t.Fatalf("0666: got %q, %v", b, err)
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
	if _, err := ReadFile(p + ".none"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

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
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(d); !errors.Is(err, ErrDirUnsafe) {
		t.Fatalf("0755: got %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(d, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(link); !errors.Is(err, ErrDirUnsafe) {
		t.Fatalf("symlink dir: got %v", err)
	}
}

// A FIFO planted at the path must be refused, never block open(2) (security review of T-0577).
func withTimeout(t *testing.T, f func() error) error {
	t.Helper()
	ch := make(chan error, 1)
	go func() { ch <- f() }()
	select {
	case err := <-ch:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("blocked on FIFO")
		return nil
	}
}

func TestReadFileRefusesFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	err := withTimeout(t, func() error { _, err := ReadFile(p); return err })
	if !errors.Is(err, ErrUnsafe) {
		t.Fatalf("got %v", err)
	}
}

func TestOpenAppendRefusesFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "records.log")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	err := withTimeout(t, func() error {
		f, err := OpenAppend(p)
		if f != nil {
			f.Close()
		}
		return err
	})
	if !errors.Is(err, ErrUnsafe) {
		t.Fatalf("got %v", err)
	}
}
