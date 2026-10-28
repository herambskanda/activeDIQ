//go:build unix

package ownerfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
