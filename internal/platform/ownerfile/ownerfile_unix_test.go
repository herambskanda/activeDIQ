//go:build !windows

package ownerfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSymlinkAndNonRegularRefused(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "target")
	if err := os.WriteFile(target, []byte("t"), 0o666); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenAppend(link); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("symlink: %v", err)
	}
	if st, _ := os.Stat(target); st.Mode().Perm() == 0o600 {
		t.Fatalf("target was chmodded: %v", st.Mode())
	}
	if _, _, err := OpenAppend(d); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("dir: %v", err)
	}
}

func TestOwnedBy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Lstat(p)
	if !ownedBy(st, os.Geteuid()) {
		t.Fatal("own file must be accepted")
	}
	if ownedBy(st, os.Geteuid()+1) {
		t.Fatal("file of another uid must be refused")
	}
}

func TestCreateTempIsOwnerOnlyBeforeWrite(t *testing.T) {
	f, err := CreateTemp(t.TempDir(), ".baseline-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if st, _ := f.Stat(); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}
