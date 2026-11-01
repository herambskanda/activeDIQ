//go:build unix

package rights

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func widenForTest(t *testing.T, p string) {
	t.Helper()
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
}

// T-0577 AC2 (Unix): a baseline path that is a symlink to a foreign file is refused by Load and the
// foreign contents are never returned.
func TestFileBaselineStoreLoadRefusesSymlinkSwap(t *testing.T) {
	d := t.TempDir()
	s := FileBaselineStore{filepath.Join(d, "baseline.json")}
	if err := s.Save(&Baseline{VerificationID: "v1"}); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(d, "foreign")
	if err := os.WriteFile(foreign, []byte(`{"verification_id":"FORGED","entries":[]}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(foreign, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, s.Path); err != nil {
		t.Fatal(err)
	}
	b, err := s.Load()
	if !errors.Is(err, ErrBaselineUnsafe) || b != nil {
		t.Fatalf("got %+v, %v", b, err)
	}
}
