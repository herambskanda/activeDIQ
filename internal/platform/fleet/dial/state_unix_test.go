//go:build unix

package dial

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// T-1315 AC1: the enrolled state directory is replaced by a symlink to a directory that holds a
// complete, correctly permissioned (but foreign) enrolment. Load refuses it and the foreign contents
// are never used; the unswapped directory loads (positive control).
func TestLoadRefusesSwappedStateDirectory(t *testing.T) {
	iss, m, dir := setup(t)
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); err != nil {
		t.Fatal(err)
	}
	foreignIss, foreignM, foreign := setup(t)
	if _, err := Enroll(context.Background(), foreignM, foreign, foreignIss.exchange); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(foreign); err != nil {
		t.Fatalf("control: the foreign enrolment is itself valid: %v", err)
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("control: %v", err)
	}
	if err := os.Rename(dir, dir+".away"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(foreign, dir); err != nil {
		t.Fatal(err)
	}
	st, err := Load(dir)
	if !errors.Is(err, ErrState) || st != nil {
		t.Fatalf("Load through a swapped directory = %v, %v; want ErrState", st, err)
	}
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); !errors.Is(err, ErrState) {
		t.Fatalf("Enroll through a swapped directory = %v; want ErrState", err)
	}
	if ents, _ := os.ReadDir(foreign); len(ents) != 5 {
		t.Fatalf("the foreign directory was written to: %d entries", len(ents))
	}
}

// T-1315 AC2: a parent that others can write to, or that is a link, is refused by Enroll and Load and
// nothing is written, whatever the state directory itself looks like.
func TestStateRefusesUntrustedParent(t *testing.T) {
	iss, m, _ := setup(t)
	// Positive control: the same flow in a trusted parent succeeds.
	if _, err := Enroll(context.Background(), m, filepath.Join(tempParent(t), "state"), iss.exchange); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, parentMode := range map[string]os.FileMode{"group-writable": 0o770, "other-writable": 0o707} {
		t.Run(name, func(t *testing.T) {
			parent := tempParent(t)
			dir := filepath.Join(parent, "state")
			if err := os.Chmod(parent, parentMode); err != nil {
				t.Fatal(err)
			}
			if _, err := Enroll(context.Background(), m, dir, iss.exchange); !errors.Is(err, ErrState) {
				t.Fatalf("Enroll under an untrusted parent = %v; want ErrState", err)
			}
			if _, err := Load(dir); !errors.Is(err, ErrState) {
				t.Fatalf("Load under an untrusted parent = %v; want ErrState", err)
			}
			os.Chmod(parent, 0o700)
			if ents, _ := os.ReadDir(parent); len(ents) != 0 {
				t.Fatalf("something was written under the untrusted parent: %v", ents)
			}
		})
	}
	t.Run("symlinked parent", func(t *testing.T) {
		real := tempParent(t)
		link := filepath.Join(tempParent(t), "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Enroll(context.Background(), m, filepath.Join(link, "state"), iss.exchange); !errors.Is(err, ErrState) {
			t.Fatalf("Enroll under a symlinked parent = %v; want ErrState", err)
		}
		if ents, _ := os.ReadDir(real); len(ents) != 0 {
			t.Fatalf("written through the symlink: %v", ents)
		}
	})
}

// T-1315 AC3 (Unix half): the key lands in a 0600 file even under a umask of 0, and no temp file is left.
func TestEnrollWritesKeyOwnerOnlyUnderOpenUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	iss, m, dir := setup(t)
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 5 {
		t.Fatalf("entries: %v", ents)
	}
	for _, e := range ents {
		if st, _ := e.Info(); st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", e.Name(), st.Mode())
		}
	}
}
