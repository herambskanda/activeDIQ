//go:build windows

package dial

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// widenParent grants BUILTIN\Users create-files/create-subfolders on parent, as the ProgramData
// default does for the folders below it (icacls by well-known SID, so it is locale independent).
func widenParent(t *testing.T, parent string) {
	t.Helper()
	if out, err := exec.Command("icacls", parent, "/grant", "*S-1-5-32-545:(CI)(WD,AD)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v\n%s", err, out)
	}
}

// T-1315 AC2 (Windows lab): Enroll and Load refuse a parent that Users can create in (so a squatter
// can rename the state directory away) and write nothing; the same flow in a trusted parent works.
func TestWindowsStateRefusesWritableParent(t *testing.T) {
	iss, m, _ := setup(t)
	if _, err := Enroll(context.Background(), m, filepath.Join(tempParent(t), "state"), iss.exchange); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	parent := tempParent(t)
	good := filepath.Join(parent, "state")
	if _, err := Enroll(context.Background(), m, good, iss.exchange); err != nil {
		t.Fatalf("positive control (same parent, before widening): %v", err)
	}
	widenParent(t, parent)
	if _, err := Load(good); !errors.Is(err, ErrState) {
		t.Fatalf("Load under a Users-writable parent = %v; want ErrState", err)
	}
	other := filepath.Join(parent, "other")
	if _, err := Enroll(context.Background(), m, other, iss.exchange); !errors.Is(err, ErrState) {
		t.Fatalf("Enroll under a Users-writable parent = %v; want ErrState", err)
	}
	if _, err := os.Lstat(other); err == nil {
		t.Fatal("Enroll created a directory under an untrusted parent")
	}
}

// T-1315 AC1 (Windows lab): a junction at the state path is refused by Load and Enroll and the target
// (a valid enrolment of its own) is neither read nor written.
func TestWindowsStateRefusesJunction(t *testing.T) {
	iss, m, dir := setup(t)
	foreignIss, foreignM, foreign := setup(t)
	if _, err := Enroll(context.Background(), foreignM, foreign, foreignIss.exchange); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(foreign); err != nil {
		t.Fatalf("control: %v", err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, foreign).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if _, err := Load(dir); !errors.Is(err, ErrState) {
		t.Fatalf("Load through a junction = %v; want ErrState", err)
	}
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); !errors.Is(err, ErrState) {
		t.Fatalf("Enroll through a junction = %v; want ErrState", err)
	}
	if ents, _ := os.ReadDir(foreign); len(ents) != 5 {
		t.Fatalf("the target was written to: %d entries", len(ents))
	}
}
