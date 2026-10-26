//go:build windows

package dial

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// widen adds an allow ACE for BUILTIN\Users to path's DACL (and unprotects it), as ProgramData would.
func widen(t *testing.T, path string) {
	t.Helper()
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	old, _, _ := sd.DACL()
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ | windows.GENERIC_WRITE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(users)},
	}}, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

// Acceptance 1: the directory is created with a protected owner-only DACL and Load accepts it.
func TestWindowsStateDirIsOwnerOnly(t *testing.T) {
	iss, m, dir := setup(t)
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); err != nil {
		t.Fatal(err)
	}
	if err := checkDir(dir); err != nil {
		t.Fatalf("checkDir: %v", err)
	}
	if err := checkFile(filepath.Join(dir, KeyFile), true); err != nil {
		t.Fatalf("key.pem: %v", err)
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

// Acceptance 2: a pre-created wider directory is refused by Enroll (nothing written) and by Load.
func TestWindowsRefusesSquattedDir(t *testing.T) {
	iss, m, dir := setup(t)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	widen(t, dir)
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); err == nil {
		t.Fatal("Enroll accepted a wider pre-existing directory")
	}
	assertNothingPersisted(t, dir)
}

func TestWindowsLoadRefusesWidenedState(t *testing.T) {
	iss, m, dir := setup(t)
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); err != nil {
		t.Fatal(err)
	}
	widen(t, filepath.Join(dir, KeyFile))
	if _, err := Load(dir); !errors.Is(err, ErrState) {
		t.Fatalf("Load with widened key.pem = %v, want ErrState", err)
	}
	widen(t, dir)
	if _, err := Load(dir); !errors.Is(err, ErrState) {
		t.Fatalf("Load with widened dir = %v, want ErrState", err)
	}
}
