//go:build windows

package dial

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// widen adds an allow ACE for BUILTIN\Users to path's DACL (and unprotects it), as ProgramData would.
func widen(t *testing.T, path string) {
	t.Helper()
	widenFlag(t, path, windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
}

// widenKeepProtected adds the Users ACE but keeps the DACL protected.
func widenKeepProtected(t *testing.T, path string) {
	t.Helper()
	widenFlag(t, path, windows.PROTECTED_DACL_SECURITY_INFORMATION)
}

func widenFlag(t *testing.T, path string, prot windows.SECURITY_INFORMATION) {
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
		windows.DACL_SECURITY_INFORMATION|prot, nil, nil, acl, nil); err != nil {
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

// ownerOnlyDir creates dir with the production protected DACL (what ensureDir would create).
func ownerOnlyDir(t *testing.T, dir string) {
	t.Helper()
	sd, err := ownerOnlySD()
	if err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, sa); err != nil {
		t.Fatal(err)
	}
}

func refuseBoth(t *testing.T, m Material, iss *issuer, dir string) {
	t.Helper()
	if err := checkDir(dir); err == nil {
		t.Fatal("checkDir accepted the directory")
	}
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); err == nil {
		t.Fatal("Enroll accepted the directory")
	}
	assertNothingPersisted(t, dir)
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted the directory")
	}
}

// Acceptance 2 (a): protected DACL but owned by another principal (BUILTIN\Users), isolating the owner check.
func TestWindowsRefusesDirOwnedByAnother(t *testing.T) {
	iss, m, dir := setup(t)
	ownerOnlyDir(t, dir)
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	// Needs SeRestorePrivilege (elevated lab shell) to assign an owner that is not the caller.
	if err := enablePrivilege("SeRestorePrivilege"); err != nil {
		t.Skipf("SeRestorePrivilege unavailable (run elevated): %v", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, users, nil, nil, nil); err != nil {
		t.Fatalf("set owner: %v", err)
	}
	refuseBoth(t, m, iss, dir)
}

// Acceptance 2 (b): protected, owned by self, plus exactly one extra Users allow ACE.
func TestWindowsRefusesDirWithExtraACE(t *testing.T) {
	iss, m, dir := setup(t)
	ownerOnlyDir(t, dir)
	widenKeepProtected(t, dir)
	refuseBoth(t, m, iss, dir)
}

// A junction at the state path pointing at an owner-only directory is refused, and isReparse sees it
// directly (independent of Go's winsymlink mapping).
func TestWindowsRefusesJunction(t *testing.T) {
	iss, m, dir := setup(t)
	target := filepath.Join(t.TempDir(), "target")
	ownerOnlyDir(t, target)
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if !isReparse(dir) {
		t.Fatal("isReparse missed a junction")
	}
	if isReparse(target) {
		t.Fatal("isReparse flagged a plain directory")
	}
	if err := checkDir(dir); err == nil {
		t.Fatal("checkDir accepted a junction")
	}
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); err == nil {
		t.Fatal("Enroll accepted a junction")
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a junction")
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Fatalf("something was written through the junction: %v", ents)
	}
}

func TestWindowsLoadRefusesWidenedState(t *testing.T) {
	iss, m, dir := setup(t)
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, KeyFile)
	orig, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	widen(t, key)
	if _, err := Load(dir); !errors.Is(err, ErrState) {
		t.Fatalf("Load with widened key.pem = %v, want ErrState", err)
	}
	// Restore key.pem (fresh owner-only file) so the dir assertion below is independent.
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(key, orig); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("Load after restoring key.pem: %v", err)
	}
	widen(t, dir)
	if _, err := Load(dir); !errors.Is(err, ErrState) {
		t.Fatalf("Load with widened dir = %v, want ErrState", err)
	}
}

func enablePrivilege(name string) error {
	var luid windows.LUID
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		return err
	}
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
		return err
	}
	if windows.GetLastError() == windows.ERROR_NOT_ALL_ASSIGNED {
		return errors.New("privilege not held")
	}
	return nil
}
