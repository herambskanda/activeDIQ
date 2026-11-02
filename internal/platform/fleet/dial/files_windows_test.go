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
	if err := checkDir(dir, ""); err != nil {
		t.Fatalf("checkDir: %v", err)
	}
	if err := checkFile(filepath.Join(dir, KeyFile), true, ""); err != nil {
		t.Fatalf("key.pem: %v", err)
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

// ownerOnlyDir creates dir with the production protected DACL (what ensureDir would create).
func ownerOnlyDir(t *testing.T, dir string) {
	t.Helper()
	sd, err := ownerOnlySD("")
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

// positiveControl proves checkDir/Enroll/Load accept a correctly built owner-only directory, so the
// refusal tests below fail if checkACL is wrong in either direction (never vacuously pass).
func positiveControl(t *testing.T, m Material, iss *issuer) {
	t.Helper()
	good := filepath.Join(t.TempDir(), "control")
	ownerOnlyDir(t, good)
	if err := checkDir(good, ""); err != nil {
		t.Fatalf("positive control: checkDir refused a correct owner-only dir: %v", err)
	}
	if _, err := Enroll(context.Background(), m, good, iss.exchange); err != nil {
		t.Fatalf("positive control: Enroll refused a correct owner-only dir: %v", err)
	}
	if _, err := Load(good); err != nil {
		t.Fatalf("positive control: Load refused a correct owner-only dir: %v", err)
	}
}

func refuseBoth(t *testing.T, m Material, iss *issuer, dir string) {
	t.Helper()
	if err := checkDir(dir, ""); err == nil {
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
	positiveControl(t, m, iss)
	ownerOnlyDir(t, dir)
	if err := checkDir(dir, ""); err != nil { // accepted before the owner changes
		t.Fatalf("checkDir refused the unmodified owner-only dir: %v", err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	// Needs SeRestorePrivilege (elevated lab shell) to assign an owner that is not the caller.
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("not elevated: assigning an owner needs SeRestorePrivilege (the lab run is elevated)")
	}
	if err := enablePrivilege("SeRestorePrivilege"); err != nil { // elevated but cannot: a real failure, not a skip
		t.Fatalf("SeRestorePrivilege unavailable although elevated: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, users, nil, nil, nil); err != nil {
		t.Fatalf("set owner: %v", err)
	}
	refuseBoth(t, m, iss, dir)
}

// Acceptance 2 (b): protected, owned by self, plus exactly one extra Users allow ACE.
func TestWindowsRefusesDirWithExtraACE(t *testing.T) {
	iss, m, dir := setup(t)
	positiveControl(t, m, iss)
	ownerOnlyDir(t, dir)
	if err := checkDir(dir, ""); err != nil { // accepted before the extra ACE
		t.Fatalf("checkDir refused the unmodified owner-only dir: %v", err)
	}
	widenKeepProtected(t, dir)
	refuseBoth(t, m, iss, dir)
}

// A junction at the state path pointing at an owner-only directory is refused, and isReparse sees it
// directly (independent of Go's winsymlink mapping).
func TestWindowsRefusesJunction(t *testing.T) {
	iss, m, dir := setup(t)
	positiveControl(t, m, iss)
	target := filepath.Join(t.TempDir(), "target")
	ownerOnlyDir(t, target)
	if err := checkDir(target, ""); err != nil { // the target itself is fine; only the junction is refused
		t.Fatalf("checkDir refused the owner-only junction target: %v", err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if !isReparse(dir) {
		t.Fatal("isReparse missed a junction")
	}
	if isReparse(target) {
		t.Fatal("isReparse flagged a plain directory")
	}
	if err := checkDir(dir, ""); err == nil {
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
	if err := writeFile(key, orig, ""); err != nil {
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

// T-1249: an administrator enrols FOR the service. The state must name SYSTEM, Administrators and the
// service account, be owned by Administrators, and must not name the invoking user. NT AUTHORITY\LOCAL
// SERVICE stands in for NT SERVICE\activeDIQAgent here because it resolves without a service; the real
// identity is proven on the lab DC (lab/windows/bin/agent-unenrolled-verify). Needs an elevated token
// (setting the owner to Administrators); the lab and CI run elevated.
func TestWindowsEnrolForAccountNamesTheAccountNotTheCaller(t *testing.T) {
	const acct = `NT AUTHORITY\LOCAL SERVICE`
	// Skip only when the token is not elevated (the one documented reason it cannot work). When elevated,
	// any Enroll(ForAccount) error is the regression this test exists to catch and fails it.
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("not elevated: enrolling for another account sets the owner to Administrators (the lab run is elevated)")
	}
	iss, m, dir := setup(t)
	if _, err := Enroll(context.Background(), m, dir, iss.exchange, ForAccount(acct)); err != nil {
		t.Fatalf("Enroll(ForAccount(%q)) in an elevated token: %v", acct, err)
	}
	svc, _, _, err := windows.LookupSID("", acct)
	if err != nil {
		t.Fatal(err)
	}
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, filepath.Join(dir, KeyFile), filepath.Join(dir, LeafFile)} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, _ := sd.Owner()
		if !owner.Equals(admins) {
			t.Errorf("%s owner = %s, want Administrators", filepath.Base(p), owner)
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil {
			t.Fatalf("%s: no DACL: %v", p, err)
		}
		sawSvc := false
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, i, &ace); err != nil {
				t.Fatal(err)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			sawSvc = sawSvc || sid.Equals(svc)
			if !tu.User.Sid.Equals(admins) && sid.Equals(tu.User.Sid) {
				t.Errorf("%s: DACL names the invoking user %s", filepath.Base(p), sid)
			}
		}
		if !sawSvc {
			t.Errorf("%s: DACL does not name %s", filepath.Base(p), acct)
		}
	}
	// Checked as the account it was written for: accepted. Checked as this (different) caller: refused,
	// and the refusal is the unsafe class, not "absent".
	if _, err := load(dir, acct); err != nil {
		t.Fatalf("load for the account: %v", err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrUnsafe) || errors.Is(err, ErrAbsent) {
		t.Fatalf("Load as the caller = %v, want ErrUnsafe", err)
	}
}

func TestWindowsForAccountUnresolvableFailsBeforeAnythingIsWritten(t *testing.T) {
	iss, m, dir := setup(t)
	if _, err := Enroll(context.Background(), m, dir, iss.exchange, ForAccount(`NT SERVICE\diqNoSuchService`)); err == nil {
		t.Fatal("enrolled for an account that does not resolve")
	}
	assertNothingPersisted(t, dir)
}
