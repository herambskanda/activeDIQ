//go:build windows

package ownerfile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustedParent is a directory that passes the parent check: created by this test with an explicit
// PROTECTED DACL of the service identity, SYSTEM and Administrators only (what the installer does).
func trustedParent(t *testing.T) string {
	t.Helper()
	return trustedDirAt(t, filepath.Join(t.TempDir(), "parent"))
}

// trustedDirAt creates path with the trusted-parent descriptor.
func trustedDirAt(t *testing.T, path string) string {
	t.Helper()
	user, system, err := desiredSIDs()
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	var ea []windows.EXPLICIT_ACCESS
	for _, s := range []*windows.SID{user, system, admins} {
		ea = append(ea, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS,
			Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee:     windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(s)},
		})
	}
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		t.Fatal(err)
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, sa); err != nil {
		t.Fatal(err)
	}
	return windows.UTF16PtrToString(p)
}

func TestWindowsDirCreateWriteRead(t *testing.T) {
	dir := filepath.Join(trustedParent(t), "state")
	d, err := CreateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.WriteFile("key.pem", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if b, err := d.ReadFile("key.pem"); err != nil || string(b) != "secret" {
		t.Fatalf("%q %v", b, err)
	}
	// T-1315 AC3: the file was created from an explicit protected descriptor (a file that inherited
	// from its directory would not carry SE_DACL_PROTECTED) and the DACL is the service identity and
	// SYSTEM only.
	assertOwnerOnly(t, filepath.Join(dir, "key.pem"))
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
	out, _ := exec.Command("icacls", dir).CombinedOutput()
	t.Logf("icacls state dir\n%s", out)
}

// T-1315 AC2 (Windows): parents the installer would never create are refused by OpenDir and CreateDir,
// and CreateDir creates nothing. The positive control uses the same layout before the mutation.
func TestWindowsDirRefusesUntrustedParent(t *testing.T) {
	for name, tc := range map[string]struct{ sid, perm string }{
		"users-create-files": {"S-1-5-32-545", "(CI)(WD,AD)"}, // the ProgramData default shape
		"users-write":        {"S-1-5-32-545", "(OI)(CI)(M)"},
		"users-delete-child": {"S-1-5-32-545", "(OI)(CI)(DC)"},
		"everyone-full":      {"S-1-1-0", "(OI)(CI)(F)"},
	} {
		t.Run(name, func(t *testing.T) {
			parent := trustedParent(t)
			ctl, err := CreateDir(filepath.Join(parent, "control"))
			if err != nil {
				t.Fatalf("positive control: %v", err)
			}
			ctl.Close()
			widenACL(t, parent, tc.sid, tc.perm)
			for _, open := range []func(string, ...DirOption) (*Dir, error){OpenDir, CreateDir} {
				d, err := open(filepath.Join(parent, "control"))
				if err == nil {
					d.Close()
					t.Fatal("untrusted parent accepted")
				}
				if !errors.Is(err, ErrParentUnsafe) {
					t.Fatalf("want ErrParentUnsafe, got %v", err)
				}
			}
			if d, err := CreateDir(filepath.Join(parent, "state")); err == nil {
				d.Close()
				t.Fatal("CreateDir accepted")
			}
			if _, err := os.Lstat(filepath.Join(parent, "state")); err == nil {
				t.Fatal("CreateDir created the directory under an untrusted parent")
			}
		})
	}
}

// A read-only grant to Users on the parent is harmless and must still be accepted (the check is on
// write-class rights, not on the presence of other principals).
func TestWindowsDirAcceptsReadOnlyForOthers(t *testing.T) {
	parent := trustedParent(t)
	widenACL(t, parent, "S-1-5-32-545", "(OI)(CI)(RX)")
	d, err := CreateDir(filepath.Join(parent, "state"))
	if err != nil {
		t.Fatalf("read-only grant refused: %v", err)
	}
	d.Close()
}

func TestWindowsDirRefusesParentJunctionAndForeignOwner(t *testing.T) {
	real := trustedParent(t)
	if d, err := CreateDir(filepath.Join(real, "state")); err != nil { // control
		t.Fatal(err)
	} else {
		d.Close()
	}
	link := filepath.Join(t.TempDir(), "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, real).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if d, err := OpenDir(filepath.Join(link, "state")); !errors.Is(err, ErrParentUnsafe) {
		if d != nil {
			d.Close()
		}
		t.Fatalf("junction parent: want ErrParentUnsafe, got %v", err)
	}
}

// T-1315 AC1 (Windows): with the directory open, replacing it by a junction to a directory of valid
// foreign files either fails outright (the handle has no FILE_SHARE_DELETE, so the rename is a sharing
// violation) or, if it ever succeeds, the held handle still never returns the foreign bytes. A fresh
// open by path is refused in both cases.
func TestWindowsDirSwappedForJunctionNeverReadsForeignContents(t *testing.T) {
	parent := trustedParent(t)
	dir := filepath.Join(parent, "state")
	foreignDir := filepath.Join(parent, "foreign")
	for p, body := range map[string]string{dir: "REAL", foreignDir: "FORGED"} {
		d, err := CreateDir(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.WriteFile("pin", []byte(body)); err != nil {
			t.Fatal(err)
		}
		d.Close()
	}
	held, err := OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if b, err := held.ReadFile("pin"); err != nil || string(b) != "REAL" { // positive control
		t.Fatalf("control: %q %v", b, err)
	}

	renameErr := os.Rename(dir, dir+".away")
	if renameErr == nil {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, foreignDir).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v: %s", err, out)
		}
		t.Log("rename of the held directory succeeded (unexpected); checking the read anyway")
	} else {
		t.Logf("rename of the held directory refused as designed: %v", renameErr)
	}
	if b, err := held.ReadFile("pin"); err == nil && string(b) != "REAL" {
		t.Fatalf("held handle returned foreign bytes %q", b)
	}
	if renameErr == nil {
		if d, err := OpenDir(dir); err == nil {
			d.Close()
			t.Fatal("OpenDir followed the junction")
		}
	}
}

// Unit tests of the ACL rule on synthetic ACLs.
func TestWindowsCheckParentACL(t *testing.T) {
	users, _ := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	user, system, _ := desiredSIDs()
	entry := func(s *windows.SID, access windows.ACCESS_MASK, mode windows.ACCESS_MODE, inh uint32) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{AccessPermissions: access, AccessMode: mode, Inheritance: inh,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(s)}}
	}
	const read = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE
	cases := []struct {
		name string
		ea   []windows.EXPLICIT_ACCESS
		ok   bool
	}{
		{"trusted only", []windows.EXPLICIT_ACCESS{entry(user, fileAllAccess, windows.GRANT_ACCESS, windows.NO_INHERITANCE), entry(system, fileAllAccess, windows.GRANT_ACCESS, windows.NO_INHERITANCE)}, true},
		{"users read", []windows.EXPLICIT_ACCESS{entry(users, read, windows.GRANT_ACCESS, windows.NO_INHERITANCE)}, true},
		{"users add file", []windows.EXPLICIT_ACCESS{entry(users, fileWriteData, windows.GRANT_ACCESS, windows.NO_INHERITANCE)}, false},
		{"users delete child", []windows.EXPLICIT_ACCESS{entry(users, fileDeleteChild, windows.GRANT_ACCESS, windows.NO_INHERITANCE)}, false},
		{"users write dac", []windows.EXPLICIT_ACCESS{entry(users, accessWriteDAC, windows.GRANT_ACCESS, windows.NO_INHERITANCE)}, false},
		{"users all, inherit only", []windows.EXPLICIT_ACCESS{entry(users, fileAllAccess, windows.GRANT_ACCESS, windows.INHERIT_ONLY_ACE|windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE)}, true},
		{"users deny write", []windows.EXPLICIT_ACCESS{entry(users, fileWriteData, windows.DENY_ACCESS, windows.NO_INHERITANCE)}, true},
	}
	for _, c := range cases {
		acl, err := windows.ACLFromEntries(c.ea, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = checkParentACL(acl, []*windows.SID{user, system}, ErrParentUnsafe)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// T-1315 review finding 2: a rename of an ANCESTOR of the state directory after OpenDir (the parent
// check covers one level only). The held handle's final path changes, so ReadFile and WriteFile are
// refused, and nothing is written under the path that is rebuilt. If the file system refuses the
// rename of an ancestor that holds an open handle, the test only runs the positive control.
func TestWindowsDirAncestorRenameNeverRedirectsIO(t *testing.T) {
	grand := trustedParent(t)
	mid := trustedDirAt(t, filepath.Join(grand, "mid"))
	dir := filepath.Join(mid, "state")
	d, err := CreateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.WriteFile("pin", []byte("REAL")); err != nil { // positive control
		t.Fatalf("control write: %v", err)
	}
	if b, err := d.ReadFile("pin"); err != nil || string(b) != "REAL" {
		t.Fatalf("control read: %q %v", b, err)
	}

	if err := os.Rename(mid, mid+".away"); err != nil {
		t.Logf("rename of an ancestor of the held directory refused by the file system: %v", err)
		return
	}
	// Rebuild the path the attacker wants the component to use.
	trustedDirAt(t, mid)
	rebuilt, err := CreateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt.Close()
	if _, err := d.ReadFile("pin"); err == nil {
		t.Fatal("ReadFile succeeded after an ancestor was renamed")
	}
	if err := d.WriteFile("key.pem", []byte("secret")); err == nil {
		t.Fatal("WriteFile succeeded after an ancestor was renamed")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("something was written under the rebuilt path: %v", ents)
	}
}

// T-1249: an administrator writes state for another account. The directory and its files are owned by
// Administrators and name SYSTEM, Administrators and that account, never the caller's user SID; the
// account is what OpenDir(ForAccount) then verifies, and the default OpenDir (which would be the
// service, whose token user is the account) accepts it only with TrustAdministrators.
func TestWindowsForAccountNamesAccountNotCaller(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("not elevated: owning a directory as Administrators needs the enabled group (the lab run is elevated)")
	}
	const account = `BUILTIN\Users` // stands for NT SERVICE\activeDIQAgent: any resolvable account that is not the caller
	acct, _, _, err := windows.LookupSID("", account)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(trustedParent(t), "state")
	d, err := CreateDir(dir, ForAccount(account))
	if err != nil {
		t.Fatalf("CreateDir: %v", err)
	}
	if err := d.WriteFile("a", []byte("x")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	d.Close()

	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	user, _, _ := desiredSIDs()
	for _, p := range []string{dir, filepath.Join(dir, "a")} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if o, _, _ := sd.Owner(); o == nil || !o.Equals(admins) {
			t.Fatalf("%s owner = %v, want Administrators", filepath.Base(p), o)
		}
		acl, _, _ := sd.DACL()
		var sawAcct bool
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, i, &ace); err != nil {
				t.Fatal(err)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			sawAcct = sawAcct || sid.Equals(acct)
			if sid.Equals(user) && !user.Equals(admins) {
				t.Fatalf("%s names the invoking user", filepath.Base(p))
			}
		}
		if !sawAcct {
			t.Fatalf("%s does not name the account", filepath.Base(p))
		}
	}
	// The account's view accepts it; a caller that does not trust Administrators refuses it.
	o, err := OpenDir(dir, ForAccount(account))
	if err != nil {
		t.Fatalf("OpenDir(ForAccount): %v", err)
	}
	if b, err := o.ReadFile("a"); err != nil || string(b) != "x" {
		t.Fatalf("ReadFile = %q, %v", b, err)
	}
	o.Close()
	if _, err := OpenDir(dir); err == nil {
		t.Fatal("default OpenDir accepted an Administrators-owned directory")
	}
}

func TestWindowsForAccountUnknownAccountFailsBeforeWriting(t *testing.T) {
	dir := filepath.Join(trustedParent(t), "state")
	if _, err := CreateDir(dir, ForAccount(`NT SERVICE\noSuchServiceT1249`)); err == nil {
		t.Fatal("CreateDir accepted an account that does not resolve")
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("the directory was created for an account that does not resolve")
	}
}
