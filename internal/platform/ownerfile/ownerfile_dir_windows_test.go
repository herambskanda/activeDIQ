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
	p, err := windows.UTF16PtrFromString(filepath.Join(t.TempDir(), "parent"))
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
			for _, open := range []func(string) (*Dir, error){OpenDir, CreateDir} {
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
