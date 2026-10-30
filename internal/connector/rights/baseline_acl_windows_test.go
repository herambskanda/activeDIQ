//go:build windows

package rights

import (
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// widenForTest adds an allow ACE for BUILTIN\Users (read) through the typed ACL API.
func widenForTest(t *testing.T, p string) {
	t.Helper()
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	old, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(users)},
	}}, old)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

// Acceptance 1 (T-0537): run on the Windows lab (make lab ... / a Windows host); logs icacls output.
func TestWindowsBaselineAndRecordDACL(t *testing.T) {
	d := t.TempDir()
	bp, rp := filepath.Join(d, "baseline.json"), filepath.Join(d, "records.log")
	if err := (FileBaselineStore{bp}).Save(&Baseline{VerificationID: "v1"}); err != nil {
		t.Fatal(err)
	}
	if err := (FileRecordSink{rp}).WriteShrink(t.Context(), ShrinkRecord{Event: "tier0_set_shrink"}); err != nil {
		t.Fatal(err)
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bp, rp} {
		out, err := exec.Command("icacls", p).CombinedOutput()
		t.Logf("icacls %s\n%s", filepath.Base(p), out)
		if err != nil {
			t.Fatal(err)
		}
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		// The default owner of a file an elevated token creates is BUILTIN\Administrators; ownerfile
		// trusts the token user, SYSTEM and Administrators as owners (its DACL is what restricts).
		system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if o, _, _ := sd.Owner(); !o.Equals(self.User.Sid) && !o.Equals(system) && !o.Equals(admins) {
			t.Fatalf("%s owner %v, want the service identity, SYSTEM or Administrators", p, o)
		}
		acl, _, _ := sd.DACL()
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, i, &ace); err != nil {
				t.Fatal(err)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sid.Equals(self.User.Sid) && !sid.Equals(system) {
				t.Fatalf("%s: unexpected ACE for %v", p, sid)
			}
		}
	}
	// Positive path (T-0577 QA): a file the store just wrote loads and round-trips.
	got, err := (FileBaselineStore{bp}).Load()
	if err != nil {
		t.Fatalf("Load of own baseline: %v", err)
	}
	if got.VerificationID != "v1" {
		t.Fatalf("Load round-trip: VerificationID %q, want v1", got.VerificationID)
	}
	// Negative path: widened DACL is refused with the typed error.
	widenForTest(t, bp)
	if _, err := (FileBaselineStore{bp}).Load(); !errors.Is(err, ErrBaselineUnsafe) {
		t.Fatalf("Load of widened baseline: got %v, want ErrBaselineUnsafe", err)
	}
}
