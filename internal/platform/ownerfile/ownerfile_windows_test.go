//go:build windows

package ownerfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func readDACL(t *testing.T, p string) (map[string]uint32, bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctrl, _, _ := sd.Control()
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatal(err)
	}
	m, ok := aceSet(acl)
	if !ok {
		t.Fatal("unexpected ACE type")
	}
	return m, ctrl&windows.SE_DACL_PROTECTED != 0
}

func assertOwnerOnly(t *testing.T, p string) {
	t.Helper()
	m, protected := readDACL(t, p)
	user, system, err := desiredSIDs()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{user.String(): true, system.String(): true}
	if !protected || len(m) != len(want) {
		t.Fatalf("protected=%v aces=%v", protected, m)
	}
	for sid, mask := range m {
		if !want[sid] || mask != fileAllAccess {
			t.Fatalf("unexpected ACE %s %#x", sid, mask)
		}
	}
}

// Windows-lab evidence for T-0242 AC1/AC2: run `go test ./internal/platform/ownerfile` on a Windows host.
func TestWindowsDACL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.jsonl")
	f, corrected, err := OpenAppend(p)
	if err != nil || corrected {
		t.Fatal(corrected, err)
	}
	_, _ = f.WriteString("x\n")
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	assertOwnerOnly(t, p)

	// Widen: inherit parent ACEs again (unprotected), then reopen: corrected.
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	f, corrected, err = OpenAppend(p)
	if err != nil || !corrected {
		t.Fatal(corrected, err)
	}
	_ = f.Close()
	assertOwnerOnly(t, p)
	if b, _ := os.ReadFile(p); string(b) != "x\n" {
		t.Fatalf("content %q", b)
	}
}

// Review finding 2: the temp file is owner-only from creation, before any write.
func TestWindowsCreateTempDACL(t *testing.T) {
	f, err := CreateTemp(t.TempDir(), ".baseline-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	assertOwnerOnly(t, f.Name())
}

// Review finding 1: a file owned by a foreign SID is refused, not corrected. Needs an elevated
// token with SeRestorePrivilege (the lab runs elevated); skipped otherwise.
func TestWindowsForeignOwnerRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.jsonl")
	f, _, err := OpenAppend(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := enablePrivilege("SeRestorePrivilege"); err != nil {
		t.Skipf("SeRestorePrivilege unavailable: %v", err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, everyone, nil, nil, nil); err != nil {
		t.Skipf("cannot set foreign owner: %v", err)
	}
	if _, _, err := OpenAppend(p); !errors.Is(err, ErrForeignOwner) {
		t.Fatalf("want ErrForeignOwner, got %v", err)
	}
}

func enablePrivilege(name string) error {
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
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
		return windows.ERROR_NOT_ALL_ASSIGNED
	}
	return nil
}

func TestWindowsReparsePointRefused(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "t")
	_ = os.WriteFile(target, []byte("t"), 0o600)
	link := filepath.Join(d, "l")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := OpenAppend(link); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("want ErrNotRegular, got %v", err)
	}
}
