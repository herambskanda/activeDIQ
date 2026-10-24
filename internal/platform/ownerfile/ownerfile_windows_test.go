//go:build windows

package ownerfile

import (
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
