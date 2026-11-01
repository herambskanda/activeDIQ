//go:build windows

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// Windows-only. Not run in the Linux authoring environment; T-0648 runs it in the lab (it needs no
// admin rights: it edits strings, not a live channel).
func TestEditSDDLGrantThenRevokeKeepsOtherACEs(t *testing.T) {
	const base = "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;ER)"
	sid, err := windows.StringToSid("S-1-5-80-1234567890-1-2-3-4")
	if err != nil {
		t.Fatal(err)
	}
	count := func(sddl string) uint16 {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		return acl.AceCount
	}
	granted, err := editSDDL(base, sid, true)
	if err != nil {
		t.Fatal(err)
	}
	if count(granted) != count(base)+1 || !strings.Contains(granted, sid.String()) {
		t.Fatalf("grant added %d ACEs; want exactly one for the service SID: %s", int(count(granted))-int(count(base)), granted)
	}
	revoked, err := editSDDL(granted, sid, false)
	if err != nil {
		t.Fatal(err)
	}
	if count(revoked) != count(base) || strings.Contains(revoked, sid.String()) {
		t.Fatalf("revoke did not restore the original ACE set: %s", revoked)
	}
	for _, other := range []string{"SY", "BA", "ER"} {
		if !strings.Contains(revoked, other) {
			t.Errorf("revoke dropped the ACE for %s: %s", other, revoked)
		}
	}
}
