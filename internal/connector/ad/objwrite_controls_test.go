package ad

import "testing"

const (
	oidTestShowDeleted         = "1.2.840.113556.1.4.417"
	oidTestShowDeactivatedLink = "1.2.840.113556.1.4.2065"
)

func controlSet(opts ReadOptions) map[string]bool {
	got := map[string]bool{}
	for _, c := range visibilityControls(opts) {
		got[c.GetControlType()] = true
	}
	return got
}

// The classification read of a deleted object sends show-deleted together with show-deactivated-link,
// or the retained memberOf is invisible on Windows (MS-ADTS 3.1.1.3.4.1.25).
func TestDeletedTargetReadControls(t *testing.T) {
	got := controlSet(ReadOptions{showDeleted: true, ShowDeactivatedLink: true, ExtendedDN: true})
	if !got[oidTestShowDeleted] || !got[oidTestShowDeactivatedLink] || len(got) != 3 {
		t.Fatalf("controls: %v", got)
	}
}

// GroupMembers reads a live group: 2065 and extended-DN, never 417 (TM-D33 rule 3: the show-deleted
// control exists only in the fixed-shape deleted reads).
func TestGroupMembersControlsExcludeShowDeleted(t *testing.T) {
	got := controlSet(groupMemberOptions)
	if got[oidTestShowDeleted] {
		t.Fatal("GroupMembers sends show-deleted (417)")
	}
	if !got[oidTestShowDeactivatedLink] {
		t.Fatal("GroupMembers lacks show-deactivated-link (2065)")
	}
}

// The exported options cannot ask for show-deleted: with every exported field set, 417 is absent.
func TestExportedReadOptionsNeverShowDeleted(t *testing.T) {
	got := controlSet(ReadOptions{ShowDeactivatedLink: true, ExtendedDN: true, Ranged: []string{"member"}})
	if got[oidTestShowDeleted] {
		t.Fatal("exported ReadOptions produced show-deleted")
	}
}

// TM-F-RIGHTS (b): the show-deleted analyser (tools/analyzers/showdeleted) pins the shape of the
// deleted reads; the values it cannot see are pinned here. A change to either list is a security
// change: the (b1) list is the fixed R2 set (T-1757 added sAMAccountName), the (b3) list is the
// restore-state set, and both reads send owner+group+DACL only (0x7), never the SACL.
func TestDeletedReadFixedLists(t *testing.T) {
	wantB1 := []string{"objectSid", "userAccountControl", "primaryGroupID", "isRecycled",
		"objectGUID", "objectClass", "isDeleted", "lastKnownParent", "msDS-LastKnownRDN", "nTSecurityDescriptor",
		"sIDHistory", "memberOf", "adminCount", "msDS-AllowedToDelegateTo",
		"msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-SecondaryKrbTgtNumber", "isCriticalSystemObject"}
	if got := deletedTargetAttrs; len(got) != len(wantB1) {
		t.Fatalf("(b1) attribute list: %v", got)
	} else {
		for i := range got {
			if got[i] != wantB1[i] {
				t.Fatalf("(b1) attribute %d: %q, want %q", i, got[i], wantB1[i])
			}
		}
	}
	wantB3 := []string{"objectGUID", "objectClass", "distinguishedName", "isDeleted", "instanceType", "uSNChanged"}
	if len(stateAttrs) != len(wantB3) {
		t.Fatalf("(b3) attribute list: %v", stateAttrs)
	}
	for i := range wantB3 {
		if stateAttrs[i] != wantB3[i] {
			t.Fatalf("(b3) attribute %d: %q, want %q", i, stateAttrs[i], wantB3[i])
		}
	}
	if v := DefaultSDFlags().Value(); v != 0x7 {
		t.Fatalf("(b1) SD_FLAGS %#x, want 0x7", v)
	}
	f, err := NewSDFlags(SDOwner, SDDACL)
	if err != nil || f.Value() != 0x5 {
		t.Fatalf("(b2) SD_FLAGS %v %v, want 0x5", f, err)
	}
}
