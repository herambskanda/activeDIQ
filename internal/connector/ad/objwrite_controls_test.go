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
