package ad

import "testing"

// The deleted-object read must send show-deleted together with show-deactivated-link, or the
// retained memberOf is invisible on Windows (MS-ADTS 3.1.1.3.4.1.25).
func TestDeletedControlsIncludeDeactivatedLink(t *testing.T) {
	got := map[string]bool{}
	for _, c := range deletedControls() {
		got[c.GetControlType()] = true
	}
	if !got["1.2.840.113556.1.4.417"] || !got["1.2.840.113556.1.4.2065"] {
		t.Fatalf("controls: %v", got)
	}
}
