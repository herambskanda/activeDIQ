package scope

import "testing"

func TestNamedControls(t *testing.T) {
	if got := ShowDeleted().GetControlType(); got != "1.2.840.113556.1.4.417" {
		t.Fatalf("ShowDeleted OID = %q", got)
	}
	if got := ShowDeactivatedLink().GetControlType(); got != "1.2.840.113556.1.4.2065" {
		t.Fatalf("ShowDeactivatedLink OID = %q", got)
	}
	if n := len(ShowDeleted().Encode().Children); n != 2 {
		t.Fatalf("show-deleted must be critical (2 children), got %d", n)
	}
	if n := len(ShowDeactivatedLink().Encode().Children); n != 1 {
		t.Fatalf("show-deactivated-link must be non-critical (1 child), got %d", n)
	}
}
