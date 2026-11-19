package sd

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

func TestPrincipalFromSIDSetCompleteness(t *testing.T) {
	a := mustSID("S-1-5-21-1-2-3-1000")
	if PrincipalFromSIDSet([]sid.SID{a}, true).Incomplete() {
		t.Fatal("a complete non-empty set is complete")
	}
	if !PrincipalFromSIDSet([]sid.SID{a}, false).Incomplete() || !PrincipalFromSIDSet(nil, true).Incomplete() {
		t.Fatal("incomplete flag and empty set must both give Incomplete")
	}
}
