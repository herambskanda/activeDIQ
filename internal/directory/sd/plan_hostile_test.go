package sd

import (
	"fmt"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// T-0770: the DACL is attacker-controlled directory data. A DACL of about a thousand object ACEs,
// each with its own trustee and object GUID, must not make the rights-change report allocate or
// evaluate without bound: it returns quickly and says it is incomplete.
func TestRightsChangesHostileSize(t *testing.T) {
	const n = 1200
	var aces []ACE
	for i := 0; i < n; i++ {
		g := guid.GUID{}
		g[0], g[1], g[2] = byte(i), byte(i>>8), 1
		typ := uint8(TypeAccessAllowedObject)
		if i%2 == 1 {
			typ = TypeAccessDeniedObject
		}
		aces = append(aces, ACE{Kind: Object, Type: typ, Mask: MaskWriteProp,
			Trustee: mustSID(fmt.Sprintf("S-1-5-21-1-2-3-%d", 1000+i)), ObjectType: &g})
	}
	before := SD{DACL: ACL{ACEs: aces}}
	norm, moves := normalizeOrder(aces)
	after := SD{DACL: ACL{ACEs: norm}}
	if len(moves) == 0 {
		t.Fatal("test setup: nothing moved")
	}
	start := time.Now()
	_, incomplete := rightsChanges(before, after, moves, nil)
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("rightsChanges took %v on a hostile DACL", d)
	}
	if !incomplete {
		t.Error("hostile-size DACL must report ChangesIncomplete")
	}
}
