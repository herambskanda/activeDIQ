package inventory_test

import (
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
)

// LAB-PS-12: an unreadable Password Settings Container returns zero entries and no error, so an empty
// result alone never counts as "the set was read".
func TestPSOSetRead_EmptyIsNotRead(t *testing.T) {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		r    inventory.PSOSetRead
		read bool
	}{
		{"zero entries, readability unproven", inventory.PSOSetRead{}, false},
		{"zero entries, list proven (no PSOs defined)", inventory.PSOSetRead{ListProven: true}, true},
		{"entries returned", inventory.PSOSetRead{Returned: 3}, true},
	} {
		if got := !c.r.ReadAt(at).IsZero(); got != c.read {
			t.Errorf("%s: read = %v, want %v", c.name, got, c.read)
		}
	}
}
