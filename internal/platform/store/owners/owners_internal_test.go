package owners

import "testing"

// The key-custody tables stay answerable from the embedded data even though no Go source may name them
// (ADR-0007 P8, FF-KEY-2 scan this very file), so this checks by owner key, not by table name. It is an
// internal test so it can iterate byTable: the package exports no function that enumerates tables.
func TestKeyCustodyOwnersAreMapped(t *testing.T) {
	seen := map[string]int{}
	for _, e := range byTable {
		seen[e.owner]++
	}
	for _, owner := range []string{"agentpolicy", "keys"} {
		if seen[owner] == 0 {
			t.Errorf("no table is mapped to owner %q", owner)
		}
	}
}
