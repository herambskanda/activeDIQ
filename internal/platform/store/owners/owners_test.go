package owners_test

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store/owners"
)

// The map is generated from the migrations (tools/gen/modules; `make gen-modules-check` proves it is
// current). These pin the answers other packages rely on.
func TestLookupAndClassOf(t *testing.T) {
	for _, tc := range []struct {
		table, owner string
		class        owners.Class
	}{
		{"report_runs", "reports", owners.System},
		{"report_run_rows", "reports", owners.System},
		{"directory_objects", "inventory", owners.System},
		{"inventory_servers", "invhost", owners.Config},
		{"authz_assignments", "authz", owners.Config},
		{"connections", "connection", owners.Config},
		{"audit_event", "audit", owners.System},
	} {
		owner, ok := owners.Lookup(tc.table)
		if !ok || owner != tc.owner {
			t.Errorf("Lookup(%q) = %q, %v; want %q", tc.table, owner, ok, tc.owner)
		}
		if class, ok := owners.ClassOf(tc.table); !ok || class != tc.class {
			t.Errorf("ClassOf(%q) = %q, %v; want %q", tc.table, class, ok, tc.class)
		}
	}
}

func TestUnknownTableFailsClosed(t *testing.T) {
	for _, table := range []string{"", "no_such_table", "public.report_runs", "REPORT_RUNS"} {
		if owner, ok := owners.Lookup(table); ok || owner != "" {
			t.Errorf("Lookup(%q) = %q, %v; want no owner", table, owner, ok)
		}
		if class, ok := owners.ClassOf(table); ok || class != "" {
			t.Errorf("ClassOf(%q) = %q, %v; want no class", table, class, ok)
		}
	}
}

// The key-custody tables stay answerable from the embedded data even though no Go source may name them
// (ADR-0007 P8, FF-KEY-2 scan this very file), so this checks by owner key, not by table name.
func TestKeyCustodyOwnersAreMapped(t *testing.T) {
	seen := map[string]int{}
	for _, table := range owners.Tables() {
		o, _ := owners.Lookup(table)
		seen[o]++
	}
	for _, owner := range []string{"agentpolicy", "keys"} {
		if seen[owner] == 0 {
			t.Errorf("no table is mapped to owner %q", owner)
		}
	}
}
