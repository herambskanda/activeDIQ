package inventory_test

import (
	"slices"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/modules/inventory"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

// The class and permission the rbac and client packages key on are this module's (relocated from
// compose/server, ADR-0013 decision 4: a test of one module's behaviour lives in that module).
func TestRBACAgreesWithTheDesignationAction(t *testing.T) {
	if rbac.TargetClassTier0Scope != inventory.TargetClassScope || client.TargetClassTier0Scope != inventory.TargetClassScope {
		t.Fatal("tier0_scope class differs from inventory.TargetClassScope")
	}
	if !slices.Contains(rbac.Tier0ScopePermissions, inventory.DesignationPermission) {
		t.Fatal("rbac does not treat inventory.DesignationPermission as a Tier-0 scope permission")
	}
	for _, r := range rbac.BuiltInRoles() {
		if r.Tier != rbac.Tier0 && slices.Contains(r.Permissions, inventory.DesignationPermission) {
			t.Fatalf("role %q holds the designation permission", r.Name)
		}
	}
}
