package connections_test

import (
	"slices"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

// T-0453: the permission the reconfirm Action asks for is in the built-in tenant-owner role, and in no
// role below it (relocated from compose/server, ADR-0013 decision 4).
func TestTenantOwnerCatalogueGrantsTheReconfirmPermission(t *testing.T) {
	for _, r := range rbac.BuiltInRoles() {
		has := slices.Contains(r.Permissions, connections.ReconfirmPermission)
		if want := r.Name == rbac.TenantOwnerRole; has != want {
			t.Errorf("role %q holds %s = %v, want %v", r.Name, connections.ReconfirmPermission, has, want)
		}
	}
}
