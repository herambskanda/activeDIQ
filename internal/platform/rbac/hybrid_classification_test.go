package rbac

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// crossing lists every built-in permission that MAY be effective across a correlation. Any other
// built-in permission must be never-cross; a new permission fails here until classified (TM-D17).
var crossing = map[authz.Permission]bool{
	"objects.user.reset_password": true,
	"objects.user.delete":         true,
	"operation.approve":           true,
	// directory.read is a read of the tenant's own directory (searchDirectoryUsers). It administers neither
	// RBAC, scopes nor connections, so a matched, attested, non-tier0 correlation may carry it (TM-D17 rule 5).
	"directory.read": true,
}

func TestHybridGateEveryBuiltInPermissionClassified(t *testing.T) {
	for _, r := range BuiltInRoles() {
		for _, p := range r.Permissions {
			if crossing[p] == authz.NeverCrosses(p) {
				t.Errorf("permission %q (role %s) is unclassified or misclassified: crosses=%v never=%v", p, r.Name, crossing[p], authz.NeverCrosses(p))
			}
		}
	}
	for _, p := range Tier0ScopePermissions {
		if !authz.NeverCrosses(p) {
			t.Errorf("tier0 scope permission %q must never cross", p)
		}
	}
}
