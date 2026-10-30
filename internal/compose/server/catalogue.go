package server

import (
	"fmt"
	"slices"

	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/notify/syslog"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

// moduleOperationPermissions are the permissions modules and platform packages declare for the
// operations they mount on the API. They are named by the owners' own constants, so a rename there
// changes the catalogue and a contract still carrying the old name fails Build.
var moduleOperationPermissions = []string{
	string(connections.TakeoverAttestPermission),
	string(directory.ReadPermission),
	syslog.ManagePermission,
	syslog.ReadPermission,
}

// permissionCatalogue is the one set of permissions that exist: every permission a built-in role
// holds plus every permission a module declares for a mounted operation. apihost.Build refuses an
// operation whose x-permission is not in it, and the API's RBAC port denies a permission that is not
// in it, so neither a typo in the contract nor a request for an unlisted permission is served.
func permissionCatalogue() apihost.Permissions {
	set := slices.Clone(moduleOperationPermissions)
	for _, r := range rbac.BuiltInRoles() {
		for _, p := range r.Permissions {
			set = append(set, string(p))
		}
	}
	slices.Sort(set)
	return apihost.Permissions(slices.Compact(set))
}

// checkCatalogue fails when a role grants or a module declares an empty permission name: a boot
// error beats a catalogue with a hole in it.
func checkCatalogue(c apihost.Permissions) error {
	if len(c) == 0 {
		return fmt.Errorf("server: permission catalogue is empty")
	}
	if c.Has("") {
		return fmt.Errorf("server: permission catalogue holds an empty permission name")
	}
	return nil
}
