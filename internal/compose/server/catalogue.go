package server

import (
	"fmt"
	"slices"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/notify/syslog"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

// kernelPermissions are the permissions that exist outside any module: every permission a built-in
// role holds plus the platform packages' own operation permissions. Module permissions arrive through
// Registrar.Permission (EP-6), so the catalogue cannot drift from the code that checks them.
func kernelPermissions() []string {
	set := []string{syslog.ManagePermission, syslog.ReadPermission}
	for _, r := range rbac.BuiltInRoles() {
		for _, p := range r.Permissions {
			set = append(set, string(p))
		}
	}
	slices.Sort(set)
	return slices.Compact(set)
}

// permissionCatalogue is the one set of permissions that exist: the kernel's plus every permission
// the booted modules registered. apihost.Build refuses an operation whose x-permission is not in it,
// and the API's RBAC port denies a permission that is not in it, so neither a typo in the contract
// nor a request for an unlisted permission is served.
func permissionCatalogue(c *module.Contributions) apihost.Permissions {
	set := kernelPermissions()
	for _, p := range c.Permissions() {
		set = append(set, string(p))
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
