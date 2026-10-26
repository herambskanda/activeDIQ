package rbac

import (
	"context"
	"fmt"
	"slices"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var (
	_ = tablekind.Declare(tablekind.Table{Name: "public.authz_roles", Entity: "DM-34", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.authz_role_permissions", Entity: "DM-34", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.authz_assignments", Entity: "DM-36", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.authz_assignment_roots", Entity: "DM-35", Kind: tablekind.Tenant})
)

// Tier says where a role sits. A Tier-0 permission is held by tier 0 only.
type Tier int

// Tiers.
const (
	Tier0 Tier = 0 // administers Tier-0 scope
	Tier1 Tier = 1 // platform administration
	Tier2 Tier = 2 // help desk
)

// Tier0ScopePermissions are the permissions that are meaningful only on a connection's Tier-0 scope.
// They are authorised on a tier0_scope target and nowhere else, and no Tier-2 role holds one.
var Tier0ScopePermissions = []authz.Permission{"inventory.tier0_designation.manage"}

// Role is one built-in role: data, read-only (DM-34.I1).
type Role struct {
	Name        string
	Tier        Tier
	Permissions []authz.Permission
}

// BuiltInRoles enumerates the roles that ship. The slice is a copy.
func BuiltInRoles() []Role {
	return []Role{
		{Name: "tier0-administrator", Tier: Tier0, Permissions: []authz.Permission{"inventory.tier0_designation.manage"}},
		{Name: "platform-administrator", Tier: Tier1, Permissions: []authz.Permission{
			"connections.hybrid_link.confirm", "operation.approve", "objects.user.reset_password", "objects.user.delete"}},
		{Name: "helpdesk-operator", Tier: Tier2, Permissions: []authz.Permission{"objects.user.reset_password"}},
	}
}

// ValidateRoles refuses a Tier-2 role holding a Tier-0 scope permission.
func ValidateRoles(rs []Role) error {
	for _, r := range rs {
		if r.Tier == Tier2 {
			for _, p := range r.Permissions {
				if slices.Contains(Tier0ScopePermissions, p) {
					return fmt.Errorf("rbac: Tier-2 role %q holds Tier-0 scope permission %q", r.Name, p)
				}
			}
		}
	}
	return nil
}

// SeedBuiltIns inserts the built-in roles for a tenant, idempotently. Existing rows are left as they are.
func SeedBuiltIns(ctx context.Context, tx store.Tx, t tenant.ID) error {
	rs := BuiltInRoles()
	if err := ValidateRoles(rs); err != nil {
		return err
	}
	for _, r := range rs {
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO public.authz_roles (tenant_id, role_name, built_in, tier) VALUES ($1::uuid, $2, true, $3)
ON CONFLICT (tenant_id, role_name) DO UPDATE SET role_name = EXCLUDED.role_name RETURNING id::text`, t.String(), r.Name, int(r.Tier)).Scan(&id)
		if err != nil {
			return fmt.Errorf("rbac: seeding role %q: %w", r.Name, err)
		}
		for _, p := range r.Permissions {
			if _, err := tx.Exec(ctx, `INSERT INTO public.authz_role_permissions (tenant_id, role_id, permission) VALUES ($1::uuid, $2::uuid, $3)
ON CONFLICT DO NOTHING`, t.String(), id, string(p)); err != nil {
				return fmt.Errorf("rbac: seeding permission %q of role %q: %w", p, r.Name, err)
			}
		}
	}
	return nil
}
