package rbac

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// TenantOwnerRole is the built-in role whose holders own the tenant (DM-30.I4, DM-36.I4).
const TenantOwnerRole = "tenant-owner"

// Owners reads who holds TenantOwnerRole. It exists so the one writer that must keep a tenant from
// losing its last owner (authn account disable/delete) does not reach into the authz tables itself.
type Owners struct{}

// TenantOwners takes the tenant's owner lock and returns the accounts that hold the built-in
// tenant-owner role through an active, in-window assignment right now. The lock is a transaction-level
// advisory lock: it is held until tx ends, and every writer that can remove an owner (account
// disable/delete, and in time assignment revoke) takes it first, so two concurrent removals are
// serialised and the second one sees the first's committed result. tx must be a tenant transaction at
// READ COMMITTED, so the read after the lock sees fresh data.
//
// Whether an account is itself active is the account store's to say; this returns holders only.
func (Owners) TenantOwners(ctx context.Context, tx store.Tx, t tenant.ID) ([]string, error) {
	if t.IsZero() {
		return nil, fmt.Errorf("rbac: owners: no tenant")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('authz.tenant-owner:' || $1::text, 0))`, t.String()); err != nil {
		return nil, fmt.Errorf("rbac: owner lock: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT a.account_id::text
FROM public.authz_assignments a
JOIN public.authz_roles r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
WHERE a.tenant_id = $1::uuid AND r.role_name = $2 AND r.built_in
  AND a.assignment_state = 'active' AND a.valid_from <= now() AND (a.valid_until IS NULL OR a.valid_until > now())`,
		t.String(), TenantOwnerRole)
	if err != nil {
		return nil, fmt.Errorf("rbac: reading tenant owners: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("rbac: reading tenant owners: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rbac: reading tenant owners: %w", err)
	}
	return out, nil
}
