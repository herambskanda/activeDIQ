package invhost

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// DM-27 InventoryServer: rows are written once by Service.Register; the app role holds no UPDATE or DELETE
// (migration 0050), but the table has no lifecycle state to protect, so it is a mutable tenant table, not X5.
var _ = tablekind.Declare(tablekind.Table{Name: "public.inventory_servers", Entity: "DM-27", Kind: tablekind.Tenant})

// PGStore is the Postgres Store over inventory_servers.
type PGStore struct{}

var _ Store = PGStore{}

// Find implements Store.
func (PGStore) Find(ctx context.Context, tx store.Tx, tid tenant.ID, fqdn string) (bool, error) {
	var one int
	err := tx.QueryRow(ctx, `SELECT 1 FROM public.inventory_servers WHERE tenant_id = $1::uuid AND fqdn = $2`,
		tid.String(), fqdn).Scan(&one)
	if store.IsNoRows(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("invhost: find: %w", err)
	}
	return true, nil
}

// Insert implements Store.
func (PGStore) Insert(ctx context.Context, tx store.Tx, tid tenant.ID, fqdn, by string) (string, bool, error) {
	var id string
	err := tx.QueryRow(ctx, `INSERT INTO public.inventory_servers (tenant_id, fqdn, registered_by)
		VALUES ($1::uuid, $2, $3) ON CONFLICT (tenant_id, fqdn) DO NOTHING RETURNING id::text`,
		tid.String(), fqdn, by).Scan(&id)
	if store.IsNoRows(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("invhost: insert: %w", err)
	}
	return id, true, nil
}
