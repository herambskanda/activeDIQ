package connection

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// c13PinsTable declares public.connection_c13_pins (TM-D26 rule 10) for fitness-domain-keys: pinned
// group objectGUIDs of a connection, written by discovery.
var c13PinsTable = tablekind.Declare(tablekind.Table{
	Name:   "public.connection_c13_pins",
	Entity: "DM-10",
	Kind:   tablekind.Tenant,
})

// maxPins bounds one read: a domain has a handful of C13 groups.
const maxPins = 1000

// PinnedC13 returns the C13 group GUIDs (canonical text) pinned for the connection (TM-D26 rule 10).
func (Store) PinnedC13(ctx context.Context, tx store.Tx, id ID) ([]string, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return nil, err
	}
	if _, err := ParseID(string(id)); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT group_guid FROM public.connection_c13_pins
		WHERE connection_id = $1::uuid ORDER BY group_guid LIMIT $2`, string(id), maxPins)
	if err != nil {
		return nil, fmt.Errorf("connection: c13 pins: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, fmt.Errorf("connection: c13 pins: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connection: c13 pins: %w", err)
	}
	return out, nil
}

// PinC13 adds GUIDs (canonical lower-case text) to the connection's pins. Idempotent; pins are never
// removed.
func (Store) PinC13(ctx context.Context, tx store.Tx, id ID, guids []string) error {
	if err := requireTenant(ctx, tx); err != nil {
		return err
	}
	if _, err := ParseID(string(id)); err != nil {
		return err
	}
	for _, g := range guids {
		if _, err := tx.Exec(ctx, `INSERT INTO public.connection_c13_pins (tenant_id, connection_id, group_guid)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2)
			ON CONFLICT DO NOTHING`, string(id), g); err != nil {
			return fmt.Errorf("connection: pin c13: %w", err)
		}
	}
	return nil
}
