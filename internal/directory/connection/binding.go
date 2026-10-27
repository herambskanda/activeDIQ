package connection

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// bindingsTable declares public.connector_bindings (DM-13) for fitness-domain-keys.
var bindingsTable = tablekind.Declare(tablekind.Table{
	Name:   "public.connector_bindings",
	Entity: "DM-13",
	Kind:   tablekind.Tenant,
})

// BindingTarget says what serves a connection. v1 writes only the embedded connector; a remote
// component target arrives with remote connector enrolment (T-0167).
type BindingTarget string

// TargetEmbedded is the connector inside the server process (ADR-0002).
const TargetEmbedded BindingTarget = "embedded"

// TargetComponent is a remote connector component reached over its fleet tunnel.
const TargetComponent BindingTarget = "component"

// Binding is one DM-13 row.
type Binding struct {
	ID           string
	ConnectionID ID
	Target       BindingTarget
	ComponentID  string // the enrolled component of a TargetComponent binding; empty for embedded
	Priority     int
	State        string
}

// ensureEmbeddedBinding makes sure the connection has its embedded binding (DM-10.I3). It is called
// by Activate, in the activating transaction, so a connection never becomes active without one. It is
// idempotent: an existing live binding is left alone.
func ensureEmbeddedBinding(ctx context.Context, tx store.Tx, id ID) error {
	_, err := tx.Exec(ctx, `INSERT INTO public.connector_bindings (tenant_id, connection_id, target)
		SELECT tenant_id, id, 'embedded' FROM public.connections WHERE id = $1::uuid
		ON CONFLICT (tenant_id, connection_id) WHERE target = 'embedded' AND state <> 'removed' DO NOTHING`, string(id))
	if err != nil {
		return fmt.Errorf("connection: create binding: %w", err)
	}
	return nil
}

const maxBindings = 100

// Bindings returns the connection's bindings that are not removed, in routing order.
func (Store) Bindings(ctx context.Context, tx store.Tx, id ID) ([]Binding, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return nil, err
	}
	if _, err := ParseID(string(id)); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT id, connection_id, target, COALESCE(component_id::text, ''), priority, state FROM public.connector_bindings
		WHERE connection_id = $1::uuid AND state <> 'removed' ORDER BY priority, id LIMIT $2`, string(id), maxBindings)
	if err != nil {
		return nil, fmt.Errorf("connection: bindings: %w", err)
	}
	defer rows.Close()
	var out []Binding
	for rows.Next() {
		var b Binding
		var conn, target string
		if err := rows.Scan(&b.ID, &conn, &target, &b.ComponentID, &b.Priority, &b.State); err != nil {
			return nil, fmt.Errorf("connection: bindings: %w", err)
		}
		b.ConnectionID, b.Target = ID(conn), BindingTarget(target)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connection: bindings: %w", err)
	}
	return out, nil
}
