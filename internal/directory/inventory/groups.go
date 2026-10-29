package inventory

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// MaxGroups bounds the groups one object can belong to, transitively. More means something is wrong,
// and a truncated answer would silently leave a designated group out, so it is ErrTooMany.
const MaxGroups = 10000

// Groups is the Postgres GroupSource over the DM-17 member and primary-group edges (a primary-group edge is a membership with no member value, TM-D25 rule 6). The walk is one recursive query
// with set semantics (UNION), so circular groups (I3) terminate without a depth counter.
type Groups struct{ db *store.DB }

var _ GroupSource = (*Groups)(nil)

// NewGroups binds a group source to a database.
func NewGroups(db *store.DB) *Groups { return &Groups{db: db} }

// GroupsOf implements GroupSource: every group that contains member directly or through nested
// groups, sorted, duplicate-free, without member itself. Only active edges count.
func (g *Groups) GroupsOf(ctx context.Context, tid tenant.ID, connection ConnectionID, member GUID) ([]GUID, error) {
	if g == nil || g.db == nil {
		return nil, ErrNotConfigured
	}
	if tid.IsZero() {
		return nil, ErrNoTenant
	}
	if !(Ref{connection, member}).Valid() {
		return nil, ErrInvalid
	}
	var out []GUID
	err := g.db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `WITH RECURSIVE up(guid) AS (
				SELECT source_guid FROM public.links
				WHERE tenant_id = $1::uuid AND connection_id = $2::uuid AND link_attr IN ('member', 'primary_group') AND state = 'active' AND target_guid = $3::uuid
			UNION
				SELECT l.source_guid FROM public.links l JOIN up ON l.target_guid = up.guid
				WHERE l.tenant_id = $1::uuid AND l.connection_id = $2::uuid AND l.link_attr IN ('member', 'primary_group') AND l.state = 'active'
			)
			SELECT guid::text FROM up WHERE guid <> $3::uuid ORDER BY guid LIMIT $4`,
			tid.String(), string(connection), string(member), MaxGroups+1)
		if err != nil {
			return fmt.Errorf("inventory: groups: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return fmt.Errorf("inventory: groups: %w", err)
			}
			out = append(out, GUID(s))
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(out) > MaxGroups {
		return nil, ErrTooMany
	}
	if out == nil {
		out = []GUID{}
	}
	return out, nil
}

var _ GroupRows = (*Groups)(nil)

// GroupExists implements GroupRows: a group row in an active state (AD live, Entra active) of the connection.
func (g *Groups) GroupExists(ctx context.Context, tid tenant.ID, connection ConnectionID, group GUID) (bool, error) {
	if g == nil || g.db == nil {
		return false, ErrNotConfigured
	}
	if tid.IsZero() {
		return false, ErrNoTenant
	}
	if !(Ref{connection, group}).Valid() {
		return false, ErrInvalid
	}
	var ok bool
	err := g.db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.directory_objects
			WHERE tenant_id = $1::uuid AND connection_id = $2::uuid AND object_guid = $3::uuid AND kind = 'group' AND state IN ($4, $5))`,
			tid.String(), string(connection), string(group), string(ObjLive), string(ObjActive)).Scan(&ok)
	})
	if err != nil {
		return false, fmt.Errorf("inventory: group row: %w", err)
	}
	return ok, nil
}
