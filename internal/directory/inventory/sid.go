package inventory

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// MaxSIDMatches bounds ObjectsBySID: two matches are already "ambiguous", so the query stops there.
const MaxSIDMatches = 2

// ObjectsBySID returns the live AD objects whose objectSid is s, at most MaxSIDMatches, ordered by
// connection and object. The SID is bound as bytes (never spliced), deleted and recycled objects are
// excluded, and a read error is an error, never an empty answer. One SID is normally one object; more
// than one (two forests with a cloned domain SID, a restored domain) is the caller's ambiguity to refuse.
func (r *Reader) ObjectsBySID(ctx context.Context, tid tenant.ID, s sid.SID) ([]Ref, error) {
	raw := s.Bytes()
	if len(raw) < 12 { // revision, count, 6-byte authority and at least one sub-authority; the zero SID encodes as a bare header
		return nil, ErrInvalid
	}
	var out []Ref
	err := r.with(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT connection_id::text, object_guid::text FROM public.directory_objects
			WHERE tenant_id = $1::uuid AND sid = $2 AND state = $3
			ORDER BY connection_id, object_guid LIMIT $4`, tid.String(), raw, string(ObjLive), MaxSIDMatches)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c, g string
			if err := rows.Scan(&c, &g); err != nil {
				return err
			}
			out = append(out, Ref{Connection: ConnectionID(c), Object: GUID(g)})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("inventory: objects by sid: %w", err)
	}
	return out, nil
}
