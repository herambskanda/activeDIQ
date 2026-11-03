package inventory

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// MaxSearchMetaRefs bounds one metadata read: four groups of at most MaxSearchGroupLimit admitted hits.
const MaxSearchMetaRefs = 4 * reportsql.MaxSearchGroupLimit

// SearchRef names one admitted hit by its identity.
type SearchRef struct{ Connection, Object string }

// SearchMeta is what a hit row shows beyond the statement's own columns: display snapshots of the stored
// row (DM-16.I2), never keys. Mail is the string attribute "mail" when the sync wrote one.
type SearchMeta struct {
	DN, SAMAccountName, UserPrincipalName, Mail string
}

// SearchMetadata is the one batched read of rule 13: the display fields of the hits the statement already
// admitted, keyed by their GUIDs. It is not a scope check and must be given only the hits of Search; it reads
// no object the scope rejected, because it is only ever asked about the ones it admitted. A ref the table
// does not hold is absent from the answer.
func (s *Searcher) SearchMetadata(ctx context.Context, tx store.Tx, tid tenant.ID, hits []reportsql.SearchHit) (map[SearchRef]SearchMeta, error) {
	if s == nil {
		return nil, ErrNotConfigured
	}
	if tid.IsZero() {
		return nil, ErrNoTenant
	}
	out := make(map[SearchRef]SearchMeta, len(hits))
	if len(hits) == 0 {
		return out, nil
	}
	if len(hits) > MaxSearchMetaRefs {
		return nil, ErrTooMany
	}
	conns, objs := make([]string, 0, len(hits)), make([]string, 0, len(hits))
	for _, h := range hits {
		c, okc := canon(h.Connection)
		o, oko := canon(h.Object)
		if !okc || !oko {
			return nil, ErrInvalid
		}
		conns, objs = append(conns, c), append(objs, o)
	}
	rows, err := tx.Query(ctx, `SELECT o.connection_id::text, o.object_guid::text, o.dn, o.sam_account_name, o.upn,
			CASE WHEN jsonb_typeof(o.attributes -> 'mail') = 'string' THEN o.attributes ->> 'mail' ELSE '' END
		FROM public.directory_objects o
		JOIN unnest($2::uuid[], $3::uuid[]) AS k (connection_id, object_guid)
		  ON o.connection_id = k.connection_id AND o.object_guid = k.object_guid
		WHERE o.tenant_id = $1::uuid`, tid.String(), conns, objs)
	if err != nil {
		return nil, fmt.Errorf("inventory: search metadata: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r SearchRef
		var m SearchMeta
		if err := rows.Scan(&r.Connection, &r.Object, &m.DN, &m.SAMAccountName, &m.UserPrincipalName, &m.Mail); err != nil {
			return nil, fmt.Errorf("inventory: search metadata: %w", err)
		}
		out[r] = m
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: search metadata: %w", err)
	}
	return out, nil
}
