package connection

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const linkColumns = `id, ad_connection_id, nc_guid, entra_connection_id, origin, state, created_at, updated_at`

func scanLink(r scanner) (HybridLink, error) {
	var l HybridLink
	var id, ad, nc, en, origin, state string
	if err := r.Scan(&id, &ad, &nc, &en, &origin, &state, &l.CreatedAt, &l.UpdatedAt); err != nil {
		return HybridLink{}, err
	}
	l.ID, l.ADConnectionID, l.NCGUID, l.EntraConnectionID = HybridLinkID(id), ID(ad), NCGUID(nc), ID(en)
	l.Origin, l.State = LinkOrigin(origin), LinkState(state)
	return l, nil
}

func (s Store) createLink(ctx context.Context, tx store.Tx, n NewHybridLink, origin LinkOrigin) (HybridLink, error) {
	n, err := n.validate()
	if err != nil {
		return HybridLink{}, err
	}
	if err := requireTenant(ctx, tx); err != nil {
		return HybridLink{}, err
	}
	state, _ := origin.initialState()
	l, err := scanLink(tx.QueryRow(ctx, `INSERT INTO public.hybrid_links (tenant_id, ad_connection_id, nc_guid, entra_connection_id, origin, state)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3::uuid, $4, $5)
		RETURNING `+linkColumns, string(n.ADConnectionID), string(n.NCGUID), string(n.EntraConnectionID), string(origin), string(state)))
	if err != nil {
		switch store.SQLState(err) {
		case "23505":
			return HybridLink{}, ErrDuplicateHybridLink
		case "AD403":
			return HybridLink{}, fmt.Errorf("%w: both sides must be connections of this tenant, an AD forest and an Entra tenant", ErrInvalid)
		}
		return HybridLink{}, fmt.Errorf("connection: create hybrid link: %w", err)
	}
	return l, nil
}

// DeclareHybridLink records an administrator's declaration: stored confirmed, origin declared.
// Declaring switches on cross-directory authority (DM-21.I2), so the caller must already have
// checked connections.hybrid_link.confirm over both sides and be inside an audited Operation; this
// method is the mechanical write only.
func (s Store) DeclareHybridLink(ctx context.Context, tx store.Tx, n NewHybridLink) (HybridLink, error) {
	return s.createLink(ctx, tx, n, OriginDeclared)
}

// DiscoverHybridLink records a link found from correlations: stored proposed, origin discovered. It
// grants nothing until confirmed (DM-21.I2).
func (s Store) DiscoverHybridLink(ctx context.Context, tx store.Tx, n NewHybridLink) (HybridLink, error) {
	return s.createLink(ctx, tx, n, OriginDiscovered)
}

// GetHybridLink returns one link of the tenant, or ErrHybridLinkNotFound.
func (Store) GetHybridLink(ctx context.Context, tx store.Tx, id HybridLinkID) (HybridLink, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return HybridLink{}, err
	}
	if _, err := ParseHybridLinkID(string(id)); err != nil {
		return HybridLink{}, err
	}
	l, err := scanLink(tx.QueryRow(ctx, `SELECT `+linkColumns+` FROM public.hybrid_links WHERE id = $1::uuid`, string(id)))
	if store.IsNoRows(err) {
		return HybridLink{}, ErrHybridLinkNotFound
	}
	if err != nil {
		return HybridLink{}, fmt.Errorf("connection: get hybrid link: %w", err)
	}
	return l, nil
}

// TransitionHybridLink moves a link from → to along a declared edge, compare-and-set on the stored
// state. The gate that decides to call it (the confirm permission, the audited Operation) is the
// caller's.
func (Store) TransitionHybridLink(ctx context.Context, tx store.Tx, id HybridLinkID, from, to LinkState) (HybridLink, error) {
	if !CanTransitionLink(from, to) {
		return HybridLink{}, fmt.Errorf("%w: %s → %s", ErrIllegalLinkTransition, from, to)
	}
	if err := requireTenant(ctx, tx); err != nil {
		return HybridLink{}, err
	}
	if _, err := ParseHybridLinkID(string(id)); err != nil {
		return HybridLink{}, err
	}
	l, err := scanLink(tx.QueryRow(ctx, `UPDATE public.hybrid_links SET state = $2, updated_at = now()
		WHERE id = $1::uuid AND state = $3 RETURNING `+linkColumns, string(id), string(to), string(from)))
	if store.IsNoRows(err) {
		if _, gerr := (Store{}).GetHybridLink(ctx, tx, id); gerr != nil {
			return HybridLink{}, gerr
		}
		return HybridLink{}, ErrLinkStateConflict
	}
	if err != nil {
		return HybridLink{}, fmt.Errorf("connection: transition hybrid link: %w", err)
	}
	return l, nil
}

// maxLinks bounds ListHybridLinks.
const maxLinks = 1000

// ListHybridLinks returns the links of one AD connection, oldest first, removed ones only if asked.
func (Store) ListHybridLinks(ctx context.Context, tx store.Tx, adConn ID, includeRemoved bool) ([]HybridLink, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return nil, err
	}
	if _, err := ParseID(string(adConn)); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+linkColumns+` FROM public.hybrid_links
		WHERE ad_connection_id = $1::uuid AND ($2 OR state <> 'removed') ORDER BY created_at, id LIMIT $3`,
		string(adConn), includeRemoved, maxLinks)
	if err != nil {
		return nil, fmt.Errorf("connection: list hybrid links: %w", err)
	}
	defer rows.Close()
	var out []HybridLink
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, fmt.Errorf("connection: list hybrid links: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connection: list hybrid links: %w", err)
	}
	return out, nil
}

// ConfirmedLink reports whether a confirmed link joins the domain and the tenant (DM-21.I2).
func (Store) ConfirmedLink(ctx context.Context, tx store.Tx, adConn ID, nc NCGUID, entraConn ID) (bool, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return false, err
	}
	ad, err := ParseID(string(adConn))
	if err != nil {
		return false, err
	}
	g, err := ParseNCGUID(string(nc))
	if err != nil {
		return false, err
	}
	en, err := ParseID(string(entraConn))
	if err != nil {
		return false, err
	}
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.hybrid_links
		WHERE ad_connection_id = $1::uuid AND nc_guid = $2 AND entra_connection_id = $3::uuid AND state = 'confirmed')`,
		string(ad), string(g), string(en)).Scan(&ok); err != nil {
		return false, fmt.Errorf("connection: confirmed hybrid link: %w", err)
	}
	return ok, nil
}

// HasLink reports whether the AD connection has a link that is not removed.
func (Store) HasLink(ctx context.Context, tx store.Tx, adConn ID) (bool, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return false, err
	}
	ad, err := ParseID(string(adConn))
	if err != nil {
		return false, err
	}
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.hybrid_links
		WHERE ad_connection_id = $1::uuid AND state IN ('proposed', 'confirmed'))`, string(ad)).Scan(&ok); err != nil {
		return false, fmt.Errorf("connection: has hybrid link: %w", err)
	}
	return ok, nil
}

// Registry methods: one tenant transaction per call, as for DM-10. Registry implements HybridLinks.
var _ HybridLinks = (*Registry)(nil)

// DeclareHybridLink adds a confirmed, declared link.
func (r *Registry) DeclareHybridLink(ctx context.Context, tid tenant.ID, n NewHybridLink) (l HybridLink, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) { l, e = r.s.DeclareHybridLink(ctx, tx, n); return })
	return l, err
}

// DiscoverHybridLink adds a proposed, discovered link.
func (r *Registry) DiscoverHybridLink(ctx context.Context, tid tenant.ID, n NewHybridLink) (l HybridLink, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) { l, e = r.s.DiscoverHybridLink(ctx, tx, n); return })
	return l, err
}

// GetHybridLink returns one link of the tenant.
func (r *Registry) GetHybridLink(ctx context.Context, tid tenant.ID, id HybridLinkID) (l HybridLink, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) { l, e = r.s.GetHybridLink(ctx, tx, id); return })
	return l, err
}

// TransitionHybridLink moves a link along a declared edge.
func (r *Registry) TransitionHybridLink(ctx context.Context, tid tenant.ID, id HybridLinkID, from, to LinkState) (l HybridLink, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) {
		l, e = r.s.TransitionHybridLink(ctx, tx, id, from, to)
		return
	})
	return l, err
}

// ListHybridLinks returns the links of one AD connection.
func (r *Registry) ListHybridLinks(ctx context.Context, tid tenant.ID, adConn ID, includeRemoved bool) (ls []HybridLink, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) {
		ls, e = r.s.ListHybridLinks(ctx, tx, adConn, includeRemoved)
		return
	})
	return ls, err
}

// Confirmed implements HybridLinks.
func (r *Registry) Confirmed(ctx context.Context, tid tenant.ID, adConn ID, nc NCGUID, entraConn ID) (ok bool, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) {
		ok, e = r.s.ConfirmedLink(ctx, tx, adConn, nc, entraConn)
		return
	})
	if err != nil {
		return false, err
	}
	return ok, nil
}

// HasHybridLink implements HybridLinks.
func (r *Registry) HasHybridLink(ctx context.Context, tid tenant.ID, adConn ID) (ok bool, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) { ok, e = r.s.HasLink(ctx, tx, adConn); return })
	if err != nil {
		return false, err
	}
	return ok, nil
}
