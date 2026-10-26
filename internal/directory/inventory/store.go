package inventory

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Reader is the Postgres implementation of CorrelationSource and Designations. Each call runs in its
// own tenant transaction (row-level security scopes it) and every statement also names the tenant.
type Reader struct {
	db     *store.DB
	groups GroupSource
}

var (
	_ CorrelationSource = (*Reader)(nil)
	_ Designations      = (*Reader)(nil)
)

// NewReader binds a reader to a database. groups is required for DesignationsFor; without it that
// call returns ErrNotConfigured rather than omit designated groups.
func NewReader(db *store.DB, groups GroupSource) *Reader { return &Reader{db: db, groups: groups} }

func (r *Reader) with(ctx context.Context, tid tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error {
	if r == nil || r.db == nil {
		return ErrNotConfigured
	}
	if tid.IsZero() {
		return ErrNoTenant
	}
	return r.db.WithTenant(ctx, tid, fn)
}

const linkColumns = `c.id::text, c.ad_connection_id::text, c.ad_object_guid::text, c.entra_connection_id::text, c.entra_object_guid::text,
	c.match, c.anchor_attr, c.anchor_value, c.ad_sid, c.state, c.candidate_reason, c.gate_checked_at, c.eligible_since, c.eligibility_class,
	COALESCE(c.reconfirmed_by::text, ''), c.reconfirmed_at, c.ad_tier0, c.ad_tier0_bases, c.entra_tier0, c.entra_tier0_bases, c.facts_as_of,
	ac.kind, ec.kind`

// CorrelationsFor implements CorrelationSource.
func (r *Reader) CorrelationsFor(ctx context.Context, tid tenant.ID, ref Ref) (Correlations, error) {
	if !ref.Valid() {
		return Correlations{}, ErrInvalid
	}
	var out []Link
	var evaluated *time.Time
	err := r.with(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		// Same transaction as the links, so the as-of cannot be newer than the links it vouches for.
		if err := tx.QueryRow(ctx, `SELECT max(evaluated_at) FROM public.correlation_evaluations
			WHERE tenant_id = $1::uuid AND connection_id = $2::uuid`, tid.String(), string(ref.Connection)).Scan(&evaluated); err != nil {
			return fmt.Errorf("inventory: evaluation as-of: %w", err)
		}
		rows, err := tx.Query(ctx, `SELECT `+linkColumns+` FROM public.correlations c
			LEFT JOIN public.connections ac ON ac.tenant_id = $1::uuid AND ac.id = c.ad_connection_id
			LEFT JOIN public.connections ec ON ec.tenant_id = $1::uuid AND ec.id = c.entra_connection_id
			WHERE c.tenant_id = $1::uuid AND c.state <> 'removed'
			AND ((c.ad_connection_id = $2::uuid AND c.ad_object_guid = $3::uuid)
			  OR (c.entra_connection_id = $2::uuid AND c.entra_object_guid = $3::uuid))
			LIMIT $4`, tid.String(), string(ref.Connection), string(ref.Object), MaxLinks+1)
		if err != nil {
			return fmt.Errorf("inventory: correlations: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				id, adC, adO, enC, enO, match, attr, state, reason, class, by string
				anchor, sid                                                   []byte
				gate, since, at, asOf                                         *time.Time
				adT, enT                                                      bool
				adB, enB                                                      []string
				adKind, enKind                                                *string
			)
			if err := rows.Scan(&id, &adC, &adO, &enC, &enO, &match, &attr, &anchor, &sid, &state, &reason,
				&gate, &since, &class, &by, &at, &adT, &adB, &enT, &enB, &asOf, &adKind, &enKind); err != nil {
				return fmt.Errorf("inventory: correlations: %w", err)
			}
			// Both connections must exist in this tenant and be of the right kind: a row that names
			// another tenant's connection or has its sides swapped would orient the tier0 facts
			// onto the wrong object (fail-open on a guard input).
			if adKind == nil || enKind == nil || *adKind != "ad_forest" || *enKind != "entra_tenant" {
				return ErrCorrupt
			}
			l, err := orient(ref, Link{
				ID: id, State: State(state), Reason: Reason(reason), Match: Match(match), AnchorAttr: attr,
				AnchorValue: anchor, ADSID: sid, EligibilityClass: class, ReconfirmedBy: by,
				GateCheckedAt: val(gate), EligibleSince: val(since), ReconfirmedAt: val(at), FactsAsOf: val(asOf),
			}, Ref{ConnectionID(adC), GUID(adO)}, Ref{ConnectionID(enC), GUID(enO)}, adT, bases(adB), enT, bases(enB))
			if err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	if err != nil {
		return Correlations{}, err
	}
	if len(out) > MaxLinks {
		return Correlations{}, ErrTooMany
	}
	sortLinks(out)
	return Correlations{Links: out, EvaluatedAt: val(evaluated)}, nil
}

func val(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

func bases(s []string) []Basis {
	out := make([]Basis, len(s))
	for i, b := range s {
		out[i] = Basis(b)
	}
	return out
}

// orient turns a stored row into a Link seen from ref.
func orient(ref Ref, l Link, ad, entra Ref, adT bool, adB []Basis, enT bool, enB []Basis) (Link, error) {
	switch l.State {
	case StateCandidate, StateMatched, StateBroken:
	default:
		return Link{}, ErrCorrupt
	}
	if ref == ad {
		l.Self, l.Peer, l.PeerKind = ad, entra, "entra_tenant"
		l.SelfTier0, l.SelfBases, l.PeerTier0, l.PeerBases = adT, adB, enT, enB
	} else {
		l.Self, l.Peer, l.PeerKind = entra, ad, "ad_forest"
		l.SelfTier0, l.SelfBases, l.PeerTier0, l.PeerBases = enT, enB, adT, adB
	}
	return l, nil
}

func sortLinks(ls []Link) {
	sort.Slice(ls, func(i, j int) bool {
		a, b := ls[i], ls[j]
		if a.Peer.Connection != b.Peer.Connection {
			return a.Peer.Connection < b.Peer.Connection
		}
		if a.Peer.Object != b.Peer.Object {
			return a.Peer.Object < b.Peer.Object
		}
		return a.ID < b.ID
	})
}

// DesignationsFor implements Designations.
func (r *Reader) DesignationsFor(ctx context.Context, tid tenant.ID, connection ConnectionID, refs []GUID) ([]GUID, error) {
	if r == nil || r.groups == nil {
		return nil, ErrNotConfigured
	}
	if tid.IsZero() {
		return nil, ErrNoTenant
	}
	if len(refs) > MaxDesignationRefs {
		return nil, ErrTooMany
	}
	cs, ok := canon(string(connection))
	if !ok || cs != string(connection) {
		return nil, ErrInvalid
	}
	// The set to test is each ref plus every group it belongs to.
	cand := map[GUID]struct{}{}
	for _, g := range refs {
		if c, ok := canon(string(g)); !ok || c != string(g) {
			return nil, ErrInvalid
		}
		cand[g] = struct{}{}
		gs, err := r.groups.GroupsOf(ctx, tid, connection, g)
		if err != nil {
			return nil, fmt.Errorf("inventory: groups: %w", err)
		}
		for _, grp := range gs {
			if c, ok := canon(string(grp)); !ok || c != string(grp) {
				return nil, ErrCorrupt
			}
			cand[grp] = struct{}{}
		}
	}
	if len(cand) == 0 {
		return []GUID{}, nil
	}
	ids := make([]string, 0, len(cand))
	for g := range cand {
		ids = append(ids, string(g))
	}
	var out []GUID
	err := r.with(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT object_guid::text FROM public.tier0_designations
			WHERE tenant_id = $1::uuid AND connection_id = $2::uuid AND removed_at IS NULL AND object_guid = ANY($3::uuid[])`,
			tid.String(), string(connection), ids)
		if err != nil {
			return fmt.Errorf("inventory: designations: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var g string
			if err := rows.Scan(&g); err != nil {
				return fmt.Errorf("inventory: designations: %w", err)
			}
			out = append(out, GUID(g))
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	if out == nil {
		out = []GUID{}
	}
	return out, nil
}
