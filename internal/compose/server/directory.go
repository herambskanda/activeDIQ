package server

import (
	"context"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/modules/search"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// buildDirectory wires the directory routes: the registry (active connection and the service-account
// gate), the user search over the connector source, and universal search over the inventory (T-1096). A
// missing source fails startup.
//
// scopes produces the caller's directory.read ReadScope (rbac.ReadScopes behind a transaction, T-0916).
// Both searches are trimmed to it; while it is nil every search is refused (fail closed), never unscoped.
func buildDirectory(ctx context.Context, db *store.DB, conns *connection.Registry, src client.ConnectorSource, reads client.Reads, scopes directory.ReadScopes) (apihost.TagHandlers, error) {
	us, err := client.NewUserSearch(conns, src, reads)
	if err != nil {
		return apihost.TagHandlers{}, fmt.Errorf("server: directory search: %w", err)
	}
	ss, err := buildSearch(ctx, db, scopes)
	if err != nil {
		return apihost.TagHandlers{}, err
	}
	// The TM-D17 classification of each hybrid-synced user: the stored correlation (DM-20) and the
	// Entra connection's takeover protection (DM-10.I7), read live per request.
	hy := directory.Classifier{Corr: inventory.NewReader(db, nil), Takeovers: conns}
	return directory.Handlers{Connections: conns, Search: us, Scopes: scopes, Hybrid: hy, Searcher: ss}.Bind(), nil
}

// buildSearch composes universal search (ADR-0011): the inventory index registered against the live schema,
// the one read-scope producer through the T-0987 port, the inventory's freshness, and a cursor key.
//
// The cursor key is random per process: a "show all" cursor lives until the server restarts and is refused
// (400 cursor_invalid) on another node. Paging across nodes needs a key from key custody; that is a
// follow-up, and until then a refused cursor only costs the admin a new search.
func buildSearch(ctx context.Context, db *store.DB, scopes search.ReadScopes) (*search.Service, error) {
	if scopes == nil {
		return nil, fmt.Errorf("server: universal search needs the read-scope producer")
	}
	sch, err := reportSchema(ctx, db)
	if err != nil {
		return nil, err
	}
	idx, err := inventory.NewSearcher(sch)
	if err != nil {
		return nil, fmt.Errorf("server: universal search: %w", err)
	}
	cur, err := search.NewEphemeralCursors()
	if err != nil {
		return nil, fmt.Errorf("server: universal search: %w", err)
	}
	return &search.Service{DB: db, Scopes: scopes, Index: idx, Fresh: searchFreshness{r: inventory.NewReader(db, nil)}, Cursors: cur}, nil
}

// searchFreshness answers the as-of of a search from the inventory's sync watermarks (D6), over the
// connections the caller's scopes reach.
type searchFreshness struct{ r *inventory.Reader }

func (f searchFreshness) AsOf(ctx context.Context, tid tenant.ID, cs []authz.ObjectID, now time.Time) (time.Time, error) {
	q := inventory.FreshnessQuery{Now: now}
	for _, c := range cs {
		q.Connections = append(q.Connections, inventory.ConnectionID(report.GUIDString(c)))
	}
	res, err := f.r.Freshness(ctx, tid, q)
	if err != nil {
		return time.Time{}, err
	}
	return res.Label.AsOf, nil
}
