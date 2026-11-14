package directory

import (
	"context"
	"fmt"
	"time"

	dirsvc "github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/search"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ModuleID is the module's ID, its OpenAPI tag and its web module ID.
const ModuleID module.ID = "directory"

// schemaTimeout bounds the schema-catalogue read universal search compiles its index from.
const schemaTimeout = time.Minute

// Module is the directory module. It builds its services in Register from the kernel's ports
// (platform.Deps) and the directory services, and contributes its routes (EP-2) and its permission
// (EP-6) through the Registrar (ADR-0013).
type Module struct {
	deps platform.Deps
	dir  dirsvc.Services
}

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir dirsvc.Services) *Module { return &Module{deps: deps, dir: dir} }

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: directory queries serve either directory kind.
func (*Module) Requires() []capability.ID { return nil }

// Register implements module.Module. The permission is always registered. The routes are mounted only
// when the install has a connector source (an unconfigured module registers nothing for its routes, it
// does not hand the host a handler that cannot answer).
func (m *Module) Register(r *module.Registrar) error {
	if err := r.Permission(ReadPermission); err != nil {
		return err
	}
	if m.dir.Source == nil {
		return nil
	}
	h, err := m.handlers()
	if err != nil {
		return err
	}
	return r.API(h.Bind())
}

// handlers builds the service behind the routes: the registry (active connection and the
// service-account gate), the user search over the connector source, and universal search over the
// inventory (T-1096).
//
// Both searches are trimmed to Deps.ReadScopes (rbac.ReadScopes behind a transaction, T-0916); until the
// composition root binds it every search is refused (fail closed), never unscoped.
func (m *Module) handlers() (Handlers, error) {
	if m.dir.Connection == nil || m.deps.DB == nil || m.deps.ReadScopes == nil {
		return Handlers{}, fmt.Errorf("directory: module needs the connection registry, the store and the read-scope producer")
	}
	us, err := client.NewUserSearch(m.dir.Connection, m.dir.Source, m.dir.Reads)
	if err != nil {
		return Handlers{}, fmt.Errorf("directory: user search: %w", err)
	}
	ss, err := buildSearch(m.deps.DB, m.deps.ReadScopes)
	if err != nil {
		return Handlers{}, err
	}
	// The TM-D17 classification of each hybrid-synced user: the stored correlation (DM-20) and the
	// Entra connection's takeover protection (DM-10.I7), read live per request.
	hy := Classifier{Corr: inventory.NewReader(m.deps.DB, nil), Takeovers: m.dir.Connection}
	return Handlers{Connections: m.dir.Connection, Search: us, Scopes: m.deps.ReadScopes, Hybrid: hy, Searcher: ss}, nil
}

// buildSearch composes universal search (ADR-0011): the inventory index registered against the live schema,
// the one read-scope producer through the T-0987 port, the inventory's freshness, and a cursor key.
//
// The cursor key is random per process: a "show all" cursor lives until the server restarts and is refused
// (400 cursor_invalid) on another node. Paging across nodes needs a key from key custody; that is a
// follow-up, and until then a refused cursor only costs the admin a new search.
func buildSearch(db *store.DB, scopes search.ReadScopes) (*search.Service, error) {
	if scopes == nil {
		return nil, fmt.Errorf("directory: universal search needs the read-scope producer")
	}
	sch, err := catalogSchema(db)
	if err != nil {
		return nil, err
	}
	idx, err := inventory.NewSearcher(sch)
	if err != nil {
		return nil, fmt.Errorf("directory: universal search: %w", err)
	}
	cur, err := search.NewEphemeralCursors()
	if err != nil {
		return nil, fmt.Errorf("directory: universal search: %w", err)
	}
	return &search.Service{DB: db, Scopes: scopes, Index: idx, Fresh: searchFreshness{r: inventory.NewReader(db, nil)}, Cursors: cur}, nil
}

// catalogSchema reads the live schema catalogue the search index compiles against. Register has no
// context, so the read is bounded by schemaTimeout.
func catalogSchema(db *store.DB) (reportsql.Schema, error) {
	ctx, cancel := context.WithTimeout(context.Background(), schemaTimeout)
	defer cancel()
	var sc reportsql.Schema
	err := db.WithPlatform(ctx, "directory: read the schema catalogue to compile the search index", func(ctx context.Context, tx store.Tx) error {
		var err error
		sc, err = reportsql.CatalogSchema(ctx, tx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("directory: search schema: %w", err)
	}
	return sc, nil
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
