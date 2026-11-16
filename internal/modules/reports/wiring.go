package reports

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ErrNoReadScopes is returned by Register when the module is wired to a store but not to the read-scope
// producer: no installation can run reports without it, and none reads unscoped.
var ErrNoReadScopes = errors.New("reports: the module needs the read-scope producer")

// wiring is what Register builds from the kernel ports: the run service, the export service and the
// library, and the API handlers over them (T-0959, T-0963, T-1104). The library compiles the report
// host's datasets against the live schema, so it can only be loaded once every module has registered
// and the host is sealed; until the ready hook runs the catalogue is empty and every run is refused.
//
// One port has no production implementation yet, and it fails closed rather than guess: the blob store
// when Deps.BlobDir is empty, so an export answers 503 not-ready rather than keep a file elsewhere.
type wiring struct {
	runs     *run.Service
	exports  *export.Service
	cat      *lateLibrary
	handlers *Handlers
}

// build wires the services from the kernel ports. A nil store means the module is not configured for
// routes (a boot test with zero Deps), and it returns nil, nil: it registers no route and no job.
func (m *Module) build() (*wiring, error) {
	d := m.deps
	if d.DB == nil {
		return nil, nil
	}
	if d.ReadScopes == nil {
		return nil, ErrNoReadScopes
	}
	if d.Jobs == nil {
		return nil, errors.New("reports: the module needs the job registry")
	}
	cat := &lateLibrary{}
	svc := &run.Service{DB: d.DB, Jobs: d.Jobs, Scopes: d.ReadScopes, Audit: d.Audit, Catalog: cat, Codec: Codec{},
		Fresh: inventoryFreshness{r: m.dir.Inventory}}
	exports := &export.Service{DB: d.DB, Jobs: d.Jobs, Runs: svc, Audit: d.Audit, Authz: authorizer{az: d.Authz}}
	if d.BlobDir != "" {
		bs, err := blob.NewFS(d.BlobDir)
		if err != nil {
			return nil, fmt.Errorf("reports: blob store: %w", err)
		}
		exports.Blob = bs
	}
	return &wiring{runs: svc, exports: exports, cat: cat,
		handlers: &Handlers{Runs: svc, Exports: exports, Library: cat}}, nil
}

// register contributes the routes, the job kinds and the ready hook. The retention cadence is seeded by
// the kernel for the install tenant (Job.Seed); the job reschedules itself and the seed is keyed by day,
// so seeding on every boot, or on several nodes, leaves one cadence.
func (w *wiring) register(r *module.Registrar, m *Module) error {
	if err := r.API(api.Bind(w.handlers)); err != nil {
		return err
	}
	for _, j := range []module.Job{
		{Kind: w.runs.Kind()},
		{Kind: w.runs.RetentionKind(), Seed: func(ctx context.Context, tx store.Tx, tid tenant.ID) error {
			return w.runs.ScheduleRetention(ctx, tx, tid)
		}},
		{Kind: w.exports.Kind()},
	} {
		if err := r.Job(j); err != nil {
			return err
		}
	}
	return r.Ready(func(ctx context.Context) error { return w.load(ctx, m) })
}

// load compiles the sealed host's datasets against the live schema (reportsql.NewRegistry) and loads the
// shipped definitions over them (library.Load). A definition that does not resolve stops start-up.
func (w *wiring) load(ctx context.Context, m *Module) error {
	host := m.deps.Report
	var ds []report.Dataset
	for _, id := range host.Datasets() {
		d, _ := host.Dataset(id)
		ds = append(ds, d)
	}
	sc, err := schema(ctx, m.deps.DB)
	if err != nil {
		return err
	}
	reg, err := reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: inventory.SecretKey}, ds...)
	if err != nil {
		return fmt.Errorf("reports: report datasets: %w", err)
	}
	lib, err := library.Load(library.Shipped(), library.Options{Datasets: ds, Registry: reg})
	if err != nil {
		return fmt.Errorf("reports: report library: %w", err)
	}
	w.cat.lib.Store(lib)
	return nil
}

// schema reads the public schema catalogue once at start-up, before the install tenant exists. The
// catalogue is the same for every tenant and holds no tenant data, so the read runs in platform scope
// (registered platform path, exemption registry).
func schema(ctx context.Context, db *store.DB) (reportsql.Schema, error) {
	var sc reportsql.Schema
	rctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	err := db.WithPlatform(rctx, "reports: read the schema catalogue to compile the report datasets", func(ctx context.Context, tx store.Tx) error {
		var err error
		sc, err = reportsql.CatalogSchema(ctx, tx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("reports: report schema: %w", err)
	}
	return sc, nil
}

// lateLibrary is the catalogue the services hold before the library exists. It finds nothing until the
// ready hook stores the loaded library, so an early run is refused as an unknown definition.
type lateLibrary struct {
	lib atomic.Pointer[library.Library]
}

var (
	_ Library     = (*lateLibrary)(nil)
	_ run.Catalog = (*lateLibrary)(nil)
)

func (l *lateLibrary) List() []library.Item {
	if lib := l.lib.Load(); lib != nil {
		return lib.List()
	}
	return nil
}

func (l *lateLibrary) Search(q string, limit int) []library.Match {
	if lib := l.lib.Load(); lib != nil {
		return lib.Search(q, limit)
	}
	return nil
}

func (l *lateLibrary) Definition(id string, version int) (run.Definition, bool) {
	if lib := l.lib.Load(); lib != nil {
		return lib.Definition(id, version)
	}
	return run.Definition{}, false
}

// inventoryFreshness reads the sync watermarks of the connections a result covers from the inventory
// reader (D6) and hands the run path the label and the threshold it used.
type inventoryFreshness struct{ r *inventory.Reader }

func (f inventoryFreshness) Freshness(ctx context.Context, tid tenant.ID, cs []authz.ObjectID, now time.Time) (run.FreshnessRead, error) {
	if f.r == nil {
		return run.FreshnessRead{}, errors.New("reports: no inventory reader")
	}
	q := inventory.FreshnessQuery{Now: now}
	for _, c := range cs {
		q.Connections = append(q.Connections, inventory.ConnectionID(report.GUIDString(c)))
	}
	res, err := f.r.Freshness(ctx, tid, q)
	if err != nil {
		return run.FreshnessRead{}, err
	}
	names := make(map[string]string, len(res.Names))
	for id, n := range res.Names {
		names[string(id)] = n
	}
	return run.FreshnessRead{Label: res.Label, Threshold: res.Threshold, Names: names}, nil
}

// authorizer answers export.Authorizer from the shared RBAC authorizer, at tenant scope like the API
// host's permission step. A missing authorizer, or any fault, refuses: it never allows by default.
type authorizer struct{ az operation.Authorizer }

func (a authorizer) Allow(ctx context.Context, tid tenant.ID, c authority.Chain, p authz.Permission) (bool, error) {
	if a.az == nil {
		return false, nil
	}
	target := authority.TargetRef{Class: rbac.TargetClassTenant, GUID: tid.String()}
	ctx = authority.WithTenant(ctx, tid.String())
	// The session's authority factor travels as on the console path. Off a request (the rerun job) there is
	// no principal, the factor is absent, and a grant that needs it is refused: it fails closed.
	if pr, ok := apihost.PrincipalFrom(ctx); ok {
		ctx = authority.WithAuthorityFactor(ctx, pr.AuthorityFactor)
	}
	err := a.az.Authorize(ctx, c, p, target, authority.Facts{})
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, rbac.ErrDenied):
		return false, nil
	default:
		return false, err
	}
}
