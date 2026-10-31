package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports"
	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// buildReports wires the report run path (T-0959) and the export path (T-0963): the run service over the
// store and the job registry, the export service over the same and the blob store, their job kinds and the
// API handlers. The catalogue is the shipped report library (T-1104), loaded over the datasets the sealed
// EP-8 host holds, so a definition that does not resolve against its dataset stops start-up.
//
// Two ports have no production implementation yet, and each fails closed rather than guess:
//   - the read-scope producer (rbac.ReadScopes needs the owner-status and object-connection sources), so a
//     run cannot be created or read and the API answers 503 not-ready (filed as a follow-up on T-0959);
//   - the blob store when blobDir is empty: an export answers 503 not-ready rather than keep a file
//     anywhere else.
func buildReports(ctx context.Context, db *store.DB, host *report.Host, jreg *jobs.Registry, sink audit.Sink, reader *inventory.Reader, scopes run.ReadScopes, az operation.Authorizer, blobDir string) (*run.Service, apihost.TagHandlers, error) {
	if scopes == nil {
		scopes = noScopes{}
	}
	lib, err := reportLibrary(ctx, db, host)
	if err != nil {
		return nil, apihost.TagHandlers{}, err
	}
	svc := &run.Service{DB: db, Jobs: jreg, Scopes: scopes, Audit: sink, Catalog: lib, Codec: reports.Codec{},
		Fresh: inventoryFreshness{r: reader}}
	exports := &export.Service{DB: db, Jobs: jreg, Runs: svc, Audit: sink, Authz: reportsAuthz{az}}
	if blobDir != "" {
		bs, err := blob.NewFS(blobDir)
		if err != nil {
			return nil, apihost.TagHandlers{}, fmt.Errorf("server: blob store: %w", err)
		}
		exports.Blob = bs
	}
	for _, k := range []jobs.Kind{svc.Kind(), svc.RetentionKind(), exports.Kind()} {
		if err := jreg.Register(k); err != nil {
			return nil, apihost.TagHandlers{}, fmt.Errorf("server: reports job kind %s: %w", k.Name, err)
		}
	}
	return svc, (&reports.Handlers{Runs: svc, Exports: exports, Library: lib}).Bind(), nil
}

// reportLibrary compiles the host's datasets against the live schema (reportsql.NewRegistry) and loads
// the shipped definitions over them (library.Load).
func reportLibrary(ctx context.Context, db *store.DB, host *report.Host) (*library.Library, error) {
	var ds []report.Dataset
	for _, id := range host.Datasets() {
		d, _ := host.Dataset(id)
		ds = append(ds, d)
	}
	sc, err := reportSchema(ctx, db)
	if err != nil {
		return nil, err
	}
	reg, err := reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: inventory.SecretKey}, ds...)
	if err != nil {
		return nil, fmt.Errorf("server: report datasets: %w", err)
	}
	lib, err := library.Load(library.Shipped(), library.Options{Datasets: ds, Registry: reg})
	if err != nil {
		return nil, fmt.Errorf("server: report library: %w", err)
	}
	return lib, nil
}

// reportSchema reads the public schema catalogue once at start-up, before the install tenant exists.
// The catalogue is the same for every tenant and holds no tenant data, so the read runs in platform
// scope (registered platform path, exemption registry).
func reportSchema(ctx context.Context, db *store.DB) (reportsql.Schema, error) {
	var sc reportsql.Schema
	rctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	err := db.WithPlatform(rctx, "server: read the schema catalogue to compile the report datasets", func(ctx context.Context, tx store.Tx) error {
		var err error
		sc, err = reportsql.CatalogSchema(ctx, tx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("server: report schema: %w", err)
	}
	return sc, nil
}

// startReportRetention seeds the retention sweep for the install tenant. The job reschedules itself and
// the seed is keyed by interval bucket, so seeding on every boot, or on several nodes, leaves one cadence
// (the same boot-time enqueue as the throttle purge; there is no general scheduler yet, DM-44).
func startReportRetention(ctx context.Context, db *store.DB, svc *run.Service, tid tenant.ID) error {
	sctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := db.WithTenant(sctx, tid, func(ctx context.Context, tx store.Tx) error {
		return svc.ScheduleRetention(ctx, tx, tid)
	}); err != nil {
		return fmt.Errorf("server: schedule report retention: %w", err)
	}
	return nil
}

// noScopes is the read-scope producer of an installation that has not wired rbac.ReadScopes.
type noScopes struct{}

func (noScopes) For(context.Context, store.Tx, tenant.ID, authority.Chain, authz.Permission) (authz.ReadScope, error) {
	return authz.ReadScope{}, run.ErrScopesUnavailable
}

// inventoryFreshness reads the sync watermarks of the connections a result covers from the inventory
// reader (D6) and hands the run path the label and the threshold it used.
type inventoryFreshness struct{ r *inventory.Reader }

func (f inventoryFreshness) Freshness(ctx context.Context, tid tenant.ID, cs []authz.ObjectID, now time.Time) (run.FreshnessRead, error) {
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

// reportsAuthz answers export.Authorizer from the shared RBAC authorizer, at tenant scope like the API
// host's permission step. A missing authorizer, or any fault, refuses: it never allows by default.
type reportsAuthz struct{ az operation.Authorizer }

func (a reportsAuthz) Allow(ctx context.Context, tid tenant.ID, c authority.Chain, p authz.Permission) (bool, error) {
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
