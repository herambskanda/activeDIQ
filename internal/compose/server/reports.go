package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports"
	"github.com/skenzeriq/activediq/internal/modules/reports/export"
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
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// buildReports wires the report run path (T-0959) and the export path (T-0963): the run service over the
// store and the job registry, the export service over the same and the blob store, their job kinds and the
// API handlers.
//
// Two ports have no production implementation yet, and each fails closed rather than guess:
//   - the read-scope producer (rbac.ReadScopes needs the owner-status and object-connection sources), so a
//     run cannot be created or read and the API answers 503 not-ready;
//   - the report library (row B5), so every definition is unknown and the API answers 404.
//
// Both are filed as follow-ups on T-0959. A third port fails closed the same way: with no blob store
// (blobDir empty) an export answers 503 not-ready rather than keep a file anywhere else.
func buildReports(db *store.DB, jreg *jobs.Registry, sink audit.Sink, reader *inventory.Reader, scopes run.ReadScopes, az operation.Authorizer, blobDir string) (*run.Service, apihost.TagHandlers, error) {
	if scopes == nil {
		scopes = noScopes{}
	}
	svc := &run.Service{DB: db, Jobs: jreg, Scopes: scopes, Audit: sink, Catalog: noLibrary{}, Codec: reports.Codec{},
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
	return svc, (&reports.Handlers{Runs: svc, Exports: exports}).Bind(), nil
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

// noLibrary is the catalogue before the report library lands: it knows no definition.
type noLibrary struct{}

func (noLibrary) Definition(string, int) (run.Definition, bool) { return run.Definition{}, false }

// inventoryFreshness reads the sync watermarks of the connections a result covers from the inventory
// reader (D6) and hands the run path the label and the threshold it used.
type inventoryFreshness struct{ r *inventory.Reader }

func (f inventoryFreshness) Freshness(ctx context.Context, tid tenant.ID, cs []authz.ObjectID, now time.Time) (report.Freshness, time.Duration, error) {
	q := inventory.FreshnessQuery{Now: now}
	for _, c := range cs {
		q.Connections = append(q.Connections, inventory.ConnectionID(report.GUIDString(c)))
	}
	res, err := f.r.Freshness(ctx, tid, q)
	if err != nil {
		return report.Freshness{}, 0, err
	}
	return res.Label, res.Threshold, nil
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
