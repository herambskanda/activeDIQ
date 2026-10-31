package server

import (
	"context"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// buildReports wires the report run path (T-0959): the run service over the store and the job registry,
// its two job kinds and the run API handlers.
//
// Two ports have no production implementation yet, and each fails closed rather than guess:
//   - the read-scope producer (rbac.ReadScopes needs the owner-status and object-connection sources), so a
//     run cannot be created or read and the API answers 503 not-ready;
//   - the report library (row B5), so every definition is unknown and the API answers 404.
//
// Both are filed as follow-ups on T-0959.
func buildReports(db *store.DB, jreg *jobs.Registry, sink audit.Sink, reader *inventory.Reader, scopes run.ReadScopes) (*run.Service, apihost.TagHandlers, error) {
	if scopes == nil {
		scopes = noScopes{}
	}
	svc := &run.Service{DB: db, Jobs: jreg, Scopes: scopes, Audit: sink, Catalog: noLibrary{}, Codec: reports.Codec{},
		Fresh: inventoryFreshness{r: reader}}
	for _, k := range []jobs.Kind{svc.Kind(), svc.RetentionKind()} {
		if err := jreg.Register(k); err != nil {
			return nil, apihost.TagHandlers{}, fmt.Errorf("server: reports job kind %s: %w", k.Name, err)
		}
	}
	return svc, (&reports.Handlers{Runs: svc}).Bind(), nil
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
