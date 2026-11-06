package server

import (
	"context"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authn/alertjob"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// startAN8Alert registers the AN-8 owner-alert drain and watchdog (T-1544, RULING AN8-A1) and seeds the
// install tenant's cadences. The sign-in path only writes the outbox row; these jobs fan it out to the
// tenant-owners through notify. It returns the drain (banners) and the renderer for the delivery dispatcher.
func startAN8Alert(ctx context.Context, db *store.DB, jreg *jobs.Registry, sink audit.Sink, tid tenant.ID) (*authn.AlertDrain, alertjob.Renderer, error) {
	deliveries, err := delivery.New(sink)
	if err != nil {
		return nil, alertjob.Renderer{}, fmt.Errorf("server: an8 alert deliveries: %w", err)
	}
	drain := &authn.AlertDrain{DB: db, Owners: rbac.Owners{}, Sink: alertjob.Sink{Deliveries: deliveries}, Audit: sink}
	aj, err := alertjob.Register(jreg, drain)
	if err != nil {
		return nil, alertjob.Renderer{}, fmt.Errorf("server: an8 alert jobs: %w", err)
	}
	sctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := db.WithTenant(sctx, tid, func(ctx context.Context, tx store.Tx) error { return aj.Schedule(ctx, tx, tid) }); err != nil {
		return nil, alertjob.Renderer{}, fmt.Errorf("server: schedule an8 alert: %w", err)
	}
	return drain, alertjob.Renderer{Tenant: func() (tenant.ID, bool) { return tid, true }}, nil
}
