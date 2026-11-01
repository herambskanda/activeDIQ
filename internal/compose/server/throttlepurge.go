package server

import (
	"context"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authn/throttlejob"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// startThrottlePurge registers authn.throttle.purge (T-0868) and seeds the install tenant's cadence in its
// own transaction. The job reschedules itself, and the seed is keyed by interval bucket, so running this on
// every boot, or on several nodes, leaves one cadence. There is no general scheduler for tenant-carrying
// periodic kinds yet (DM-44): this is the boot-time enqueue the audit and connection cadences also use.
func startThrottlePurge(ctx context.Context, db *store.DB, jreg *jobs.Registry, creds *authn.LocalCredentials, tid tenant.ID) error {
	tj, err := throttlejob.Register(jreg, creds, 0)
	if err != nil {
		return fmt.Errorf("server: throttle purge job: %w", err)
	}
	sctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := db.WithTenant(sctx, tid, func(ctx context.Context, tx store.Tx) error {
		return tj.Schedule(ctx, tx, tid)
	}); err != nil {
		return fmt.Errorf("server: schedule throttle purge: %w", err)
	}
	return nil
}
