package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// syncKernel is what buildSync wires: the sync.full job kind and the supervisor that queues it.
type syncKernel struct {
	Jobs       *dsync.Jobs
	Supervisor *syncSupervisor
}

// buildSync registers sync.full (T-1192) over the engine of T-1191 and returns the supervisor that queues
// one job per active AD connection. The engine reads through csrc, the same connector source the other
// directory paths use, so a lab build's in-process connector and a production tunnel are both served.
// holder names this node on the platform leases the job takes (one reader per naming context). The
// activation hook it returns is handed to the connection service, so a connection that becomes active has
// its first read queued in the activation's own transaction.
func buildSync(db *store.DB, conns *connection.Registry, csrc client.ConnectorSource, jreg *jobs.Registry, holder string, interval time.Duration, leaseTTL time.Duration) (*syncKernel, error) {
	rsrc, err := client.NewReaderSource(csrc)
	if err != nil {
		return nil, fmt.Errorf("server: sync job: %w", err)
	}
	eng := &dsync.Engine{Tenants: db, Conns: conns, Domains: connectionDomains{conns: conns}, Source: rsrc,
		Ingester: dsync.NewIngester(), Cursors: dsync.Store{}, Log: slog.Default()}
	j, err := dsync.RegisterJobs(jreg, dsync.JobConfig{DB: db, Cycle: eng, Passes: inventory.Writer{}, Holder: holder, LeaseTTL: leaseTTL, Log: slog.Default()})
	if err != nil {
		return nil, fmt.Errorf("server: sync job: %w", err)
	}
	sup, err := newSyncSupervisor(db, conns, j, interval)
	if err != nil {
		return nil, err
	}
	return &syncKernel{Jobs: j, Supervisor: sup}, nil
}

// connectionDomains is the dsync.Domains of a connection until the managed-domain set (DM-14, FR-24) is
// stored: the one domain naming context every forest has, the forest root's, which is the connection's
// directory identity. A child domain is not read until an admin's selection exists to name it.
type connectionDomains struct{ conns *connection.Registry }

func (d connectionDomains) ManagedDomains(ctx context.Context, tid tenant.ID, id connection.ID) ([]dsync.Domain, error) {
	c, err := d.conns.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	if c.Kind != connection.KindADForest || c.DirectoryIdentity == "" {
		return nil, nil
	}
	return []dsync.Domain{{NC: inventory.GUID(strings.ToLower(string(c.DirectoryIdentity))), Kind: dsync.NCDomain}}, nil
}

// syncSupervisor queues sync.full for every ACTIVE AD connection of the install tenant: at boot, after an
// activation (the connection service's hook does that one) and every interval. It starts nothing itself:
// the job runs on the worker, under the platform lease. A duplicate is harmless: the job is de-duplicated
// on the connection while one is queued or running, and the lease allows one reader per partition.
type syncSupervisor struct {
	db       *store.DB
	conns    *connection.Registry
	jobs     *dsync.Jobs
	interval time.Duration
}

func newSyncSupervisor(db *store.DB, conns *connection.Registry, j *dsync.Jobs, interval time.Duration) (*syncSupervisor, error) {
	if interval < config.MinSyncInterval || interval > config.MaxSyncInterval {
		return nil, fmt.Errorf("server: sync interval must be between %s and %s", config.MinSyncInterval, config.MaxSyncInterval)
	}
	return &syncSupervisor{db: db, conns: conns, jobs: j, interval: interval}, nil
}

// enqueueActive queues a full read of each active, unretired AD connection of the tenant. It returns how
// many jobs it queued (a duplicate is not counted). Draft, verifying and suspended connections get none; a
// tenant with no connection is a no-op.
func (s *syncSupervisor) enqueueActive(ctx context.Context, tid tenant.ID) (int, error) {
	all, err := s.conns.List(ctx, tid, false)
	if err != nil {
		return 0, fmt.Errorf("server: sync supervisor: list connections: %w", err)
	}
	queued := 0
	for _, c := range all {
		if c.Kind != connection.KindADForest || c.State != connection.StateActive || c.RetiredAt != nil {
			continue
		}
		var dup bool
		if err := s.db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			e, err := s.jobs.Enqueue(ctx, tx, tid, c.ID)
			dup = e.Duplicate
			return err
		}); err != nil {
			return queued, fmt.Errorf("server: sync supervisor: enqueue: %w", err)
		}
		if !dup {
			queued++
		}
	}
	return queued, nil
}

// run queues once now (boot) and then every interval until ctx ends. A failed pass is logged and the next
// tick tries again: the supervisor never stops the server.
func (s *syncSupervisor) run(ctx context.Context, tid tenant.ID) {
	pass := func() {
		n, err := s.enqueueActive(ctx, tid)
		switch {
		case err != nil && ctx.Err() == nil:
			slog.Warn("server: queueing the directory sync failed; will retry", "err", err)
		case err == nil && n > 0:
			slog.Info("server: directory sync queued", "connections", n)
		}
	}
	pass()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pass()
		}
	}
}

// nodeHolder is the lease holder of a node that was given no ACTIVEDIQ_INSTANCE_ID: unique per process.
func nodeHolder() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("server: no randomness for the node id") // the process cannot make a safe lease holder either
	}
	return "node-" + hex.EncodeToString(b[:])
}
