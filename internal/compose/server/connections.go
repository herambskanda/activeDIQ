package server

import (
	"fmt"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// connectionKernel is what buildConnections wires: the service that runs verifications and the jobs
// that schedule the rights check.
type connectionKernel struct {
	Service *connection.Service
	Jobs    *connection.Jobs
}

// buildConnections wires connection.Service to the registry, the directory client (its VerifyConnection
// half) and the audit chain, and registers the scheduled rights check in the job registry the worker
// runs. Activation starts the tenant's cadence in its own transaction. A client with no verify
// transport fails every run closed (client.ErrNoVerifier): the run is recorded as failed and the
// write gate stays shut, so wiring ahead of the gRPC transport is safe.
func buildConnections(db *store.DB, sink audit.Sink, c *client.Client, jreg *jobs.Registry, opts ...connection.Option) (*connectionKernel, error) {
	fw := &lateScheduler{}
	svc, err := connection.NewService(connection.NewRegistry(db), c, sink, append([]connection.Option{connection.WithScheduler(fw)}, opts...)...)
	if err != nil {
		return nil, fmt.Errorf("server: connection service: %w", err)
	}
	j, err := connection.RegisterJobs(jreg, svc, 0)
	if err != nil {
		return nil, fmt.Errorf("server: connection jobs: %w", err)
	}
	fw.Scheduler = j
	return &connectionKernel{Service: svc, Jobs: j}, nil
}

// lateScheduler breaks the construction cycle: the job body needs the service, the service needs the
// scheduler. It is set before buildConnections returns.
type lateScheduler struct{ connection.Scheduler }
