package server

import (
	"context"
	"log/slog"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/health"
	healthapi "github.com/skenzeriq/activediq/internal/platform/health/api"
)

// pinger is what the readiness probe asks of the store: does the database answer.
type pinger interface {
	Ping(ctx context.Context) error
}

// buildHealth mounts the anonymous platform probes (AN-1, tag platform.health): /health/live and
// /health/ready, which load balancers, the container healthcheck and the Windows service check probe.
// Readiness is the database answering; the health package bounds each check, shares one probe round
// between concurrent callers and reuses a finished round for a short time, so an anonymous caller cannot
// drive the database. A failed check reaches the log only, never the response.
func buildHealth(db pinger, log *slog.Logger) apihost.TagHandlers {
	return healthapi.Bind(health.New(log, []health.NamedCheck{
		{Name: "store", Check: db.Ping},
	}))
}
