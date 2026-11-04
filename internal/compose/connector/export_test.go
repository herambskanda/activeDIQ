package connector

import (
	"context"
	"log/slog"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/connector/service"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/fleet/tunnelclient"
)

// Test seams for the external tests: the real Run with substituted dial-out and AD session.
type Backend = backend

func NewBackend(svc *service.Service, closeFn func()) *Backend {
	return &backend{svc: svc, close: closeFn}
}

func RunWith(ctx context.Context, cfg config.Config,
	load func(string) (*dial.State, error),
	open func(context.Context, Local, *slog.Logger) (*Backend, error),
	serve func(context.Context, tunnelclient.Config)) error {
	return run(ctx, cfg, env{load: load, open: open, serve: serve})
}

// OpenBackend is the real AD-session assembly, for the lab-tagged end-to-end test.
func OpenBackend(ctx context.Context, loc Local, log *slog.Logger) (*Backend, error) {
	return openBackend(ctx, loc, log)
}

// Service exposes the bound service of a backend to external tests.
func (b *Backend) Service() *service.Service { return b.svc }

func (b *Backend) Close() { b.close() }
