package connector

import (
	"context"
	"log/slog"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/fleet/tunnelclient"
	"github.com/skenzeriq/activediq/internal/platform/ownerfile"
)

// Test seams for the external tests: the real Run with substituted dial-out and AD session.
type Backend = backend

func NewBackend(v *rights.VerifyHandler, r *read.Handler, w *write.Handler, closeFn func()) *Backend {
	return &backend{verify: v, read: r, write: w, close: closeFn}
}

func RunWith(ctx context.Context, cfg config.Config,
	load func(string) (*dial.State, error),
	open func(context.Context, Local, *slog.Logger) (*Backend, error),
	serve func(context.Context, tunnelclient.Config)) error {
	return run(ctx, cfg, env{ensureDir: func(string) error { return nil }, load: load, open: open, serve: serve})
}

// RunWithEnsure is RunWith with the state-directory check substituted.
func RunWithEnsure(ctx context.Context, cfg config.Config, ensure func(string) error,
	load func(string) (*dial.State, error),
	open func(context.Context, Local, *slog.Logger) (*Backend, error),
	serve func(context.Context, tunnelclient.Config)) error {
	return run(ctx, cfg, env{ensureDir: ensure, load: load, open: open, serve: serve})
}

// RunReal is Run with only the dial-out and the AD session substituted: the real ownerfile check runs.
func RunReal(ctx context.Context, cfg config.Config,
	load func(string) (*dial.State, error),
	open func(context.Context, Local, *slog.Logger) (*Backend, error),
	serve func(context.Context, tunnelclient.Config)) error {
	return run(ctx, cfg, env{ensureDir: ownerfile.EnsureDir, load: load, open: open, serve: serve})
}

// OpenBackend is the real AD-session assembly, for the lab-tagged end-to-end test.
func OpenBackend(ctx context.Context, loc Local, log *slog.Logger) (*Backend, error) {
	return openBackend(ctx, loc, log)
}

// Handlers exposes the bound handlers of a backend to external tests.
func (b *Backend) Handlers() (*rights.VerifyHandler, *read.Handler, *write.Handler) {
	return b.verify, b.read, b.write
}

func (b *Backend) Close() { b.close() }
