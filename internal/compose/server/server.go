// Package server is the composition-root role package of cmd/server (blueprint §1, §2 rule 7). It wires
// this role's adapters and imports only what that binary may link. It boots the (still empty)
// generated module list, opens the store and runs the job worker until the process is told to stop.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// ErrNoDatabase is returned by Run when no database DSN is configured. The server has nothing to do
// without its database, and it must say so rather than idle.
var ErrNoDatabase = errors.New("server: no database configured (" + config.EnvDatabaseDSN + ")")

// Run runs the server role until ctx is done: it boots the modules, opens the store and runs the job
// worker. When ctx ends the worker stops claiming and drains; Run returns jobs.ErrDrainTimeout (wrapped)
// if running bodies ignored the forced cancellation, which the binary turns into a non-zero exit.
func Run(ctx context.Context, cfg config.Config) error {
	if cfg.DatabaseDSN == "" {
		return ErrNoDatabase
	}
	// Capabilities come from the deployment profile once config selects one; no module requires
	// one yet.
	if _, err := boot(ctx, capability.NewSet()); err != nil {
		return fmt.Errorf("server: boot modules: %w", err)
	}
	db, err := store.Open(ctx, store.Config{DSN: cfg.DatabaseDSN})
	if err != nil {
		return fmt.Errorf("server: open store: %w", err)
	}
	defer db.Close()
	// Modules contribute job kinds to this registry once the Registrar grows a Job method; until then
	// it is empty and the worker only runs its maintenance timers.
	return runWorker(ctx, db, jobs.NewRegistry(), jobs.WorkerConfig{Holder: cfg.InstanceID, ShutdownGrace: cfg.ShutdownGrace})
}

// runWorker builds the worker and runs it until ctx ends. An invalid holder or setting fails here,
// before anything is claimed.
func runWorker(ctx context.Context, db *store.DB, reg *jobs.Registry, wcfg jobs.WorkerConfig) error {
	w, err := jobs.NewWorker(db, reg, wcfg)
	if err != nil {
		return fmt.Errorf("server: job worker: %w", err)
	}
	slog.Info("server: job worker started")
	if err := w.Run(ctx); err != nil {
		slog.Error("server: job worker did not drain; unfinished claims are left for the next process to rescue", "err", err)
		return fmt.Errorf("server: job worker: %w", err)
	}
	slog.Info("server: job worker stopped")
	return nil
}

// boot hands the generated module list to module.Boot, the only caller of it (ADR-0003 rule 5).
func boot(ctx context.Context, enabled capability.Set) (*module.Contributions, error) {
	return module.Boot(ctx, generatedModules(platform.Deps{}, directory.Services{}), enabled)
}
