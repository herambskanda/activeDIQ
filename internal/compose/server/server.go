// Package server is the composition-root role package of cmd/server (blueprint §1, §2 rule 7). It wires
// this role's adapters and imports only what that binary may link. It boots the (still empty)
// generated module list, opens the store and runs the job worker until the process is told to stop.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
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
	// Build the API before anything is opened: a bad budget or contract fails startup here.
	api, err := buildAPI(cfg)
	if err != nil {
		return err
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
	ln, err := net.Listen("tcp", cfg.APIAddr)
	if err != nil {
		return fmt.Errorf("server: api listen: %w", err)
	}
	srv := newAPIServer(cfg.APIAddr, api)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	slog.Info("server: api listening", "addr", ln.Addr().String())

	// Modules contribute job kinds to this registry once the Registrar grows a Job method; until then
	// it is empty and the worker only runs its maintenance timers.
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerErr := make(chan error, 1)
	go func() {
		workerErr <- runWorker(wctx, db, jobs.NewRegistry(), jobs.WorkerConfig{Holder: cfg.InstanceID, ShutdownGrace: cfg.ShutdownGrace})
	}()

	var firstErr error
	select {
	case firstErr = <-workerErr:
		workerErr = nil
	case err := <-serveErr:
		firstErr = fmt.Errorf("server: api listener: %w", err)
		serveErr = nil
	}
	cancel()
	// The listener stops accepting and in-flight requests get the shutdown grace.
	sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownGrace)
	defer scancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
		if firstErr == nil {
			firstErr = fmt.Errorf("server: api shutdown: %w", err)
		}
	}
	if serveErr != nil {
		<-serveErr
	}
	if workerErr != nil {
		if err := <-workerErr; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// buildAPI makes the API handler: apihost.Build over the embedded contract with the body budget from
// configuration. No module contributes routes yet, so every tag is unmounted and answers a problem.
func buildAPI(cfg config.Config) (http.Handler, error) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		return nil, fmt.Errorf("server: api contract: %w", err)
	}
	s, err := apihost.Build(doc, nil, apiPolicy, apiCatalogue, failClosedPorts(), apihost.WithBodyBudget(cfg.APIBodyBudget))
	if err != nil {
		return nil, fmt.Errorf("server: build api: %w", err)
	}
	return s, nil
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
