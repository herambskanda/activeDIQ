// Package connector is the composition-root role package of cmd/connector (blueprint §1, §2 rule 7). It wires
// this role's adapters and imports only what that binary may link: the directory connector, the tunnel
// dial-out and the local configuration. The connector opens no listener: the server reaches it only
// through the tunnel the connector dialled out (TB6, TM-TB6-T10).
package connector

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/tunnelbind"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/fleet/tunnelclient"
	"github.com/skenzeriq/activediq/internal/platform/ownerfile"
)

// Errors the caller can tell apart: a missing configuration or enrolment is an operator action, not a
// crash loop.
var (
	ErrNoConfig    = errors.New("connector: " + config.EnvConnectorConfig + " is not set")
	ErrNotEnrolled = errors.New("connector: not enrolled; enrol this connector first")
	// ErrStateDirUnsafe: the state directory (or its parent) could not be created or verified as
	// restricted to the service identity. The connector refuses to start: it reads and writes the
	// shrink baseline, ratchet and records there (T-0577, T-0596).
	ErrStateDirUnsafe = errors.New("connector: state directory is not safe")
)

// env holds the seams Run is built from; the tests replace them, Run never does.
type env struct {
	// ensureDir creates or verifies a state directory (ownerfile.EnsureDir in Run).
	ensureDir func(dir string) error
	load      func(dir string) (*dial.State, error)
	open      func(ctx context.Context, loc Local, log *slog.Logger) (*backend, error)
	serve     func(ctx context.Context, c tunnelclient.Config)
}

// Run runs the connector role until ctx is done: configuration, the enrolled mTLS leaf, the AD session
// bound to the configured connection, the durable baseline, then the tunnel.
func Run(ctx context.Context, cfg config.Config) error {
	return run(ctx, cfg, env{ensureDir: ownerfile.EnsureDir, load: dial.Load, open: openBackend, serve: tunnelclient.Run})
}

func run(ctx context.Context, cfg config.Config, e env) error {
	loc, err := LoadLocal(cfg.ConnectorConfigPath)
	if err != nil {
		return err
	}
	// Before anything is read from or written to DataDir, and before the tunnel is dialled.
	if err := ensureStateDir(loc.DataDir, e.ensureDir); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	st, err := e.load(loc.EnrollmentDir)
	if err != nil || len(st.Leaf.Certificate) == 0 {
		return ErrNotEnrolled
	}
	leaf, err := x509.ParseCertificate(st.Leaf.Certificate[0])
	if err != nil {
		return ErrNotEnrolled
	}
	id, err := fleet.IdentityOf(leaf)
	if err != nil || id.Kind != fleet.KindConnector {
		return ErrNotEnrolled
	}
	be, err := e.open(ctx, loc, log)
	if err != nil {
		return err
	}
	defer be.close()
	binding, err := TunnelBinding(be.verify, be.read, be.write)
	if err != nil {
		return err
	}
	e.serve(ctx, tunnelclient.Config{State: st, Identity: id, Binding: binding, Log: log, Open: tunnelbind.Open})
	return nil
}

// ensureStateDir verifies the connector's state root and then the state directory: first the
// parent of dataDir, then dataDir itself, each with ensure (ownerfile.EnsureDir). EnsureDir creates
// only the last path element, and an ordinary parent (C:\ProgramData lets BUILTIN\Users create
// subfolders) would let a local user pre-create or rename the state directory, so the parent must be
// the connector's own directory, service-identity-only like the state directory (contract §8.3a,
// security review of T-0577). If the parent does not exist, ensure creates it protected. Any
// failure refuses the start, naming the directory; the cause is kept for errors.Is.
func ensureStateDir(dataDir string, ensure func(string) error) error {
	parent := filepath.Dir(dataDir)
	if parent == dataDir {
		return fmt.Errorf("%w: %q has no parent directory of its own", ErrStateDirUnsafe, dataDir)
	}
	for _, d := range []string{parent, dataDir} {
		if err := ensure(d); err != nil {
			return fmt.Errorf("%w: %q: %w; refusing to start", ErrStateDirUnsafe, d, err)
		}
	}
	return nil
}
