// Package connector is the composition-root role package of cmd/connector (blueprint §1, §2 rule 7). It wires
// this role's adapters and imports only what that binary may link: the directory connector, the tunnel
// dial-out and the local configuration. The connector opens no listener: the server reaches it only
// through the tunnel the connector dialled out (TB6, TM-TB6-T10).
package connector

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/tunnelbind"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/fleet/tunnelclient"
)

// Errors the caller can tell apart: a missing configuration or enrolment is an operator action, not a
// crash loop.
var (
	ErrNoConfig    = errors.New("connector: " + config.EnvConnectorConfig + " is not set")
	ErrNotEnrolled = errors.New("connector: not enrolled; enrol this connector first")
)

// env holds the seams Run is built from; the tests replace them, Run never does.
type env struct {
	load  func(dir string) (*dial.State, error)
	open  func(ctx context.Context, loc Local, log *slog.Logger) (*backend, error)
	serve func(ctx context.Context, c tunnelclient.Config)
}

// Run runs the connector role until ctx is done: configuration, the enrolled mTLS leaf, the AD session
// bound to the configured connection, the durable baseline, then the tunnel.
func Run(ctx context.Context, cfg config.Config) error {
	return run(ctx, cfg, env{load: dial.Load, open: openBackend, serve: tunnelclient.Run})
}

func run(ctx context.Context, cfg config.Config, e env) error {
	loc, err := LoadLocal(cfg.ConnectorConfigPath)
	if err != nil {
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
