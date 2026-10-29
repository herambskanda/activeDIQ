package server

import (
	"context"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// LabSeeder seeds a lab's connections once the tenant and the connection service exist. It is an alias
// of an unnamed func type so labboot (which the shipped server never imports) needs no import of this
// package.
type LabSeeder = func(ctx context.Context, conns *connection.Registry, svc *connection.Service, tid tenant.ID) error

// LabBootstrap wraps the connector source with in-process lab connectors and returns the seeder and a
// closer. Only the lab binary (tools/labserver) supplies one; the shipped server passes none.
type LabBootstrap = func(ctx context.Context, getenv func(string) string, next client.ConnectorSource) (client.ConnectorSource, LabSeeder, func(), error)

// Option configures Run.
type Option func(*runOptions)

type runOptions struct{ lab LabBootstrap }

// WithLabBootstrap attaches a lab bootstrap (T-0684).
func WithLabBootstrap(b LabBootstrap) Option { return func(o *runOptions) { o.lab = b } }
