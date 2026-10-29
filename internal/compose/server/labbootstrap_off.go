//go:build !lab

package server

import (
	"context"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// labSeeder seeds lab connections; the production build's is a no-op.
type labSeeder func(ctx context.Context, conns *connection.Registry, svc *connection.Service, tid tenant.ID) error

// labBootstrap is inert in a production build (T-0684): the lab bootstrap is compiled only under the
// `lab` build tag, so a shipped server neither reads WIN_LAB_* / LAB_* nor seeds a connection nor
// opens an in-process connector, whatever its environment holds. It hands back next unchanged.
func labBootstrap(_ context.Context, _ func(string) string, next client.ConnectorSource) (client.ConnectorSource, labSeeder, func(), error) {
	return next, func(context.Context, *connection.Registry, *connection.Service, tenant.ID) error { return nil }, func() {}, nil
}
