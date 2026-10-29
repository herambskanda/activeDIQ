//go:build !lab

package server

import (
	"context"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// labBootstrap is inert in a production build (T-0684): the lab bootstrap is compiled only under the
// `lab` build tag, so a shipped server neither reads WIN_LAB_* / LAB_* nor seeds a connection nor
// opens an in-process connector, whatever its environment holds. It hands back next unchanged.
func labBootstrap(_ context.Context, _ *store.DB, _ *connection.Registry, _ func(string) string, next client.ConnectorSource) (client.ConnectorSource, func(), error) {
	return next, func() {}, nil
}
