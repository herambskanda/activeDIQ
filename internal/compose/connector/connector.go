// Package connector is the composition-root role package of cmd/connector (blueprint §1, §2 rule 7). It wires
// this role's adapters and imports only what that binary may link. The skeleton wires nothing yet:
// Run reports that the role is not built.
package connector

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/compose/config"
)

// ErrNotBuilt is returned by Run until the role is implemented. A role that does nothing must say
// so; it must never exit successfully as if it had run.
var ErrNotBuilt = errors.New("connector: role not built yet")

// Run runs the connector role until ctx is done.
func Run(ctx context.Context, cfg config.Config) error {
	_, _ = ctx, cfg
	return ErrNotBuilt
}
