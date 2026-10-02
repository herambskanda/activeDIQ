// Package server is the composition-root role package of cmd/server (blueprint §1, §2 rule 7). It wires
// this role's adapters and imports only what that binary may link. The skeleton boots the (still
// empty) generated module list and wires nothing else: Run then reports that the role is not built.
package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
)

// ErrNotBuilt is returned by Run until the role is implemented. A role that does nothing must say
// so; it must never exit successfully as if it had run.
var ErrNotBuilt = errors.New("server: role not built yet")

// Run runs the server role until ctx is done.
func Run(ctx context.Context, cfg config.Config) error {
	_ = cfg
	// Capabilities come from the deployment profile once config selects one; no module requires
	// one yet.
	if _, err := boot(ctx, capability.NewSet()); err != nil {
		return fmt.Errorf("server: boot modules: %w", err)
	}
	return ErrNotBuilt
}

// boot hands the generated module list to module.Boot, the only caller of it (ADR-0003 rule 5).
func boot(ctx context.Context, enabled capability.Set) (*module.Contributions, error) {
	return module.Boot(ctx, generatedModules(platform.Deps{}, directory.Services{}), enabled)
}
