// Package compliance is the server module for legal holds on personal subjects (ADR-0005 rule 11). It
// contributes the two Actions that place and lift a hold. It owns no table (F1): it writes through
// personal.Store inside the runner's transaction, so a hold change, its audit event and its permission
// check commit together. The runtime role could DELETE a hold row directly; nothing in the database can tell
// that from a sanctioned release, so releasing is reachable in the product only through this module's
// RBAC-gated, step-up-gated, human-only, audited Action.
package compliance

import (
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
)

// ModuleID is the module's ID, its OpenAPI tag and its web module ID.
const ModuleID module.ID = "compliance"

// Module is the compliance module.
type Module struct{}

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir directory.Services) *Module {
	_, _ = deps, dir
	return &Module{}
}

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: holds live in activeDIQ's own store, whichever directory is connected.
func (*Module) Requires() []capability.ID { return nil }

// Register implements module.Module.
func (*Module) Register(r *module.Registrar) error {
	for _, build := range []func() (operationAction, error){SetHold, ReleaseHold} {
		a, err := build()
		if err != nil {
			return err
		}
		if err := r.Action(a); err != nil {
			return err
		}
	}
	return nil
}
