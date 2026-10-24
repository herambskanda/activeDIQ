// Package inventory is the server module for the directory inventory's customer-facing writes
// (blueprint §5.2, ADR-0003). It contributes the configuration Actions that change the customer's
// Tier-0 designations (DM-16.I8). It owns no table (F1): it writes through directory/inventory's Go
// API inside its Actions' transactions, so every change is permission-checked, step-up gated and
// audited by the Operation runner.
package inventory

import (
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
)

// ModuleID is the module's ID, its OpenAPI tag and its web module ID.
const ModuleID module.ID = "inventory"

// Module is the inventory module.
type Module struct{}

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir directory.Services) *Module {
	_, _ = deps, dir
	return &Module{}
}

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: designations apply to either directory kind.
func (*Module) Requires() []capability.ID { return nil }

// Register implements module.Module.
func (*Module) Register(r *module.Registrar) error {
	a, err := SetDesignation()
	if err != nil {
		return err
	}
	return r.Action(a)
}
