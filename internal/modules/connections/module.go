// Package connections is the server module for directory connections (blueprint §5.4, ADR-0003). It
// contributes the configuration Actions that change a connection: here, the Tier-0 override of
// TM-D1. It owns no table (F1): it writes DM-10, DM-24 and DM-25 through directory/connection's Go
// API inside its Actions' transactions.
package connections

import (
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
)

// ModuleID is the module's ID, its OpenAPI tag and its web module ID.
const ModuleID module.ID = "connections"

// Module is the connections module.
type Module struct{}

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir directory.Services) *Module {
	_, _ = deps, dir
	return &Module{}
}

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: the module is useful with either directory kind.
func (*Module) Requires() []capability.ID { return nil }

// Register implements module.Module.
func (*Module) Register(r *module.Registrar) error {
	a, err := Tier0OverrideAcknowledge()
	if err != nil {
		return err
	}
	return r.Action(a)
}
