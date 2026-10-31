package reports

import (
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
)

// ModuleID is the module's ID, its OpenAPI tag and its web module ID.
const ModuleID module.ID = "reports"

// Module is the reports module. The run path (package run) and the API handlers are wired by the
// composition root, which owns the database, the job registry and the read-scope producer; the module
// itself registers what the platform collects at boot. Report datasets arrive with the library (row B5).
type Module struct{}

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir directory.Services) *Module {
	_, _ = deps, dir
	return &Module{}
}

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: reports read the collected store of either directory kind.
func (*Module) Requires() []capability.ID { return nil }

// Register implements module.Module.
func (*Module) Register(*module.Registrar) error { return nil }
