// Package delegation is the server module for access administration (blueprint §5.4, ADR-0003). It
// contributes the four Actions that change who may do what: create and edit a custom role, grant and
// revoke an assignment. It owns no table (F1): it writes DM-34 to DM-36 through rbac.Grants inside the
// runner's transaction, so the change, its audit event and its no-escalation proof commit together
// (DM-36.I1). It also owns the EP-6 scope evaluators for the directory root kinds (scope.go).
// It decides nothing about who may call it: the permission of each Action does, in the runner.
package delegation

import (
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

// ModuleID is the module's ID, its OpenAPI tag and its web module ID.
const ModuleID module.ID = "delegation"

// Module is the delegation module.
type Module struct{ access *rbac.Grants }

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir directory.Services) *Module {
	_ = dir
	return &Module{access: deps.Access}
}

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: roles and assignments live in activeDIQ's own store, whichever
// directory is connected.
func (*Module) Requires() []capability.ID { return nil }

// Register implements module.Module.
func (m *Module) Register(r *module.Registrar) error {
	as, err := Actions(m.access)
	if err != nil {
		return err
	}
	for _, a := range as {
		if err := r.Action(a); err != nil {
			return err
		}
	}
	return registerScopeEvaluators(r)
}
