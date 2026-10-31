// Package notify is the server module for the tenant's mail settings (T-0950). It contributes the one
// Action that changes them, notify.settings.update: the allowed recipient domains and the SMTP relay.
// It owns no table (F1): it writes through settings.Store inside the runner's transaction, so the
// change, its audit event and its step-up check commit together.
//
// Widening the allowed domains turns external addresses internal, and changing the relay re-points every
// outbound mail, so the Action carries StepUp and is a control-plane operation (TM-D30 SX-7).
package notify

import (
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
)

// ModuleID is the module's ID, its OpenAPI tag and its web module ID.
const ModuleID module.ID = "notify"

// Module is the notify module.
type Module struct{}

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir directory.Services) *Module {
	_, _ = deps, dir
	return &Module{}
}

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: settings live in activeDIQ's own store, whichever directory is connected.
func (*Module) Requires() []capability.ID { return nil }

// Register implements module.Module.
func (*Module) Register(r *module.Registrar) error {
	a, err := UpdateSettings()
	if err != nil {
		return err
	}
	return r.Action(a)
}
