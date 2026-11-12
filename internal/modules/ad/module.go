// Package ad is the server module for account-state Actions on an AD connection (blueprint §5.4,
// ADR-0003, ADR-0005): reset password, unlock, enable, disable. It owns no table and writes nothing
// itself. Plan reads the live account on the operation's pins and reports what will change; Apply
// hands the connector's account kinds (directory/accountkind) to the directory client with the
// runner's Step, which is the only key to the write; Verify re-reads the account and re-runs the
// Tier-0 check before it confirms. The four Actions share one builder (actions.go) and differ only
// in a spec row, so a fifth account kind is a row, not a handler.
//
// It decides nothing about who may call it: the permission of each Action does, in the runner, at
// Plan and again at Apply (rule 7). Nothing here builds an LDAP filter, DN or PowerShell string.
package ad

import (
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
)

// ModuleID is the module's ID and the owner segment of its Action IDs.
const ModuleID module.ID = "ad"

// Module is the ad module.
type Module struct{ ports ports }

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir directory.Services) *Module {
	_ = deps
	return &Module{ports: ports{reader: dir.AccountReader, writer: dir.AccountWriter}}
}

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: the account kinds exist on an AD connection only; Entra is not
// an AccountProvider (connector contract §8.10.10).
func (*Module) Requires() []capability.ID { return []capability.ID{capability.DirectoryAD} }

// Register implements module.Module.
func (m *Module) Register(r *module.Registrar) error {
	as, err := Actions(m.ports.reader, m.ports.writer)
	if err != nil {
		return err
	}
	for _, a := range as {
		if err := r.Action(a); err != nil {
			return err
		}
	}
	return nil
}
