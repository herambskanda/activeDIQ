// Package agentfleet is the server module for the fleet of host agents, starting with addc (the DC
// agent): the name the agent-host contract left open (agent-host-addc-contract.md §7) and the module
// ID, OpenAPI tag and audit component of everything the server does for an agent.
//
// The module owns the DM-86 to DM-89 tables (policy keys, keysets, policy heads, agent events) through
// three platform packages, because their consumers run outside an Operation: the signer
// (internal/platform/agentpolicy/signer) is the only code that opens the policy key (ADR-0007, P8),
// the rotation job (internal/platform/agentpolicy/rotation) runs on the worker, and the event ingest
// (internal/platform/agentingest) runs on the fleet listener and stamps identity from the client
// certificate (S1). Compose will wire them like the connection checks once the production tenant DEK
// source exists (T-0598); the page knowledge/development/architecture/modules/agentfleet.md lists them.
//
// It contributes two Actions (actions.go): edit the addc password and event policy, and rotate the
// policy key ahead of schedule. Their permissions are in the tenant-owner role and the owner-role
// database guard (migration 0082).
package agentfleet

import (
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy/signer"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// ModuleID is the module's ID, its OpenAPI tag, its web module ID and the audit component.
const ModuleID module.ID = "agentfleet"

// Module is the agentfleet module.
type Module struct{ signer *signer.Signer }

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir directory.Services) *Module {
	_ = dir
	return &Module{signer: deps.AgentPolicy}
}

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: an agent fleet needs no directory capability to exist.
func (*Module) Requires() []capability.ID { return nil }

// Register implements module.Module: the policy edit and the key rotation. The signer may be an
// unconfigured one until compose wires the tenant DEK source; the Actions then refuse every run.
func (m *Module) Register(r *module.Registrar) error {
	sg := m.signer
	if sg == nil {
		sg = &signer.Signer{}
	}
	for _, build := range []func(PolicySigner) (operation.Action, error){PolicyEdit, KeyRotate} {
		a, err := build(sg)
		if err != nil {
			return err
		}
		if err := r.Action(a); err != nil {
			return err
		}
	}
	return nil
}
