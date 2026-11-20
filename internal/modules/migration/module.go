// Package migration is the server module of the ManageEngine importer's intake (spec e2-11 §6.1, §7;
// T-2060): the migration project, the quarantined import job, the size gate that runs before any byte of a
// source is read, and the per-tenant and per-user quotas. No format parser lives here.
//
// Creating a project and submitting a job are Actions (migration.project.create, migration.job.submit),
// so permission, tenant isolation and the audit event come from the operation kernel: a caller without
// migration.import is refused and the refusal is audited. A source over its size limit is recorded as a
// `rejected` job naming the limit hit; nothing about it was read.
package migration

import (
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// ModuleID is the module's ID, its OpenAPI tag and its web module ID.
const ModuleID module.ID = "migration"

// Module is the migration module.
type Module struct{}

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir directory.Services) *Module {
	_, _ = deps, dir
	return &Module{}
}

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: importers need no directory access (spec §9).
func (*Module) Requires() []capability.ID { return nil }

// Register implements module.Module.
func (*Module) Register(r *module.Registrar) error {
	if err := r.Permission(PermImport); err != nil {
		return err
	}
	for _, build := range []func() (operation.Action, error){CreateProject, SubmitJob, func() (operation.Action, error) { return RecordFidelity(nil) }} {
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
