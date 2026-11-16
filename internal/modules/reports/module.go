package reports

import (
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
)

// ModuleID is the module's ID, its OpenAPI tag and its web module ID.
const ModuleID module.ID = "reports"

// Module is the reports module. It builds the run and export services, the library and the API handlers
// from the kernel ports in platform.Deps and contributes them through the Registrar (ADR-0013): the
// routes (EP-2), the permissions (EP-6) and the job kinds (EP-5), the retention sweep among them.
type Module struct {
	deps platform.Deps
	dir  directory.Services
}

// New builds the module. Every module constructor receives the same two values (ADR-0003 rule 4).
func New(deps platform.Deps, dir directory.Services) *Module {
	return &Module{deps: deps, dir: dir}
}

// ID implements module.Module.
func (*Module) ID() module.ID { return ModuleID }

// Requires implements module.Module: reports read the collected store of either directory kind.
func (*Module) Requires() []capability.ID { return nil }

// Register implements module.Module. A module with no store in its Deps registers only its
// permissions: it does not hand the host a route it cannot serve.
func (m *Module) Register(r *module.Registrar) error {
	for _, p := range []authz.Permission{RunPermission, ExportPermission, SchedulePermission, ScheduleManageAllPermission, DeliverExternalPermission} {
		if err := r.Permission(p); err != nil {
			return err
		}
	}
	w, err := m.build()
	if err != nil || w == nil {
		return err
	}
	return w.register(r, m)
}
