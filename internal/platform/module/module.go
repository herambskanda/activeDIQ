// Package module is the server module extension point (blueprint §4.1, EP-1). A module is the
// only way a feature enters the server: it declares what it requires and contributes everything
// through the Registrar. Modules never import each other (blueprint §2 rule 4).
//
// The skeleton carries the contract with the Action registration method. Registrar methods for the
// other contribution kinds (API, Job, Permission, ScopeEvaluator, AuditKind, Dataset, Sink,
// AuthMethod, ApprovalGate) are added by the ticket that builds the extension point they hook
// into (EP-2 to EP-10), so the interface never names a type that does not exist yet.
package module

import (
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// ID is a module's stable identifier. It is also its OpenAPI tag and its web module ID.
type ID string

// Module is a server feature module.
type Module interface {
	ID() ID
	// Requires lists the capabilities that must be enabled for the module to load.
	Requires() []capability.ID
	// Register contributes the module's parts. It is called once at boot, and it is the only way
	// to contribute anything.
	Register(r Registrar) error
}

// Registrar is append-only and closed after boot. A duplicate ID fails start-up.
type Registrar interface {
	// Action registers an Action (EP-3). A duplicate ActionID is an error.
	Action(a operation.Action) error
}
