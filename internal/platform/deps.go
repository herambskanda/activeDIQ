// Package platform is the kernel root (ADR-0003 rule 1). It declares Deps, the fixed struct of
// kernel services every server module constructor receives, and it is imported only by server
// modules and internal/compose/server.
package platform

// Deps is the set of kernel services handed to every server module: operation, audit, authz, jobs,
// report, notify, keys, blob, telemetry and so on (ADR-0003 rule 4).
//
// It is empty until the kernel services exist. It grows one field per kernel service, never per
// module: a field's type must be declared in a kernel package listed in the blueprint catalogue
// (§5.1), and never in an interface declared in this package for one module's benefit.
type Deps struct{}
