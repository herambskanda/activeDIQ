// Package platform is the kernel root (ADR-0003 rule 1). It declares Deps, the fixed struct of
// kernel services every server module constructor receives, and it is imported only by server
// modules and internal/compose/server.
package platform

import (
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Deps is the set of kernel services handed to every server module: operation, audit, authz, jobs,
// report, notify, keys, blob, telemetry and so on (ADR-0003 rule 4).
//
// It grows one field per kernel service, never per module: a field's type must be declared in a
// kernel package listed in the blueprint catalogue (§5.1), and never in an interface declared in this
// package for one module's benefit.
type Deps struct {
	// Access writes roles and assignments under the no-escalation rule (DM-36.I1). Nil until the
	// composition root wires it; the module that uses it then refuses every write.
	Access *rbac.Grants
	// Report is the EP-8 host: the registered report datasets and the resolver that turns a
	// definition plus run parameters into the one Query a run executes. compose/server fills it
	// with the datasets directory packages export and the ones modules register, then seals it.
	// Nil until wired; Host methods on a nil host find no dataset.
	Report *report.Host
	// DB is the store. Nil until wired; a module that needs it then registers nothing for the feature.
	DB *store.DB
	// Audit is the audit sink (the chainer) a module appends its own events to. Nil until wired.
	Audit audit.Sink
	// Authz is the shared authorizer the operation runner uses. Nil until wired.
	Authz operation.Authorizer
	// StepUp answers whether a console session is inside the step-up window (TM §7.4). Nil refuses.
	StepUp *authn.StepUp
	// Attestation configures the TM-D17 takeover attestation. Zero when the install has not set an app
	// registration: the module then mounts no attestation route.
	Attestation Attestation
}

// Attestation is the install's TM-D17 attestation configuration: the Entra app registration that carries
// the delegated permission, and the canonical public origin its redirect URI is built on.
type Attestation struct {
	ClientID string // empty: attestation is not configured
	Origin   string // canonical https origin, no trailing slash (config.ParsePublicURL)
}
