// Package operation is the operation pipeline kernel package (blueprint §5.1, §4.2): EP-3 (Action)
// and EP-4 (approval gate). The skeleton carries the Action interface only. The pipeline itself
// (Plan, Submit, Approve, Undo, operation state) arrives with T-0047, and the empty types below
// gain their fields there.
package operation

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// ActionID names an Action, for example "objects.user.create". It is stable and namespaced by
// the owning module.
type ActionID string

// SchemaRef points at the OpenAPI component that describes an Action's input. The API, workflow,
// automation and the command palette all share it (blueprint §4.2).
type SchemaRef string

// Input is the validated input of one Action invocation.
type Input struct{}

// Plan is the result of a dry run: live reads, the diff, reversibility and approvals needed.
type Plan struct{}

// Outcome is what Apply did, as read back from the directory or store.
type Outcome struct{}

// Reversibility says whether an Action can be undone and why not.
type Reversibility struct{}

// Action is the one shape for every write (blueprint §4.2, ENH-04). The same Action serves a
// single edit, a bulk CSV, a workflow step, an automation policy and the command palette. No
// directory write is reachable except from an Action's Apply.
type Action interface {
	ID() ActionID
	Permission() authz.Permission
	Schema() SchemaRef
	// Plan is the dry run. It performs no writes.
	Plan(ctx context.Context, in Input) (Plan, error)
	// Apply executes a Plan; it is idempotent per (operation, step).
	Apply(ctx context.Context, p Plan) (Outcome, error)
	// Verify reads the result back and fails if it does not match the Plan.
	Verify(ctx context.Context, o Outcome) error
	// Inverse returns the input that undoes o, or says why it cannot be undone.
	Inverse(o Outcome) (Input, Reversibility)
}
