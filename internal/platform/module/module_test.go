package module_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// action is a test double. It also proves that operation.Action can be implemented in full.
type action struct{ id operation.ActionID }

func (a action) ID() operation.ActionID       { return a.id }
func (a action) Permission() authz.Permission { return "test.permission" }
func (a action) Schema() operation.SchemaRef  { return "#/components/schemas/Test" }
func (action) Plan(context.Context, operation.Input) (operation.Plan, error) {
	return operation.Plan{}, nil
}
func (action) Apply(context.Context, operation.Plan) (operation.Outcome, error) {
	return operation.Outcome{}, nil
}
func (action) Verify(context.Context, operation.Outcome) error { return nil }
func (action) Inverse(operation.Outcome) (operation.Input, operation.Reversibility) {
	return operation.Input{}, operation.Reversibility{}
}

type registrar map[operation.ActionID]operation.Action

func (r registrar) Action(a operation.Action) error {
	if _, dup := r[a.ID()]; dup {
		return fmt.Errorf("duplicate action %q", a.ID())
	}
	r[a.ID()] = a
	return nil
}

type fake struct{}

func (fake) ID() module.ID             { return "fake" }
func (fake) Requires() []capability.ID { return []capability.ID{capability.DirectoryAD} }
func (fake) Register(r module.Registrar) error {
	return r.Action(action{id: "fake.thing.do"})
}

// TestContract compiles the contract against a fake module and checks the one rule the
// interface states in prose: registering the same ID twice must be reportable by a Registrar.
func TestContract(t *testing.T) {
	var m module.Module = fake{}
	r := registrar{}
	if err := m.Register(r); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := m.Register(r); err == nil {
		t.Fatal("second Register of the same Action ID must fail")
	}
	if len(r) != 1 {
		t.Fatalf("registered %d actions, want 1", len(r))
	}
}
