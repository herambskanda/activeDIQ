package moduletest

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// Action returns a complete, do-nothing Store Action with the given ID, for tests that register
// Actions. It proves operation.Action can be implemented in full.
func Action(id operation.ActionID) operation.Action { return action{id: id} }

type action struct{ id operation.ActionID }

func (a action) Describe() operation.Descriptor {
	return operation.Descriptor{ID: a.id, Version: 1, Permission: "test.permission",
		Input: "#/components/schemas/Test", Target: operation.TargetStore,
		Reversibility: operation.Reversible, AuditKind: "test.changed"}
}
func (action) Plan(context.Context, operation.PlanContext, operation.Input) ([]operation.StepPlan, error) {
	return nil, nil
}
func (action) Apply(context.Context, step.Step, operation.StepPlan) (operation.Outcome, error) {
	return operation.Outcome{}, nil
}
func (action) Verify(context.Context, step.Step, operation.StepPlan, operation.Outcome) (operation.Verdict, error) {
	return operation.Verdict{OK: true}, nil
}
func (action) Inverse(operation.StepPlan, operation.Outcome) (operation.Input, error) {
	return nil, operation.ErrIrreversible
}
