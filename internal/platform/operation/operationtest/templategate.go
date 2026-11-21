package operationtest

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// FakeTemplateGate is the documented stand-in for PlanContext.Templates in a hand-built PlanContext
// (ADR-0015 D1). The Runner never uses it: it binds the real gate to the operation's chain. A nil
// Permit allows every Template; otherwise only the Templates it lists are allowed and any other is
// refused with the same *operation.PlanRefusal "template_not_permitted" the Runner's gate returns.
type FakeTemplateGate struct {
	Permit map[string]bool
	Calls  []string // the Templates asked about, in order
}

func (g *FakeTemplateGate) CheckTemplate(_ context.Context, _ authz.Permission, template string) error {
	g.Calls = append(g.Calls, template)
	if g.Permit == nil || g.Permit[template] {
		return nil
	}
	return &operation.PlanRefusal{Code: "template_not_permitted"}
}

var _ operation.TemplateGate = (*FakeTemplateGate)(nil)
