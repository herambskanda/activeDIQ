package operation

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/platform/authority"
)

// GateID names a registered approval gate.
type GateID string

// RouteKind is a gate's verdict.
type RouteKind string

// Route kinds.
const (
	RouteAllow RouteKind = "allow"
	RouteHold  RouteKind = "hold"
	RouteDeny  RouteKind = "deny"
)

// Route is what a gate returns for a plan.
type Route struct {
	Kind   RouteKind
	Ref    string // Hold: the Request reference
	Reason string // Deny: machine reason code
}

// PlanSummary is what a gate sees: the Action and the plan, never a secret.
type PlanSummary struct {
	Action       Descriptor
	Steps        []StepPlan
	PlanHash     string
	Irreversible bool
	// HoldReason is set when the kernel already holds the operation (rule 8). The gate then chooses
	// between a workflow Request and the kernel's single approval; it cannot allow it.
	HoldReason HoldReason
	Origin     string
	Requester  authority.Principal
}

// Gate is the approval gate (EP-4, rule 8).
type Gate interface {
	ID() GateID
	Route(ctx context.Context, p PlanSummary) (Route, error)
}

// PermissionOnly is the kernel default gate: Plan has already checked the permission, so it allows.
type PermissionOnly struct{}

// ID implements Gate.
func (PermissionOnly) ID() GateID { return "permission-only" }

// Route implements Gate.
func (PermissionOnly) Route(context.Context, PlanSummary) (Route, error) {
	return Route{Kind: RouteAllow}, nil
}

// errGate is returned when a gate errors or answers with something that is not allow, hold or deny.
// A gate fails closed: the operation is not run.
var errGate = errors.New("operation: gate did not allow")
