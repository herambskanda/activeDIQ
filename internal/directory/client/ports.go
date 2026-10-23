package client

import (
	"context"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Consumer-side ports of the Tier0Context builder (T-0109). They are declared here, empty, so the
// builder's inputs have a home before their providers exist; each provider ticket adds the methods
// it supplies: CorrelationSource from inventory (T-0167), HybridLinks from DM-21 (T-0168),
// Designations and OverrideSource from the override store (T-0100). Nothing in this package calls
// them.
type (
	// CorrelationSource answers DM-20 correlation questions about touched objects.
	CorrelationSource interface{}
	// Designations answers the customer's Tier-0 designations (DM-24).
	Designations interface{}
	// OverrideSource answers the Tier0Override in force for a connection's credential (DM-25).
	OverrideSource interface{}
	// HybridLinks is the registry's read port over DM-21, reused unchanged.
	HybridLinks = connection.HybridLinks
)

// Stage is the point of the write at which a Tier0Context is built.
type Stage string

// Stages. The context is built again at Apply: Apply does not trust that Plan passed.
const (
	StagePlan  Stage = "plan"
	StageApply Stage = "apply"
)

// Tier0Builder builds the per-request Tier0Context that every Plan and Apply carries (connector
// contract §8.3 F1). The skeleton declares the hook; T-0109 implements it. A builder error or a nil
// context refuses the write.
type Tier0Builder interface {
	Build(ctx context.Context, st Stage, op WriteOp) (*connectorv1.Tier0Context, error)
}

// Transport is the connector's write group as the client sees it. The gRPC transport ticket
// implements it; the generated write client is referenced there and nowhere else.
type Transport interface {
	Plan(ctx context.Context, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error)
	Apply(ctx context.Context, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error)
}

// FactsReader reads, live on the pinned DCs, what a FactsQuery asks about one target. It is the read
// half of the write path and the implementation of operation.LiveFacts.
type FactsReader interface {
	Facts(ctx context.Context, pins authority.Pins, q authority.FactsQuery) (authority.Facts, error)
}
