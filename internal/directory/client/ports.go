package client

import (
	"context"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Consumer-side ports of the Tier0Context builder (T-0109). Providers implement them structurally;
// this package imports only their value types.
type (
	// CorrelationSource answers DM-20 correlation questions about touched objects (T-0167).
	CorrelationSource = inventory.CorrelationSource
	// Designations answers the customer's Tier-0 designations (DM-16.I8).
	Designations = inventory.Designations
	// HybridLinks is the registry's read port over DM-21, reused unchanged.
	HybridLinks = connection.HybridLinks
)

// OverrideSource answers the Tier0Override in force for a connection's current credential (DM-25).
// The override store is the only authority for it (TM-R15): nothing the Action supplies is read.
type OverrideSource interface {
	Tier0OverrideInForce(ctx context.Context, tid tenant.ID, id connection.ID) (*connection.Tier0Override, error)
}

var _ OverrideSource = (*connection.Registry)(nil)
var _ RevisionSource = (*inventory.Reader)(nil)

// ConnectionSource reads a connection's kind and directory identity (DM-10).
type ConnectionSource interface {
	Get(ctx context.Context, tid tenant.ID, id connection.ID) (connection.Connection, error)
}

// RevisionSource supplies the server's tier0-set revision, echoed by the connector in audit and in
// errors. It changes whenever the designations or the tier0 facts of the inventory change.
type RevisionSource interface {
	Tier0Revision(ctx context.Context, tid tenant.ID) (uint64, error)
}

// LiveRefresher re-reads, live from the directories, the correlation facts of one object (DM-20.I5)
// and returns the time of the read. It is optional: without it a statement resting on facts older
// than the connector's limit is not sent (contract §8.3 F3).
type LiveRefresher interface {
	RefreshCorrelations(ctx context.Context, tid tenant.ID, ref inventory.Ref) (time.Time, error)
}

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
	Build(ctx context.Context, st Stage, op WriteOp) (Tier0, error)
}

// Tier0 is what the builder returns: the context, and the gate override in force for the
// connection (DM-25) when the server's override store has one. The override's authority is that
// store (TM-R15), never the Action's input, so WriteOp has no override field; with no
// OverrideSource wired the builder returns none and the request carries none.
type Tier0 struct {
	Context  *connectorv1.Tier0Context
	Override *connectorv1.WriteGateOverride
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
