package inventory

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// MaxLinks bounds the correlations of one object. An object has at most one live peer per
// connection of the other kind, so a larger answer means something is wrong.
const MaxLinks = 1000

// MaxDesignationRefs bounds the objects of one DesignationsFor call (a touched set).
const MaxDesignationRefs = 5000

// CorrelationSource is the DM-20 read port. directory/client builds CorrelationStatements from it.
type CorrelationSource interface {
	// CorrelationsFor returns every correlation of ref, from either side, in every state except
	// removed: candidate, matched and broken are all returned, none filtered by state (C16/E5 count
	// every state, TM §6.4). The result is empty only if the store holds none. A read error is an
	// error, never an empty result. Ordered by peer connection, peer object and ID.
	CorrelationsFor(ctx context.Context, tid tenant.ID, ref Ref) ([]Link, error)
}

// Designations is the DM-16.I8 read port.
type Designations interface {
	// DesignationsFor returns the designated GUIDs of the connection that matter to refs: each ref
	// that is designated, and each designated group any ref is a member of (contract §8.3 F2). The
	// result is sorted and duplicate-free; refs must be objects of the connection. It never returns
	// another tenant's or connection's designation.
	DesignationsFor(ctx context.Context, tid tenant.ID, connection ConnectionID, refs []GUID) ([]GUID, error)
}

// GroupSource names the groups an object belongs to, transitively (nested groups included, circular
// groups terminate). It is the membership slice of the inventory (DM-17), which lands with sync;
// DesignationsFor requires one so that a designated group can never be silently left out.
type GroupSource interface {
	GroupsOf(ctx context.Context, tid tenant.ID, connection ConnectionID, member GUID) ([]GUID, error)
}
