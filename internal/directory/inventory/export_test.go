package inventory

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// SetClosureBudget lowers the closure row budget for a test and returns the function that restores it.
// Tests that use it must not run in parallel with other closure tests.
func SetClosureBudget(root, conn int) (restore func()) {
	old := closureBudget
	closureBudget = budget{root: root, conn: conn}
	return func() { closureBudget = old }
}

// ClosureBudget reports the budget in force.
func ClosureBudget() (root, conn int) { return closureBudget.root, closureBudget.conn }

// DecideClosure runs the expansion decision from scratch on the current links and reports the groups it
// would expand and the groups it would leave out (the oracle for "the stored outcome is a function of the graph").
func DecideClosure(ctx context.Context, tx store.Tx, connection ConnectionID) (admitted, over []string, err error) {
	universe, err := liveGroups(ctx, tx, connection)
	if err != nil {
		return nil, nil, err
	}
	edges, err := nestingEdges(ctx, tx, connection)
	if err != nil {
		return nil, nil, err
	}
	counts, err := memberCounts(ctx, tx, connection)
	if err != nil {
		return nil, nil, err
	}
	admitted, over = splitByBudget(universe.guids, universe.privileged, edges, counts, closureBudget)
	return admitted, over, nil
}

// LivePrivileged runs the SQL that classifies the live groups of a connection and returns the GUIDs it
// marks as well-known privileged (the input of the closure's privileged-first rule).
func LivePrivileged(ctx context.Context, tx store.Tx, connection ConnectionID) (map[string]bool, error) {
	u, err := liveGroups(ctx, tx, connection)
	if err != nil {
		return nil, err
	}
	return u.privileged, nil
}

// SetAncestryBudget lowers the OU-move rewrite budget (rows per moved container, rows per Populate call)
// for a test and returns the function that restores it. Not for parallel tests.
func SetAncestryBudget(move, cycle int) (restore func()) {
	old := ancestryBudget
	ancestryBudget = struct{ move, cycle int }{move, cycle}
	return func() { ancestryBudget = old }
}

// SetPSOAppliesBudget lowers the msDS-PSOAppliesTo caps (active edges per PSO, per connection) for a test.
func SetPSOAppliesBudget(perPSO, perConn int) (restore func()) {
	old := psoApplies
	psoApplies = struct{ perPSO, perConn int }{perPSO, perConn}
	return func() { psoApplies = old }
}

// PSOAppliesBudget reports the caps in force.
func PSOAppliesBudget() (perPSO, perConn int) { return psoApplies.perPSO, psoApplies.perConn }

// AncestryBudgetInForce reports the OU-move rewrite budget in force.
func AncestryBudgetInForce() (move, cycle int) { return ancestryBudget.move, ancestryBudget.cycle }
