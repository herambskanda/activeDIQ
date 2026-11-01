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
