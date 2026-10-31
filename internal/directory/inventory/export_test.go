package inventory

// SetClosureBudget lowers the closure row budget for a test and returns the function that restores it.
// Tests that use it must not run in parallel with other closure tests.
func SetClosureBudget(root, conn int) (restore func()) {
	old := closureBudget
	closureBudget = budget{root: root, conn: conn}
	return func() { closureBudget = old }
}

// ClosureBudget reports the budget in force.
func ClosureBudget() (root, conn int) { return closureBudget.root, closureBudget.conn }
