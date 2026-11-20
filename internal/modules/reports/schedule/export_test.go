package schedule

import (
	"context"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Deliver runs the recipient evaluation of the fire (no run or export is made): the test hands it the fire's
// exports.
func (f *Fire) Deliver(ctx context.Context, tx store.Tx, tid tenant.ID, scheduleID, fireID string, exports map[string]string) error {
	s, err := f.Store.Get(ctx, tx, scheduleID, false)
	if err != nil {
		return err
	}
	fr, err := loadFire(ctx, tx, fireID)
	if err != nil {
		return err
	}
	fr.Exports = exports
	return f.deliver(ctx, tx, tid, s, fr, run.Run{})
}
