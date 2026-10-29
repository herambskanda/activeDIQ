package fleetsql

import (
	"context"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// InsertCAForTest inserts one more active CA row, so a test can stage a retired CA beside an active one.
func InsertCAForTest(ctx context.Context, tx store.Tx, ks KeySource, tid tenant.ID) error {
	_, err := createCA(ctx, tx, ks, tid, time.Now())
	return err
}
