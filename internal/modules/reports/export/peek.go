package export

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Peek loads an export without any gate. It is for the schedule fire job, which made the export for the
// schedule's owner and reads its state and size to decide the delivery, and for the delivery renderer, which
// reads the file the Delivery row names. It is never reachable from a request.
func Peek(ctx context.Context, tx store.Tx, id ID) (Export, error) {
	return load(ctx, tx, id, false)
}
