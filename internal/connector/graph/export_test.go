package graph

import (
	"context"

	"github.com/skenzeriq/activediq/internal/directory/odata"
)

// ReadForTest exposes the generic read seam to the external tests, which have no public read
// that takes a key string.
func ReadForTest(ctx context.Context, c *Client, req odata.Request) error {
	var out map[string]any
	return c.read(ctx, req, &out)
}
