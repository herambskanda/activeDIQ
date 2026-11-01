package directory

import (
	"context"

	"github.com/skenzeriq/activediq/internal/modules/directory/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// SearchDirectory is in the contract (T-1094, ADR-0011) and mounted. Until the search module (T-1096)
// and the inventory index (T-1095) land it answers 501 not-implemented rather than a made-up body.
// T-1096 replaces this method; it must never echo in.Body.Q.
func (Handlers) SearchDirectory(context.Context, api.SearchDirectoryInput) (api.SearchDirectoryOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (T-1096)")
}
