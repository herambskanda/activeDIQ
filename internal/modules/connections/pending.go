package connections

import (
	"context"

	"github.com/skenzeriq/activediq/internal/modules/connections/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// ReadPermission reads the health of the connections the caller's grant covers (listConnectionHealth, T-1834).
// No step-up: it is a read and its rows carry no secret.
const ReadPermission authz.Permission = "connections.read"

// ListConnectionHealth is in the contract (T-1834) and mounted. Until the backend ticket that reads connection
// and DC health lands, it answers 501 not-implemented rather than a made-up body. That ticket replaces this file.
func (h *AttestHandlers) ListConnectionHealth(context.Context, api.ListConnectionHealthInput) (api.ListConnectionHealthOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (connection health read)")
}

// GetConnectionSummary is in the contract (T-1842) and mounted. It answers 501 until the backend ticket that counts the
// tenant's connections lands (any signed-in administrator, no connections.read). That ticket deletes this method.
func (h *AttestHandlers) GetConnectionSummary(context.Context, api.GetConnectionSummaryInput) (api.GetConnectionSummaryOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (connection summary)")
}
