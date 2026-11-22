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

// ManagePermission creates a directory connection (createConnection, T-1920). It needs a fresh step-up: creating or
// changing a connection or its credential re-points A2 (TM section 7.4, policy.yaml stepUp).
const ManagePermission authz.Permission = "connections.manage"

// VerifyPermission starts the onboarding verification of a draft connection (verifyConnection, T-1920) and, later,
// reads its findings (spec FR-16). No step-up: the run writes nothing to the directory.
const VerifyPermission authz.Permission = "connections.verify"

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

// CreateConnection is in the contract (T-1920) and mounted. It answers 501 until the backend ticket that wires the
// directory/connection registry (create a draft, DM-10 L1) behind it lands. That ticket deletes this method.
func (h *AttestHandlers) CreateConnection(context.Context, api.CreateConnectionInput) (api.CreateConnectionOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (create a connection)")
}

// GetConnection is in the contract (T-1920) and mounted. It answers 501 until the backend ticket that reads a
// connection through the registry and the caller's connections.read grant lands. That ticket deletes this method.
func (h *AttestHandlers) GetConnection(context.Context, api.GetConnectionInput) (api.GetConnectionOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (read a connection)")
}

// VerifyConnection is in the contract (T-1920) and mounted. It answers 501 until the backend ticket that runs
// connection.Service.Verify (onboarding) and maps the run to check rows lands. That ticket deletes this method.
func (h *AttestHandlers) VerifyConnection(context.Context, api.VerifyConnectionInput) (api.VerifyConnectionOutput, error) {
	return nil, apitypes.NotImplemented("not available yet (verify a connection)")
}
