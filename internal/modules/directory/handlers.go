package directory

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/directory/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// DefaultLimit is how many users searchDirectoryUsers answers when limit is not given.
const DefaultLimit = 25

// tier0GroupFinding is the kind the connector's rights check gives a service account that is a
// member, directly or through nesting, of a Tier-0 group (Domain Admins and the rest of threat-model
// §6.4).
const tier0GroupFinding connection.FindingKind = "tier0_group_membership"

// Refusal reasons, shown in the problem detail. They are fixed text: no account, group or DN name.
const (
	reasonNoConnection = "no active directory connection is configured for this tenant"
	reasonTier0        = "the connection's service account is a member of a Tier-0 group; activeDIQ will not read the directory with it. Remove the account from the group and verify the connection again"
	reasonUnverified   = "the connection's service-account rights have not been verified (or the last check failed); verify the connection and try again"
	reasonUnavailable  = "the directory could not be reached"
)

// Connections is what the handler needs of the connection registry. *connection.Registry satisfies it.
type Connections interface {
	List(ctx context.Context, tid tenant.ID, includeDiscarded bool) ([]connection.Connection, error)
	Health(ctx context.Context, tid tenant.ID, id connection.ID, withFindings bool, now time.Time) (connection.Health, error)
}

// UserSearcher is the connector-backed user search. *client.UserSearch satisfies it.
type UserSearcher interface {
	Users(ctx context.Context, tid tenant.ID, id connection.ID, text string, limit int) (client.UserSearchResult, error)
}

// Handlers implements api.Handlers: searchDirectoryUsers. The tenant comes from the authenticated
// principal; the text of q reaches the directory only as a value inside a typed filter tree.
type Handlers struct {
	Connections Connections
	Search      UserSearcher
	Hybrid      Classifier
	Now         func() time.Time
	Log         *slog.Logger
}

var _ api.Handlers = Handlers{}

// Bind returns the tag's routes for apihost.Build.
func (h Handlers) Bind() apihost.TagHandlers { return api.Bind(h) }

func (h Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// SearchDirectoryUsers implements api.Handlers.
func (h Handlers) SearchDirectoryUsers(ctx context.Context, in api.SearchDirectoryUsersInput) (api.SearchDirectoryUsersOutput, error) {
	p, ok := apihost.PrincipalFrom(ctx)
	if !ok || p.ID == "" {
		return nil, apitypes.Forbidden("")
	}
	tid, err := tenantref.TenantFromText(p.Tenant)
	if err != nil {
		return nil, apitypes.Forbidden("")
	}
	limit := DefaultLimit
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	id, err := h.activeConnection(ctx, tid)
	if err != nil {
		return nil, err
	}
	res, err := h.Search.Users(ctx, tid, id, in.Q, limit)
	if err != nil {
		return nil, h.searchProblem(err)
	}
	items := make([]api.DirectoryUser, 0, len(res.Users))
	for _, u := range res.Users {
		g, err := apitypes.ParseUUID(u.ObjectGUID)
		if err != nil {
			h.log().Error("directory search: unparseable object guid", "error_class", "protocol")
			return nil, apitypes.Internal("")
		}
		items = append(items, api.DirectoryUser{ObjectGUID: g, DisplayName: u.DisplayName,
			SamAccountName: u.SAMAccountName, UserPrincipalName: u.UserPrincipalName, Enabled: u.Enabled,
			Hybrid: h.Hybrid.Classify(ctx, tid, id, u.ObjectGUID)})
	}
	return api.SearchDirectoryUsers200{Body: api.DirectoryUserList{Items: items}}, nil
}

// activeConnection returns the tenant's active AD connection, after the service-account gate: a
// connection whose newest rights check is not a clean pass, is stale, or reports membership of a
// Tier-0 group (or an acknowledged Tier-0 installation) is refused. It fails closed on anything
// it cannot decide.
func (h Handlers) activeConnection(ctx context.Context, tid tenant.ID) (connection.ID, error) {
	cs, err := h.Connections.List(ctx, tid, false)
	if err != nil {
		h.log().Error("directory search: connection list failed", "error_class", "store")
		return "", apitypes.Internal("")
	}
	for _, c := range cs {
		if c.Kind != connection.KindADForest || c.State != connection.StateActive || c.RetiredAt != nil {
			continue
		}
		hl, err := h.Connections.Health(ctx, tid, c.ID, true, h.now())
		if err != nil {
			h.log().Error("directory search: health read failed", "error_class", "store")
			return "", apitypes.Internal("")
		}
		if why := gate(hl); why != "" {
			h.log().Warn("directory search: refused by the service-account gate", "connection", string(c.ID))
			return "", apitypes.DirectoryUnavailable(why)
		}
		return c.ID, nil
	}
	return "", apitypes.DirectoryUnavailable(reasonNoConnection)
}

// gate returns the refusal reason for a connection's health, or "" when searching is allowed.
func gate(hl connection.Health) string {
	if hl.Tier0Installation {
		return reasonTier0
	}
	for _, f := range hl.Excessive {
		if f.Kind == tier0GroupFinding {
			return reasonTier0
		}
	}
	if hl.Verdict != connection.VerdictPass || hl.RightsStale || hl.RightsCheckedAt == nil {
		return reasonUnverified
	}
	return ""
}

// searchProblem maps a client or connector error to a problem. The error text is never sent.
func (h Handlers) searchProblem(err error) error {
	var rem *client.RemoteError
	switch {
	case errors.Is(err, client.ErrSearchTextInvalid):
		return apitypes.Validation("")
	case errors.Is(err, client.ErrSearchConnection), errors.Is(err, client.ErrNoEndpoint), errors.Is(err, client.ErrNoConnectorTunnels):
		return apitypes.DirectoryUnavailable(reasonUnavailable)
	case errors.As(err, &rem):
		h.log().Warn("directory search: connector refused", "connector_code", rem.Err.GetCode().String())
		return apitypes.DirectoryUnavailable(reasonUnavailable)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), grpcUnavailable(err):
		return apitypes.DirectoryUnavailable(reasonUnavailable)
	}
	h.log().Error("directory search failed", "error_class", "internal")
	return apitypes.Internal("")
}

func grpcUnavailable(err error) bool {
	st, ok := status.FromError(err)
	return ok && (st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded)
}
