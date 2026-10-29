package client

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Errors of the tunnel connector source. None carries an identifier or a peer message.
var (
	ErrNoConnectorTunnels = errors.New("client: no connector tunnel source wired")
	ErrNoEndpoint         = errors.New("client: connection has no reachable connector endpoint")
)

// BindingSource reads a connection's routing bindings (DM-13) under a tenant. *connection.Registry
// satisfies it.
type BindingSource interface {
	Bindings(ctx context.Context, tid tenant.ID, id connection.ID) ([]connection.Binding, error)
}

// Tunnels gives the client connection of an enrolled component. *gateway.Hub satisfies it. The
// component dialled the server over mutual TLS and the fleet gateway verified its certificate against
// the tenant's CAs and its current serial; this package never dials and has no credentials option, so
// there is no way to reach a connector without that mutual-TLS tunnel.
type Tunnels interface {
	Conn(tid tenant.ID, componentID string) grpc.ClientConnInterface
}

// TunnelSource is the ConnectorSource that resolves a connection to its connector's tunnel. The
// connection is resolved under the tenant of ctx (authority.WithTenant) before any binding is read,
// so a connection of another tenant, a retired one or an unknown one is refused and no tunnel is
// opened. Only an active component binding is used, lowest priority first; an embedded binding has
// no in-process connector endpoint yet and is not an endpoint.
type TunnelSource struct {
	conns    ConnectionSource
	bindings BindingSource
	tunnels  Tunnels
}

var _ ConnectorSource = (*TunnelSource)(nil)

// NewTunnelSource returns the source. Every argument is required.
func NewTunnelSource(conns ConnectionSource, bindings BindingSource, tunnels Tunnels) (*TunnelSource, error) {
	switch {
	case conns == nil:
		return nil, errors.New("client: tunnel source needs a connection source")
	case bindings == nil:
		return nil, errors.New("client: tunnel source needs a binding source")
	case tunnels == nil:
		return nil, ErrNoConnectorTunnels
	}
	return &TunnelSource{conns: conns, bindings: bindings, tunnels: tunnels}, nil
}

// Connector implements ConnectorSource.
func (s *TunnelSource) Connector(ctx context.Context, connectionID string) (connectorv1.ConnectorClient, error) {
	tid, err := tenantref.TenantFromContext(ctx)
	if err != nil {
		return nil, ErrReadTenant
	}
	id, err := connection.ParseID(connectionID)
	if err != nil {
		return nil, ErrReadConnection
	}
	conn, err := s.conns.Get(ctx, tid, id)
	if err != nil || conn.ID != id || conn.RetiredAt != nil {
		return nil, ErrReadConnection
	}
	bs, err := s.bindings.Bindings(ctx, tid, id)
	if err != nil {
		return nil, ErrNoEndpoint
	}
	for _, b := range bs { // routing order: priority, then id
		if b.ConnectionID == id && b.State == "active" && b.Target == connection.TargetComponent && b.ComponentID != "" {
			return connectorv1.NewConnectorClient(s.tunnels.Conn(tid, b.ComponentID)), nil
		}
	}
	return nil, ErrNoEndpoint
}
