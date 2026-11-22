package connector

import (
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/skenzeriq/activediq/internal/connector/service"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ErrMount is returned for an incomplete mount; it carries no certificate or directory text.
var ErrMount = errors.New("connector: mount needs a service")

// TunnelBinding is the connector's side of the "connector" contract (TB6, TM-TB6-T10): the server
// opens every Connector method over the tunnel the connector dialled out, and this binding serves
// the VerifyConnection, Read, ScopedSearch, ReadPerDC, Describe, ChangeFeed, Plan and Apply groups (the rest stay Unimplemented). It mounts one
// ConnectorServer on the per-tunnel registrar, which is never a process grpc.Server; the connector
// opens no listener. The peer is authenticated by the tunnel's pinned-server mTLS (fleet/dial), the
// registrar refuses any method outside the contract, and the tunnel belongs to one tenant: a
// binding asked to serve an identity that is not a connector of a tenant registers nothing, so
// every call to it is refused. The handlers themselves refuse a request whose directory identity is
// not the connector's own. Its contract is built from the same descriptor as
// compose/server.FleetBindings. A nil service refuses construction.
func TunnelBinding(svc *service.Service) (fleet.Binding, error) {
	if svc == nil {
		return fleet.Binding{}, ErrMount
	}
	desc := connectorv1.File_activediq_connector_v1_connector_proto.Services().ByName("Connector")
	if desc == nil {
		return fleet.Binding{}, fleet.ErrContract
	}
	c, err := fleet.NewContract("connector", []protoreflect.ServiceDescriptor{desc}, nil)
	if err != nil {
		return fleet.Binding{}, err
	}
	srv := svc.Server()
	return fleet.Binding{Contract: c, Register: func(id fleet.Identity, reg grpc.ServiceRegistrar) {
		if id.Kind != fleet.KindConnector || id.Tenant.IsZero() || id.ComponentID == "" {
			return
		}
		connectorv1.RegisterConnectorServer(reg, srv)
	}}, nil
}
