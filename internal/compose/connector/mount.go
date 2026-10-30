package connector

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ErrMount is returned for an incomplete mount; it carries no certificate or directory text.
var ErrMount = errors.New("connector: mount needs a verify handler, a read handler and a write handler")

// TunnelBinding is the connector's side of the "connector" contract (TB6, TM-TB6-T10): the server
// opens every Connector method over the tunnel the connector dialled out, and this binding serves
// the VerifyConnection, Read, ScopedSearch, Plan and Apply groups (the rest stay Unimplemented). It mounts one
// ConnectorServer on the per-tunnel registrar, which is never a process grpc.Server; the connector
// opens no listener. The peer is authenticated by the tunnel's pinned-server mTLS (fleet/dial), the
// registrar refuses any method outside the contract, and the tunnel belongs to one tenant: a
// binding asked to serve an identity that is not a connector of a tenant registers nothing, so
// every call to it is refused. The handlers themselves refuse a request whose directory identity is
// not the connector's own. Its contract is built from the same descriptor as
// compose/server.FleetBindings. A nil handler refuses construction.
func TunnelBinding(v *rights.VerifyHandler, r *read.Handler, w *write.Handler) (fleet.Binding, error) {
	if v == nil || r == nil || w == nil {
		return fleet.Binding{}, ErrMount
	}
	svc := connectorv1.File_activediq_connector_v1_connector_proto.Services().ByName("Connector")
	if svc == nil {
		return fleet.Binding{}, fleet.ErrContract
	}
	c, err := fleet.NewContract("connector", []protoreflect.ServiceDescriptor{svc}, nil)
	if err != nil {
		return fleet.Binding{}, err
	}
	srv := &tunnelServer{verify: rights.NewServer(v), read: read.NewServer(r), write: write.NewServer(w)}
	return fleet.Binding{Contract: c, Register: func(id fleet.Identity, reg grpc.ServiceRegistrar) {
		if id.Kind != fleet.KindConnector || id.Tenant.IsZero() || id.ComponentID == "" {
			return
		}
		connectorv1.RegisterConnectorServer(reg, srv)
	}}, nil
}

// tunnelServer routes each served RPC to its group's server (embedding the group servers would be
// ambiguous). It is the one composite ConnectorServer per tunnel registrar: each group's Register
// registers the whole Connector service, so registering two would collide. Everything else is Unimplemented.
type tunnelServer struct {
	connectorv1.UnimplementedConnectorServer
	verify *rights.Server
	read   *read.Server
	write  *write.Server
}

func (s *tunnelServer) VerifyConnection(req *connectorv1.VerifyConnectionRequest, st grpc.ServerStreamingServer[connectorv1.VerifyConnectionResponse]) error {
	return s.verify.VerifyConnection(req, st)
}

func (s *tunnelServer) Read(req *connectorv1.ReadRequest, st grpc.ServerStreamingServer[connectorv1.ReadResponse]) error {
	return s.read.Read(req, st)
}

func (s *tunnelServer) ScopedSearch(req *connectorv1.ScopedSearchRequest, st grpc.ServerStreamingServer[connectorv1.ScopedSearchResponse]) error {
	return s.read.ScopedSearch(req, st)
}

func (s *tunnelServer) Plan(ctx context.Context, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	return s.write.Plan(ctx, req)
}

func (s *tunnelServer) Apply(ctx context.Context, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	return s.write.Apply(ctx, req)
}
