package connector

import (
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ErrMount is returned for an incomplete mount; it carries no certificate or directory text.
var ErrMount = errors.New("connector: mount needs a verify handler")

// TunnelBinding is the connector's side of the "connector" contract (TB6, TM-TB6-T10): the server
// opens every Connector method over the tunnel the connector dialled out, and this binding serves
// them. rights.Register mounts the VerifyConnection group on the per-tunnel registrar, which is never
// a process grpc.Server; the connector opens no listener. The peer is authenticated by the tunnel's
// pinned-server mTLS (fleet/dial), and the registrar refuses any method outside the contract.
// Its contract is built from the same descriptor as compose/server.FleetBindings. A nil handler
// refuses construction.
func TunnelBinding(h *rights.VerifyHandler) (fleet.Binding, error) {
	if h == nil {
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
	return fleet.Binding{Contract: c, Serve: func(_ fleet.Identity, reg grpc.ServiceRegistrar) {
		rights.Register(reg, h)
	}}, nil
}
