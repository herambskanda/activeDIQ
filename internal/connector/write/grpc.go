package write

import (
	"context"

	"google.golang.org/grpc"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Server is the remote transport: a connectorv1.ConnectorServer whose Plan and Apply are the
// Handler's. The other RPCs of the service stay Unimplemented here; a connector binary embeds this
// type in the server that implements the read group. Transport authentication (mutual TLS to the
// server) belongs to the gRPC server the connector builds; the Handler adds the connection and
// directory-identity binding of step 1 on top, for both transports.
type Server struct {
	connectorv1.UnimplementedConnectorServer
	h *Handler
}

// NewServer wraps a Handler.
func NewServer(h *Handler) *Server { return &Server{h: h} }

// Plan implements connectorv1.ConnectorServer.
func (s *Server) Plan(ctx context.Context, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	return s.h.Plan(ctx, req)
}

// Apply implements connectorv1.ConnectorServer.
func (s *Server) Apply(ctx context.Context, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	return s.h.Apply(ctx, req)
}

// Register mounts the write group on a gRPC server.
func Register(s grpc.ServiceRegistrar, h *Handler) {
	connectorv1.RegisterConnectorServer(s, NewServer(h))
}
