package read

import (
	"google.golang.org/grpc"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Server is the remote transport of the read group: a connectorv1.ConnectorServer whose Read is the
// Handler's. The other RPCs stay Unimplemented; a connector binary combines the groups by routing
// each RPC to its handler (embedding two such servers would be ambiguous).
type Server struct {
	connectorv1.UnimplementedConnectorServer
	h *Handler
}

// NewServer wraps a Handler.
func NewServer(h *Handler) *Server { return &Server{h: h} }

// Read implements connectorv1.ConnectorServer.
func (s *Server) Read(req *connectorv1.ReadRequest, st grpc.ServerStreamingServer[connectorv1.ReadResponse]) error {
	return s.h.Read(st.Context(), req, st)
}

// Register mounts the read group on a gRPC server.
func Register(s grpc.ServiceRegistrar, h *Handler) {
	connectorv1.RegisterConnectorServer(s, NewServer(h))
}
