package read

import (
	"context"

	"google.golang.org/grpc"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Server is the remote transport of the read group: a connectorv1.ConnectorServer whose Read, ScopedSearch and Describe are the
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

// ScopedSearch implements connectorv1.ConnectorServer.
func (s *Server) ScopedSearch(req *connectorv1.ScopedSearchRequest, st grpc.ServerStreamingServer[connectorv1.ScopedSearchResponse]) error {
	return s.h.ScopedSearch(st.Context(), req, st)
}

// Describe implements connectorv1.ConnectorServer: the topology half (naming contexts, limits).
func (s *Server) Describe(ctx context.Context, req *connectorv1.DescribeRequest) (*connectorv1.DescribeResponse, error) {
	return s.h.Describe(ctx, req)
}

// Register mounts the read group on a gRPC server.
func Register(s grpc.ServiceRegistrar, h *Handler) {
	connectorv1.RegisterConnectorServer(s, NewServer(h))
}
