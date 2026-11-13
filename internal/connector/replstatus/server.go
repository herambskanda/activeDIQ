package replstatus

import (
	"google.golang.org/grpc"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Server is the remote transport of ReadReplicationStatus. Like read.Server it leaves every other
// RPC Unimplemented; a connector binary routes each RPC to its group's handler.
type Server struct {
	connectorv1.UnimplementedConnectorServer
	h *Handler
}

// NewServer wraps a Handler.
func NewServer(h *Handler) *Server { return &Server{h: h} }

// ReadReplicationStatus implements connectorv1.ConnectorServer.
func (s *Server) ReadReplicationStatus(req *connectorv1.ReadReplicationStatusRequest, st grpc.ServerStreamingServer[connectorv1.ReadReplicationStatusResponse]) error {
	return s.h.ReadReplicationStatus(st.Context(), req, st)
}
