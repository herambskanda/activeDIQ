package rights

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// VerifyHandler is the AD VerifyConnection RPC (contract §8.4) over StreamAD. Every error it returns
// is a gRPC status with a ConnectorError detail: a code and a fixed message, never the wrapped error
// text (a directory diagnostic can carry a DN, DM-24.I3).
type VerifyHandler struct {
	Dir      ADDirectory
	Epoch    *EpochState
	Identity dn.ObjectRef
	Now      func() time.Time
	// OnLocalRecordFailed is called when the stream ends with LOCAL_RECORD_FAILED, so the caller can
	// close the write gate (contract §8.3a). May be nil.
	OnLocalRecordFailed func()
}

// VerifyConnection runs the verification and streams its events.
func (h *VerifyHandler) VerifyConnection(ctx context.Context, req *v1.VerifyConnectionRequest, st grpc.ServerStreamingServer[v1.VerifyConnectionResponse]) error {
	sendFailed := false
	send := func(r *v1.VerifyConnectionResponse) error {
		err := st.Send(r)
		sendFailed = err != nil
		return err
	}
	err := StreamAD(ctx, h.Dir, h.Epoch, req, h.Identity, send, h.Now)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrLocalRecordFailed) && h.OnLocalRecordFailed != nil {
		h.OnLocalRecordFailed()
	}
	return verifyStatusError(ctx, err, sendFailed)
}

// verifyStatusError maps a StreamAD failure to a status that carries no text from err.
func verifyStatusError(ctx context.Context, err error, sendFailed bool) error {
	switch {
	case IsInvalidArgument(err):
		return write.NewRefusal(v1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, v1.RetryAdvice_RETRY_ADVICE_NEVER, "invalid request")
	case errors.Is(err, ErrLocalRecordFailed):
		return write.NewRefusal(v1.ErrorCode_ERROR_CODE_LOCAL_RECORD_FAILED, v1.RetryAdvice_RETRY_ADVICE_NEVER, "a local record could not be made durable")
	case sendFailed:
		return status.Error(grpccodes.Unavailable, "stream closed")
	}
	if ce, ok := adConnectorError(err); ok {
		return write.NewRefusal(ce.Code, ce.Retry, ce.Message)
	}
	if ctx.Err() != nil {
		return status.FromContextError(ctx.Err()).Err()
	}
	return write.NewRefusal(v1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, v1.RetryAdvice_RETRY_ADVICE_NEVER, "directory verification failed")
}

// Server is the remote transport of the verify group; the other RPCs stay Unimplemented.
type Server struct {
	v1.UnimplementedConnectorServer
	h *VerifyHandler
}

// NewServer wraps a handler.
func NewServer(h *VerifyHandler) *Server { return &Server{h: h} }

// VerifyConnection implements v1.ConnectorServer.
func (s *Server) VerifyConnection(req *v1.VerifyConnectionRequest, st grpc.ServerStreamingServer[v1.VerifyConnectionResponse]) error {
	return s.h.VerifyConnection(st.Context(), req, st)
}

// Register mounts the verify group on a gRPC server.
func Register(s grpc.ServiceRegistrar, h *VerifyHandler) { v1.RegisterConnectorServer(s, NewServer(h)) }
