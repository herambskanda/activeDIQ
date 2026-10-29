package rights

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// VerifyHandler is the AD VerifyConnection RPC (contract §8.4) over StreamAD. Every error it returns
// is a gRPC status with a ConnectorError detail: a code and a fixed message, never the wrapped error
// text (a directory diagnostic can carry a DN, DM-24.I3). Build it with NewVerifyHandler; the zero
// value refuses every call.
type VerifyHandler struct {
	dir       ADDirectory
	epoch     *EpochState
	identity  dn.ObjectRef
	directory *v1.DirectoryIdentity
	now       func() time.Time
	gate      *write.GateBook
	onLRF     func(connectionID string)
	log       *slog.Logger
}

// VerifyConfig is what NewVerifyHandler needs.
type VerifyConfig struct {
	Dir      ADDirectory
	Epoch    *EpochState
	Identity dn.ObjectRef
	// Directory is the forest the connector is bound to; streamed in `completed` (contract v1.3).
	Directory *v1.DirectoryIdentity
	Now       func() time.Time
	// Gate receives GateBook.Complete for every stream that ends with `completed` (contract §8.2).
	Gate *write.GateBook
	// OnLocalRecordFailed is mandatory: it closes the prior epoch's write gate when the stream ends
	// with LOCAL_RECORD_FAILED (contract §8.3a). Wire it to Gate.CloseLocalRecordFailed. A handler
	// that feeds Complete without it would leave the gate open after a failed durable record.
	OnLocalRecordFailed func(connectionID string)
	// Log receives one line per failed run carrying ad.CodeOf only; nil means slog.Default.
	Log *slog.Logger
}

// ErrVerifyConfig is returned by NewVerifyHandler for an incomplete configuration; it carries no
// directory text.
var ErrVerifyConfig = errors.New("rights: verify handler needs a directory, gate, epoch and local-record-failed hook")

// NewVerifyHandler fails closed: a nil OnLocalRecordFailed, Gate, Dir, Epoch or Directory refuses
// construction, so no GateBook.Complete feed exists without the hook.
func NewVerifyHandler(c VerifyConfig) (*VerifyHandler, error) {
	if c.OnLocalRecordFailed == nil || c.Gate == nil || c.Dir == nil || c.Epoch == nil || c.Directory == nil {
		return nil, ErrVerifyConfig
	}
	return &VerifyHandler{dir: c.Dir, epoch: c.Epoch, identity: c.Identity, directory: c.Directory,
		now: c.Now, gate: c.Gate, onLRF: c.OnLocalRecordFailed, log: c.Log}, nil
}

// VerifyConnection runs the verification and streams its events.
func (h *VerifyHandler) VerifyConnection(ctx context.Context, req *v1.VerifyConnectionRequest, st grpc.ServerStreamingServer[v1.VerifyConnectionResponse]) error {
	if h == nil || h.gate == nil || h.onLRF == nil || h.dir == nil {
		return write.NewRefusal(v1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE, v1.RetryAdvice_RETRY_ADVICE_NEVER, "verify handler not configured")
	}
	connID := req.GetConnection().GetConnectionId()
	if connID == "" {
		return write.NewRefusal(v1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, v1.RetryAdvice_RETRY_ADVICE_NEVER, "invalid request")
	}
	sendFailed := false
	feed := newRunFeed(req)
	send := func(r *v1.VerifyConnectionResponse) error {
		err := st.Send(r)
		sendFailed = err != nil
		if err == nil {
			if run, ok := feed.observe(r); ok {
				h.gate.Complete(connID, run)
			}
		}
		return err
	}
	err := StreamAD(ctx, h.dir, h.epoch, req, h.identity, h.directory, send, h.now)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrLocalRecordFailed) {
		h.onLRF(connID)
	}
	h.logFailure(ctx, err)
	return verifyStatusError(ctx, err, sendFailed)
}

// logFailure logs the stable ad.Code of err and nothing else: the error text of a directory failure
// can carry a DN (errNoIdentity wraps the LDAP cause, DM-24.I3), so neither err nor its Error() is
// ever passed to the logger.
func (h *VerifyHandler) logFailure(ctx context.Context, err error) {
	l := h.log
	if l == nil {
		l = slog.Default()
	}
	l.LogAttrs(ctx, slog.LevelWarn, "connector: verify connection failed",
		slog.String("ad_code", string(ad.CodeOf(err))),
		slog.Bool("local_record_failed", errors.Is(err, ErrLocalRecordFailed)))
}

// runFeed collects the parts of a stream the write gate stands on.
type runFeed struct {
	inputs   []write.Mark
	blocking [][]byte
	set      map[string][]write.Basis
	vid      []byte
}

func newRunFeed(req *v1.VerifyConnectionRequest) *runFeed {
	f := &runFeed{set: map[string][]write.Basis{}, vid: req.GetVerificationId().GetValue()}
	for _, g := range req.GetDesignatedTier0() {
		if v, err := ParseGUID(g); err == nil {
			f.inputs = append(f.inputs, write.Mark{Object: v, Basis: tier0.Designated, Source: "run"})
		}
	}
	for _, m := range req.GetCorrelatedTier0() {
		if v, err := ParseGUID(m.GetObject()); err == nil {
			f.inputs = append(f.inputs, write.Mark{Object: v, Basis: tier0.C16, Source: "run"})
		}
	}
	return f
}

// observe records a sent event and returns the Run once `completed` was sent.
func (f *runFeed) observe(r *v1.VerifyConnectionResponse) (write.Run, bool) {
	switch e := r.GetEvent().(type) {
	case *v1.VerifyConnectionResponse_Findings:
		for _, fi := range e.Findings.GetFindings() {
			if fi.GetCheck() == v1.VerificationCheck_VERIFICATION_CHECK_V7_OVER_PRIVILEGE &&
				fi.GetSeverity() == v1.FindingSeverity_FINDING_SEVERITY_BLOCK {
				f.blocking = append(f.blocking, fi.GetFingerprint())
			}
		}
	case *v1.VerifyConnectionResponse_Tier0Set:
		for _, m := range e.Tier0Set.GetMembers() {
			if g, err := ParseGUID(m.GetObject()); err == nil {
				f.set[g.String()] = append([]write.Basis(nil), m.GetBasis()...)
			}
		}
	case *v1.VerifyConnectionResponse_Completed:
		c := e.Completed
		checks := map[v1.VerificationCheck]v1.CheckOutcome{}
		for _, cr := range c.GetChecks() {
			checks[cr.GetCheck()] = cr.GetOutcome()
		}
		return write.Run{VerificationID: f.vid, CompletedAt: c.GetCompletedAt().AsTime(), Verdict: c.GetVerdict(),
			Checks: checks, Blocking: f.blocking, Set: f.set, Inputs: f.inputs}, true
	}
	return write.Run{}, false
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
