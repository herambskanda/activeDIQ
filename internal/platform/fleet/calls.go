package fleet

import (
	"context"
	"errors"
	"io"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// CallError is the error of a call that did not succeed. Its status text is fixed per code (TM-D24
// C4); what a component said is kept apart and reachable only through ComponentReported.
type CallError struct {
	st          *status.Status
	reported    string
	hasReported bool
	unknown     bool
}

func (e *CallError) Error() string              { return e.st.Err().Error() }
func (e *CallError) GRPCStatus() *status.Status { return e.st }

// ComponentReported returns the component's own sanitised text (at most MaxStatusMessage bytes,
// escaped), for a typed component_reported field. It is untrusted and nothing may decide on it
// (TM-D24 C2). The caller labels it as reported by the component.
func ComponentReported(err error) (string, bool) {
	var ce *CallError
	if errors.As(err, &ce) && ce.hasReported {
		return ce.reported, true
	}
	return "", false
}

// OutcomeUnknown reports whether err is a call that failed because its tunnel ended after the open
// frame was queued: the component may or may not have acted (TM-D24 B6). The step's outcome is
// unknown, never success, and is reconciled as ADR-0005 directs.
func OutcomeUnknown(err error) bool {
	var ce *CallError
	return errors.As(err, &ce) && ce.unknown
}

func fixedErr(c codes.Code) *CallError { return &CallError{st: status.New(c, FixedText(c))} }

// call is one multiplexed call. mu-guarded fields belong to Mux.mu.
type call struct {
	id     uint64
	opener Role
	method string

	in  chan []byte   // inbound data, in order
	fin chan struct{} // closed once finErr is set: the inbound side is over
	// finErr is io.EOF for a clean end of the inbound side, otherwise the error to return.
	finErr  error
	dead    chan struct{} // closed when the call is retired, so a blocked push gives up
	ctx     context.Context
	cancel  context.CancelFunc
	sendMu  sync.Mutex // orders this call's own frames: nothing goes out after cancel or close
	selfHlf bool       // guarded by sendMu: this side sent half_close

	// Flow control, guarded by Mux.mu: credit we hold to send on this call, messages the peer sent
	// that we have not granted back, and the part of those the handler already consumed.
	sndCredit    int
	rcvHeld      int
	rcvConsumed  int
	tunPend      int  // peer messages of this call still counted against the tunnel window
	keepBuffered bool // retire without draining: buffered data must still reach the reader

	peerHalf bool // guarded by Mux.mu
	unary    bool // one message each way: a second data frame from the peer is a violation
	peerData int  // data frames accepted from the peer
	selfDone bool // this side cancelled or closed
	peerDone bool // the peer closed or cancelled
	retired  bool
	finOnce  bool
}

// recv returns the next inbound message, or the end of the inbound side. Buffered data is always
// delivered before the end, and the end before a context error, so a peer's real close status is not
// masked by the cancellation that follows a retired call.
func (m *Mux) recv(c *call, ctx context.Context) ([]byte, error) {
	for {
		select {
		case p := <-c.in:
			m.consumed(c)
			return p, nil
		default:
		}
		select {
		case <-c.fin:
			select {
			case p := <-c.in:
				m.consumed(c)
				return p, nil
			default:
			}
			return nil, c.finErr
		default:
		}
		select {
		case p := <-c.in:
			m.consumed(c)
			return p, nil
		case <-c.fin:
			continue
		case <-ctx.Done():
			select {
			case <-c.fin:
				continue
			default:
				return nil, status.FromContextError(ctx.Err()).Err()
			}
		}
	}
}

// clientStream is the grpc.ClientStream of a call this side opened.
type clientStream struct {
	m *Mux
	c *call
}

func (s *clientStream) Header() (metadata.MD, error) { return nil, nil }
func (s *clientStream) Trailer() metadata.MD         { return nil }
func (s *clientStream) Context() context.Context     { return s.c.ctx }

func (s *clientStream) CloseSend() error {
	c := s.c
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if c.selfHlf || s.m.isSelfDone(c) {
		return nil
	}
	c.selfHlf = true
	return s.m.send(Frame{CallID: c.id, Body: BodyHalfClose})
}

func (s *clientStream) SendMsg(msg any) error {
	pm, ok := msg.(proto.Message)
	if !ok {
		return fixedErr(codes.Internal)
	}
	b, err := proto.Marshal(pm)
	if err != nil {
		return fixedErr(codes.Internal)
	}
	return s.m.sendData(s.c, b)
}

func (s *clientStream) RecvMsg(msg any) error {
	pm, ok := msg.(proto.Message)
	if !ok {
		return fixedErr(codes.Internal)
	}
	p, err := s.m.recv(s.c, s.c.ctx)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		s.m.abandon(s.c, err)
		return err
	}
	if err := proto.Unmarshal(p, pm); err != nil {
		s.m.abandon(s.c, nil)
		return fixedErr(codes.Internal)
	}
	return nil
}

// serverStream is the grpc.ServerStream of a call the peer opened.
type serverStream struct {
	m *Mux
	c *call
}

func (s *serverStream) SetHeader(metadata.MD) error  { return nil }
func (s *serverStream) SendHeader(metadata.MD) error { return nil }
func (s *serverStream) SetTrailer(metadata.MD)       {}
func (s *serverStream) Context() context.Context     { return s.c.ctx }

func (s *serverStream) SendMsg(msg any) error {
	pm, ok := msg.(proto.Message)
	if !ok {
		return fixedErr(codes.Internal)
	}
	b, err := proto.Marshal(pm)
	if err != nil {
		return fixedErr(codes.Internal)
	}
	return s.m.sendData(s.c, b)
}

func (s *serverStream) RecvMsg(msg any) error {
	pm, ok := msg.(proto.Message)
	if !ok {
		return fixedErr(codes.Internal)
	}
	p, err := s.m.recv(s.c, s.c.ctx)
	if err != nil {
		return err
	}
	if err := proto.Unmarshal(p, pm); err != nil {
		return fixedErr(codes.InvalidArgument)
	}
	return nil
}
