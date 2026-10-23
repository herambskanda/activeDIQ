package fleet

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Defaults for the numeric limits of TM-D24 B7 and the frame size. The flow-control numbers of
// TM-TB6-T7 (credit accounting) are a separate ticket.
const (
	DefaultMaxCalls   = 256
	DefaultMaxPayload = 4 << 20
	outQueue          = 64
	callInbox         = 16
	maxTombstones     = 1024
)

// ErrTunnelConfig is returned by NewMux for an unusable configuration.
var ErrTunnelConfig = errors.New("fleet: tunnel is not configured")

// ErrReplaced ends a tunnel that a newer tunnel of the same component displaced.
var ErrReplaced = errors.New("fleet: tunnel replaced by a newer tunnel of the same component")

// ErrBackpressure ends a tunnel whose peer does not drain what we send it.
var ErrBackpressure = errors.New("fleet: peer does not drain the tunnel")

// ProtocolError ends a tunnel the peer misused (TM-D24 B5). It carries only the fixed violation.
type ProtocolError struct{ Violation Violation }

func (e *ProtocolError) Error() string { return "fleet: tunnel protocol error: " + string(e.Violation) }

// MuxConfig configures one tunnel's multiplexer.
type MuxConfig struct {
	Role       Role
	Identity   Identity
	Binding    Binding
	Transport  Transport
	Reporter   Reporter     // required on the server; the component side may leave it nil
	Logger     *slog.Logger // nil: slog.Default()
	MaxCalls   int          // concurrent open calls per direction; 0: DefaultMaxCalls
	MaxPayload int          // bytes per CallData; 0: DefaultMaxPayload
}

// Mux is the multiplexer of one tunnel instance. All call state lives here and dies with it
// (TM-D24 B1): a Mux is never reused for another stream.
type Mux struct {
	role       Role
	id         Identity
	bind       Binding
	tr         Transport
	rep        Reporter
	log        *slog.Logger
	maxCalls   int
	maxPayload int
	reg        *registrar

	out  chan Frame
	done chan struct{}
	wg   sync.WaitGroup // handler goroutines

	openMu sync.Mutex // allocation and enqueue of an open are one step, so ids hit the wire in order

	mu       sync.Mutex
	base     context.Context
	closed   bool
	err      error
	calls    map[uint64]*call
	doneQ    []uint64
	nextID   uint64
	peerHigh uint64
	liveSelf int
	livePeer int
}

// NewMux builds the multiplexer and the per-tunnel registrar (TM-D24 A3). It fails if the binding's
// Serve registers a method outside the contract.
func NewMux(cfg MuxConfig) (*Mux, error) {
	if !cfg.Role.valid() || cfg.Transport == nil || cfg.Binding.Contract.name == "" || (cfg.Role == RoleServer && cfg.Reporter == nil) {
		return nil, ErrTunnelConfig
	}
	m := &Mux{
		role: cfg.Role, id: cfg.Identity, bind: cfg.Binding, tr: cfg.Transport, rep: cfg.Reporter,
		log: cfg.Logger, maxCalls: cfg.MaxCalls, maxPayload: cfg.MaxPayload,
		out: make(chan Frame, outQueue), done: make(chan struct{}), calls: map[uint64]*call{},
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	if m.maxCalls <= 0 {
		m.maxCalls = DefaultMaxCalls
	}
	if m.maxPayload <= 0 {
		m.maxPayload = DefaultMaxPayload
	}
	m.nextID = 1
	if cfg.Role == RoleComponent {
		m.nextID = 2
	}
	m.reg = newRegistrar(cfg.Binding.Contract, cfg.Role.peer())
	if cfg.Binding.Serve != nil {
		cfg.Binding.Serve(cfg.Identity, m.reg)
	}
	if m.reg.err != nil {
		return nil, m.reg.err
	}
	return m, nil
}

// Identity is the authenticated component this tunnel belongs to.
func (m *Mux) Identity() Identity { return m.id }

// Done is closed when the tunnel has ended.
func (m *Mux) Done() <-chan struct{} { return m.done }

// Close ends the tunnel. Every pending call fails UNAVAILABLE with an unknown outcome.
func (m *Mux) Close() { m.fail(ErrReplaced) }

// Conn is the grpc.ClientConnInterface for calls this side opens, bound to this tunnel only.
func (m *Mux) Conn() grpc.ClientConnInterface { return conn{m} }

// Run reads the tunnel until it ends and returns why: nil for a clean end of the peer's stream, a
// *ProtocolError for a violation (already reported), or the transport's or context's error. When Run
// returns every call has ended and every handler goroutine has returned.
func (m *Mux) Run(ctx context.Context) error {
	m.mu.Lock()
	m.base = context.WithValue(ctx, ctxKey{}, m.id)
	m.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { m.fail(ctx.Err()) })
	defer stop()

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case f := <-m.out:
				if err := m.tr.Send(f); err != nil {
					m.fail(err)
					return
				}
			case <-m.done:
				return
			}
		}
	}()

	for {
		f, err := m.tr.Recv()
		if err != nil {
			m.fail(err)
			break
		}
		if v := m.handle(f); v != "" {
			m.violation(ctx, v)
			break
		}
	}
	<-writerDone
	m.wg.Wait()
	m.mu.Lock()
	err := m.err
	m.mu.Unlock()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (m *Mux) violation(ctx context.Context, v Violation) {
	m.fail(&ProtocolError{Violation: v})
	if m.rep == nil {
		return
	}
	// The tunnel is already closing; the audit call must not be cancelled with it.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := m.rep.ProtocolError(rctx, m.id, v); err != nil {
		m.log.Error("fleet: protocol error could not be reported", slog.String("component", m.id.ComponentID), slog.String("violation", string(v)))
	}
}

// fail ends the tunnel once. Every live call ends under the same lock that publishes the end, so a
// caller that sees Done also sees its call's final error (TM-D24 B6).
func (m *Mux) fail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	m.err = err
	close(m.done)
	for _, c := range m.calls {
		if c.retired {
			continue
		}
		if c.opener == m.role {
			m.finishLocked(c, &CallError{st: status.New(codes.Unavailable, "tunnel closed; outcome unknown"), unknown: true})
		} else {
			m.finishLocked(c, fixedErr(codes.Canceled))
		}
		m.retireLocked(c)
	}
}

// ---- sending ----

func (m *Mux) send(f Frame) error {
	select {
	case m.out <- f:
		return nil
	case <-m.done:
		return io.ErrClosedPipe
	}
}

// reply queues a frame from the read loop, which must never block on a slow peer.
func (m *Mux) reply(f Frame) {
	select {
	case m.out <- f:
	default:
		m.fail(ErrBackpressure)
	}
}

func (m *Mux) isSelfDone(c *call) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return c.selfDone || c.peerDone
}

func (m *Mux) sendData(c *call, b []byte) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if len(b) > m.maxPayload {
		return fixedErr(codes.ResourceExhausted)
	}
	m.mu.Lock()
	over := c.selfDone || c.peerDone
	m.mu.Unlock()
	if over || (c.opener == m.role && c.selfHlf) {
		if c.opener == m.role {
			return io.EOF
		}
		return fixedErr(codes.Canceled)
	}
	if err := m.send(Frame{CallID: c.id, Body: BodyData, Payload: b}); err != nil {
		return fixedErr(codes.Unavailable)
	}
	return nil
}

// ---- call lifecycle (all *Locked helpers hold m.mu) ----

func (m *Mux) finishLocked(c *call, err error) {
	if c.finOnce {
		return
	}
	c.finOnce = true
	c.finErr = err
	close(c.fin)
}

func (m *Mux) retireLocked(c *call) {
	if c.retired {
		return
	}
	c.retired = true
	if c.opener == m.role {
		m.liveSelf--
	} else {
		m.livePeer--
	}
	close(c.dead)
	c.cancel()
	m.doneQ = append(m.doneQ, c.id)
	for len(m.doneQ) > maxTombstones {
		delete(m.calls, m.doneQ[0])
		m.doneQ = m.doneQ[1:]
	}
}

func (m *Mux) newCall(id uint64, opener Role, method string, parent context.Context, timeout time.Duration) *call {
	var ctx context.Context
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, timeout)
	} else {
		ctx, cancel = context.WithCancel(parent)
	}
	return &call{
		id: id, opener: opener, method: method, ctx: ctx, cancel: cancel,
		in: make(chan []byte, callInbox), fin: make(chan struct{}), dead: make(chan struct{}),
	}
}

// cancelCall abandons a call this side opened. Nothing goes out after the cancel for that call.
func (m *Mux) cancelCall(c *call) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	m.mu.Lock()
	if c.selfDone || c.peerDone || c.retired {
		m.mu.Unlock()
		return
	}
	c.selfDone = true
	err := status.FromContextError(c.ctx.Err()).Err()
	if c.ctx.Err() == nil {
		err = fixedErr(codes.Canceled)
	}
	m.finishLocked(c, err)
	m.retireLocked(c)
	m.mu.Unlock()
	_ = m.send(Frame{CallID: c.id, Body: BodyCancel}) // best effort: a dead tunnel needs no cancel
}

func (m *Mux) abandon(c *call, _ error) { m.cancelCall(c) }

// closeCall ends a call the peer opened, with this side's final status. The text is fixed per code.
func (m *Mux) closeCall(c *call, code codes.Code) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	m.mu.Lock()
	if c.selfDone || c.peerDone || c.retired {
		m.mu.Unlock()
		return
	}
	c.selfDone = true
	m.retireLocked(c)
	m.mu.Unlock()
	_ = m.send(Frame{CallID: c.id, Body: BodyClose, Code: int32(code), Message: FixedText(code)})
}

// ---- receiving ----

// handle applies one peer frame. It returns the violation that must close the tunnel, or "".
func (m *Mux) handle(f Frame) Violation {
	if f.Body == BodyNone {
		return ViolationEmptyBody
	}
	if len(f.Payload) > m.maxPayload {
		return ViolationOversize
	}
	if f.CallID == 0 {
		if f.Body != BodyCredit {
			return ViolationCallZero
		}
		return ""
	}
	if f.Body == BodyOpen {
		return m.handleOpen(f)
	}

	m.mu.Lock()
	c := m.calls[f.CallID]
	if c == nil {
		m.mu.Unlock()
		return ViolationUnknownCall
	}
	if c.peerDone {
		m.mu.Unlock()
		return ViolationForbidden
	}
	if c.selfDone {
		m.mu.Unlock() // in flight after this side's cancel or close (TM-D24 B4)
		return ""
	}
	peerOpened := c.opener != m.role
	switch f.Body {
	case BodyCredit:
		m.mu.Unlock()
		return ""
	case BodyData:
		if peerOpened && c.peerHalf {
			m.mu.Unlock()
			return ViolationForbidden
		}
		m.mu.Unlock()
		select {
		case c.in <- f.Payload:
		case <-c.dead:
		case <-m.done:
		}
		return ""
	case BodyHalfClose:
		if !peerOpened || c.peerHalf {
			m.mu.Unlock()
			return ViolationForbidden
		}
		c.peerHalf = true
		m.finishLocked(c, io.EOF)
	case BodyCancel:
		if !peerOpened {
			m.mu.Unlock()
			return ViolationForbidden
		}
		c.peerDone = true
		m.finishLocked(c, fixedErr(codes.Canceled))
		m.retireLocked(c)
	case BodyClose:
		if peerOpened {
			m.mu.Unlock()
			return ViolationForbidden
		}
		c.peerDone = true
		m.finishLocked(c, m.closeError(c, f))
		m.retireLocked(c)
	default:
		m.mu.Unlock()
		return ViolationForbidden
	}
	m.mu.Unlock()
	return ""
}

// closeError turns the peer's CallClose into the call's final error (TM-D24 C). The code is
// normalised, the status text is fixed, and the peer's text is kept apart, sanitised.
func (m *Mux) closeError(c *call, f Frame) error {
	code := NormalizeCode(f.Code)
	var reported string
	if f.Message != "" {
		reported = SanitizeStatusText(f.Message)
	}
	if reported != "" && code != codes.OK {
		m.log.Info("fleet: component closed a call",
			slog.String("component", m.id.ComponentID),
			slog.String("method", c.method),
			slog.Int("code", int(code)),
			slog.String("component_reported", reported))
	}
	if code == codes.OK {
		return io.EOF
	}
	return &CallError{st: status.New(code, FixedText(code)), reported: reported, hasReported: f.Message != ""}
}

func (m *Mux) handleOpen(f Frame) Violation {
	peer := m.role.peer()
	if f.CallID&1 != peer.parity() {
		return ViolationWrongParity
	}
	m.mu.Lock()
	if f.CallID <= m.peerHigh {
		m.mu.Unlock()
		return ViolationNonIncreasing
	}
	if !validMethodName(f.Method) {
		m.mu.Unlock()
		return ViolationBadMethod
	}
	m.peerHigh = f.CallID

	var uh unaryHandler
	var sh streamHandler
	var isUnary, ok bool
	if m.bind.Contract.allows(peer, f.Method) {
		uh, isUnary = m.reg.unary[f.Method]
		sh, ok = m.reg.streams[f.Method]
		ok = ok || isUnary
	}
	refuse := func(code codes.Code) Violation {
		// The id is spent: remember it as ended by us so its in-flight frames are dropped.
		c := m.newCall(f.CallID, peer, "", context.Background(), 0)
		c.selfDone = true
		m.livePeer++ // retireLocked takes it off again
		m.calls[f.CallID] = c
		m.finishLocked(c, fixedErr(code))
		m.retireLocked(c)
		m.mu.Unlock()
		m.reply(Frame{CallID: f.CallID, Body: BodyClose, Code: int32(code), Message: FixedText(code)})
		return ""
	}
	if !ok {
		return refuse(codes.PermissionDenied) // one answer for unknown method, wrong direction and wrong contract (A4)
	}
	if m.livePeer >= m.maxCalls {
		return refuse(codes.ResourceExhausted)
	}
	var timeout time.Duration
	if f.TimeoutMS > 0 {
		timeout = time.Duration(f.TimeoutMS) * time.Millisecond
	}
	c := m.newCall(f.CallID, peer, f.Method, m.base, timeout)
	m.calls[f.CallID] = c
	m.livePeer++
	m.wg.Add(1)
	m.mu.Unlock()
	go m.serve(c, isUnary, uh, sh)
	return ""
}

// serve runs one component-opened call on the per-tunnel registrar's handler.
func (m *Mux) serve(c *call, isUnary bool, uh unaryHandler, sh streamHandler) {
	defer m.wg.Done()
	code := codes.OK
	func() {
		defer func() {
			if r := recover(); r != nil {
				m.log.Error("fleet: call handler panicked", slog.String("method", c.method), slog.String("component", m.id.ComponentID))
				code = codes.Internal
			}
		}()
		ss := &serverStream{m: m, c: c}
		var err error
		if isUnary {
			var resp any
			resp, err = uh.h(uh.srv, c.ctx, func(v any) error { return ss.RecvMsg(v) }, nil)
			if err == nil {
				err = ss.SendMsg(resp)
			}
		} else {
			err = sh.h(sh.srv, ss)
		}
		if err != nil {
			if st, ok := status.FromError(err); ok {
				code = st.Code()
			} else {
				code = status.FromContextError(err).Code() // Canceled, DeadlineExceeded, else Unknown
			}
			if code == codes.OK || int(code) > int(codes.Unauthenticated) {
				code = codes.Unknown
			}
		}
	}()
	m.closeCall(c, code)
}

// ---- client side ----

type conn struct{ m *Mux }

func (cn conn) NewStream(ctx context.Context, _ *grpc.StreamDesc, method string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	c, err := cn.m.open(ctx, method)
	if err != nil {
		return nil, err
	}
	return &clientStream{m: cn.m, c: c}, nil
}

func (cn conn) Invoke(ctx context.Context, method string, args, reply any, _ ...grpc.CallOption) error {
	c, err := cn.m.open(ctx, method)
	if err != nil {
		return err
	}
	cs := &clientStream{m: cn.m, c: c}
	defer cn.m.cancelCall(c) // a no-op once the call has ended
	if err := cs.SendMsg(args); err != nil {
		if errors.Is(err, io.EOF) {
			return cn.m.finalError(c)
		}
		return err
	}
	if err := cs.CloseSend(); err != nil {
		return err
	}
	if err := cs.RecvMsg(reply); err != nil {
		if errors.Is(err, io.EOF) {
			return fixedErr(codes.Internal) // closed OK without a response
		}
		return err
	}
	p, err := c.recv(c.ctx) // the end of the call: a second response is a contract violation
	switch {
	case err == nil:
		_ = p
		return fixedErr(codes.Internal)
	case errors.Is(err, io.EOF):
		return nil
	default:
		return err
	}
}

func (m *Mux) finalError(c *call) error {
	select {
	case <-c.fin:
		if errors.Is(c.finErr, io.EOF) {
			return fixedErr(codes.Internal)
		}
		return c.finErr
	default:
		return fixedErr(codes.Unavailable)
	}
}

// open starts a call this side opens. The method must be in this side's allow-set (TM-D24 A2).
func (m *Mux) open(ctx context.Context, method string) (*call, error) {
	if !validMethodName(method) || !m.bind.Contract.allows(m.role, method) {
		return nil, fixedErr(codes.PermissionDenied)
	}
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	var timeoutMS uint32
	var timeout time.Duration
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
		if timeout <= 0 {
			return nil, fixedErr(codes.DeadlineExceeded)
		}
		ms := (timeout + time.Millisecond - 1) / time.Millisecond
		timeoutMS = uint32(min(int64(ms), math.MaxUint32))
	}

	m.openMu.Lock()
	defer m.openMu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, fixedErr(codes.Unavailable)
	}
	if m.liveSelf >= m.maxCalls {
		m.mu.Unlock()
		return nil, fixedErr(codes.ResourceExhausted)
	}
	id := m.nextID
	m.nextID += 2
	c := m.newCall(id, m.role, method, ctx, 0)
	m.calls[id] = c
	m.liveSelf++
	m.mu.Unlock()

	if err := m.send(Frame{CallID: id, Body: BodyOpen, Method: method, TimeoutMS: timeoutMS}); err != nil {
		// The tunnel ended while queuing: fail() has already ended this call as outcome unknown.
		return nil, m.finalError(c)
	}
	context.AfterFunc(c.ctx, func() { m.cancelCall(c) })
	return c, nil
}
