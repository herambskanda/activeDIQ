package fleet

import "context"

// The tunnel multiplexer (T-0209, TM-D24). It is contract-agnostic and does not import the generated
// fleet stubs (blueprint §2 rule 1): the transport adapter in compose translates between
// fleetv1.TunnelFrame and Frame, so nothing here knows the wire encoding of the envelope.

// Role is which end of the tunnel a Mux is. The server opens odd call ids, the component even ones
// (TM-D24 B2). fleet/dial reuses the same Mux with RoleComponent, so the rules are written once.
type Role int

// Roles. The zero value is deliberately not a role.
const (
	RoleServer Role = iota + 1
	RoleComponent
)

func (r Role) valid() bool { return r == RoleServer || r == RoleComponent }

// parity is the low bit of the call ids the role opens.
func (r Role) parity() uint64 {
	if r == RoleServer {
		return 1
	}
	return 0
}

func (r Role) peer() Role {
	if r == RoleServer {
		return RoleComponent
	}
	return RoleServer
}

// Body says which member of the frame oneof is set. The zero value is "none", which is a protocol
// error on receipt.
type Body int

// Frame bodies.
const (
	BodyNone Body = iota
	BodyOpen
	BodyData
	BodyHalfClose
	BodyClose
	BodyCancel
	BodyCredit
)

// Frame is one tunnel frame. Which fields apply depends on Body.
type Frame struct {
	CallID    uint64
	Body      Body
	Method    string // BodyOpen
	TimeoutMS uint32 // BodyOpen
	Payload   []byte // BodyData
	Code      int32  // BodyClose, a google.rpc.Code number as the peer sent it
	Message   string // BodyClose; untrusted when it comes from a component
	Messages  uint32 // BodyCredit
}

// Transport carries frames over one tunnel stream. Send and Recv are each called from one goroutine.
// Recv returns an error when the stream ends, for whatever reason.
type Transport interface {
	Send(Frame) error
	Recv() (Frame, error)
}

// Violation is the reason a tunnel was closed for a protocol error. It is a fixed vocabulary: nothing
// the peer sent is copied into it (TM-D24 C2).
type Violation string

// Violations (TM-D24 B5, A4).
const (
	ViolationEmptyBody     Violation = "empty_body"
	ViolationCallZero      Violation = "call_id_0_not_credit"
	ViolationWrongParity   Violation = "open_wrong_parity"
	ViolationNonIncreasing Violation = "open_id_not_increasing"
	ViolationUnknownCall   Violation = "frame_on_unopened_call"
	ViolationForbidden     Violation = "frame_forbidden_for_role_or_state"
	ViolationBadMethod     Violation = "method_name_invalid"
	ViolationOversize      Violation = "frame_too_large"
)

// Reporter receives what the multiplexer must make visible outside the tunnel. The composition root
// implements it over the audit port (ADR-0005 rule 11).
type Reporter interface {
	// ProtocolError is called once, before Run returns, when the peer broke the protocol. The tunnel
	// is already being closed. A returned error is logged; it never reopens the tunnel.
	ProtocolError(ctx context.Context, id Identity, v Violation) error
}
