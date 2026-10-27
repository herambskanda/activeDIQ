package server

import (
	"errors"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

// The Fleet.Tunnel adapter (T-0287). The platform multiplexer (T-0209) never imports the generated
// protos, so this file carries the translation between fleetv1.TunnelFrame and fleet.Frame, binds
// each component kind to its contract, and runs one Mux per accepted stream.

// TunnelDeps is what serving Fleet.Tunnel needs. Every field is required.
type TunnelDeps struct {
	Hub      *fleet.Hub
	Bindings fleet.Bindings
	Reporter fleet.Reporter // audits a protocol violation against the component (TM-D24 B5)
	Logger   *slog.Logger
}

// Fixed answers. They repeat nothing the component sent.
var (
	errTunnelUnavailable = status.Error(codes.Unavailable, "tunnel unavailable")
	errTunnelNoIdentity  = status.Error(codes.Unauthenticated, "no component identity")
	errTunnelNoContract  = status.Error(codes.PermissionDenied, "no tunnel for this component kind")
	errTunnelProtocol    = status.Error(codes.InvalidArgument, "tunnel protocol error")
)

// FleetBindings binds the connector kind to the connector contract: the server opens every Connector
// method and the component opens none. Other kinds have no contract yet, so they get no tunnel
// (Bindings.For fails closed).
func FleetBindings() (fleet.Bindings, error) {
	svc := connectorv1.File_activediq_connector_v1_connector_proto.Services().ByName("Connector")
	if svc == nil {
		return nil, fleet.ErrContract
	}
	c, err := fleet.NewContract("connector", []protoreflect.ServiceDescriptor{svc}, nil)
	if err != nil {
		return nil, err
	}
	return fleet.Bindings{fleet.KindConnector: {Contract: c}}, nil
}

// ServeTunnel runs a Mux over one accepted Tunnel stream until it ends. The Mux runs on the stream's
// own context, the one the gateway interceptor derived, so revoking the component (CloseComponent or
// the periodic re-check) fails the Mux, and the Hub then refuses calls to it.
func ServeTunnel(d TunnelDeps, st grpc.BidiStreamingServer[fleetv1.TunnelFrame, fleetv1.TunnelFrame]) error {
	if d.Hub == nil || d.Reporter == nil {
		return errTunnelUnavailable
	}
	ctx := st.Context()
	id, ok := fleet.IdentityFrom(ctx)
	if !ok {
		return errTunnelNoIdentity
	}
	bd, err := d.Bindings.For(id)
	if err != nil {
		return errTunnelNoContract
	}
	m, err := fleet.NewMux(fleet.MuxConfig{
		Role: fleet.RoleServer, Identity: id, Binding: bd, Transport: tunnelTransport{st},
		Reporter: d.Reporter, Logger: d.Logger,
	})
	if err != nil {
		return errTunnelUnavailable
	}
	detach := d.Hub.Attach(m)
	defer detach()
	defer m.Close()

	err = m.Run(ctx)
	var pe *fleet.ProtocolError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &pe):
		return errTunnelProtocol
	case ctx.Err() != nil:
		return status.FromContextError(ctx.Err()).Err()
	case errors.Is(err, fleet.ErrReplaced):
		return status.Error(codes.Aborted, "tunnel replaced")
	}
	return errTunnelUnavailable
}

// tunnelTransport adapts the generated stream to fleet.Transport.
type tunnelTransport struct {
	st grpc.BidiStreamingServer[fleetv1.TunnelFrame, fleetv1.TunnelFrame]
}

func (t tunnelTransport) Recv() (fleet.Frame, error) {
	f, err := t.st.Recv()
	if err != nil {
		return fleet.Frame{}, err
	}
	return frameFromProto(f), nil
}

func (t tunnelTransport) Send(f fleet.Frame) error {
	pf, ok := frameToProto(f)
	if !ok {
		return errors.New("fleet: frame has no body")
	}
	return t.st.Send(pf)
}

func frameFromProto(f *fleetv1.TunnelFrame) fleet.Frame {
	out := fleet.Frame{CallID: f.GetCallId()}
	switch b := f.GetBody().(type) {
	case *fleetv1.TunnelFrame_Open:
		out.Body, out.Method, out.TimeoutMS = fleet.BodyOpen, b.Open.GetMethod(), b.Open.GetTimeoutMs()
	case *fleetv1.TunnelFrame_Data:
		out.Body, out.Payload = fleet.BodyData, b.Data.GetPayload()
	case *fleetv1.TunnelFrame_HalfClose:
		out.Body = fleet.BodyHalfClose
	case *fleetv1.TunnelFrame_Close:
		out.Body, out.Code, out.Message = fleet.BodyClose, b.Close.GetStatusCode(), b.Close.GetStatusMessage()
	case *fleetv1.TunnelFrame_Cancel:
		out.Body = fleet.BodyCancel
	case *fleetv1.TunnelFrame_Credit:
		out.Body, out.Messages = fleet.BodyCredit, b.Credit.GetMessages()
	}
	return out
}

func frameToProto(f fleet.Frame) (*fleetv1.TunnelFrame, bool) {
	out := &fleetv1.TunnelFrame{CallId: f.CallID}
	switch f.Body {
	case fleet.BodyOpen:
		out.Body = &fleetv1.TunnelFrame_Open{Open: &fleetv1.CallOpen{Method: f.Method, TimeoutMs: f.TimeoutMS}}
	case fleet.BodyData:
		out.Body = &fleetv1.TunnelFrame_Data{Data: &fleetv1.CallData{Payload: f.Payload}}
	case fleet.BodyHalfClose:
		out.Body = &fleetv1.TunnelFrame_HalfClose{HalfClose: &fleetv1.CallHalfClose{}}
	case fleet.BodyClose:
		out.Body = &fleetv1.TunnelFrame_Close{Close: &fleetv1.CallClose{StatusCode: f.Code, StatusMessage: f.Message}}
	case fleet.BodyCancel:
		out.Body = &fleetv1.TunnelFrame_Cancel{Cancel: &fleetv1.CallCancel{}}
	case fleet.BodyCredit:
		out.Body = &fleetv1.TunnelFrame_Credit{Credit: &fleetv1.FlowCredit{Messages: f.Messages}}
	default:
		return nil, false
	}
	return out, true
}
