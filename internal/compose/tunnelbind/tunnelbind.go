// Package tunnelbind binds the platform's contract-agnostic tunnel client to the activediq.fleet.v1
// wire: the TunnelFrame <-> fleet.Frame conversion, the generated bidi stream and the Fleet.Tunnel
// call. The platform root never imports internal/proto/activediq/…, so this one package, shared by
// compose/agent and compose/connector, carries the client side of that binding (blueprint §2.2 rule 1;
// the server side is compose/server/fleettunnel.go).
package tunnelbind

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

// Open opens Fleet.Tunnel on conn and returns the stream as a fleet.Transport. It is the value of
// tunnelclient.Config.Open for every component.
func Open(ctx context.Context, conn grpc.ClientConnInterface) (fleet.Transport, error) {
	st, err := fleetv1.NewFleetClient(conn).Tunnel(ctx)
	if err != nil {
		return nil, err
	}
	return transport{st}, nil
}

// transport adapts the Fleet.Tunnel client stream to fleet.Transport.
type transport struct {
	st grpc.BidiStreamingClient[fleetv1.TunnelFrame, fleetv1.TunnelFrame]
}

func (t transport) Recv() (fleet.Frame, error) {
	f, err := t.st.Recv()
	if err != nil {
		return fleet.Frame{}, err
	}
	return frameFromProto(f), nil
}

func (t transport) Send(f fleet.Frame) error {
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
