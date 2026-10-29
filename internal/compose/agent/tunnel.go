package agent

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"

	kernel "github.com/skenzeriq/activediq/internal/platform/agent"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	addcv1 "github.com/skenzeriq/activediq/internal/proto/activediq/addc/v1"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

// addcContract is the one contract the DC agent speaks (agent-host-addc-contract §2): the server may
// call Host and Addc; the agent may call EventIngest. Nothing else is registered or callable.
func addcContract() (fleet.Contract, error) {
	host := agentv1.File_skenzeriq_agent_v1_agent_proto.Services().ByName("Host")
	ing := agentv1.File_skenzeriq_agent_v1_agent_proto.Services().ByName("EventIngest")
	addc := addcv1.File_activediq_addc_v1_addc_proto.Services().ByName("Addc")
	if host == nil || ing == nil || addc == nil {
		return fleet.Contract{}, fleet.ErrContract
	}
	return fleet.NewContract("addc", []protoreflect.ServiceDescriptor{host, addc}, []protoreflect.ServiceDescriptor{ing})
}

// clientTransport adapts the Fleet.Tunnel client stream to fleet.Transport.
type clientTransport struct {
	st grpc.BidiStreamingClient[fleetv1.TunnelFrame, fleetv1.TunnelFrame]
}

func (t clientTransport) Recv() (fleet.Frame, error) {
	f, err := t.st.Recv()
	if err != nil {
		return fleet.Frame{}, err
	}
	return frameFromProto(f), nil
}

func (t clientTransport) Send(f fleet.Frame) error {
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

// tunnelLoop dials the server and serves the contract until ctx is done, reconnecting with capped,
// jittered backoff. The agent has no listener; this outbound stream is its only network use.
func tunnelLoop(ctx context.Context, st *dial.State, h *kernel.Host, id fleet.Identity, c fleet.Contract, log *slog.Logger) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := serveOnce(ctx, st, h, id, c)
		if ctx.Err() != nil {
			return
		}
		log.Warn("tunnel ended", "err_kind", errKind(err))
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff + time.Duration(time.Now().UnixNano()%int64(backoff/2+1))):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func errKind(err error) string {
	var pe *fleet.ProtocolError
	switch {
	case err == nil:
		return "closed"
	case errors.As(err, &pe):
		return "protocol"
	}
	return "transport"
}

func serveOnce(ctx context.Context, st *dial.State, h *kernel.Host, id fleet.Identity, c fleet.Contract) error {
	var lastErr error
	for _, ep := range st.Endpoints {
		addr := endpointAddr(ep)
		conn, err := dial.DialOut(addr, st)
		if err != nil {
			lastErr = err
			continue
		}
		err = serveConn(ctx, conn, h, id, c)
		_ = conn.Close()
		return err
	}
	if lastErr == nil {
		lastErr = errors.New("agent: no endpoints")
	}
	return lastErr
}

func serveConn(ctx context.Context, conn *grpc.ClientConn, h *kernel.Host, id fleet.Identity, c fleet.Contract) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := fleetv1.NewFleetClient(conn).Tunnel(ctx)
	if err != nil {
		return err
	}
	m, err := fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleComponent, Identity: id,
		Binding: fleet.Binding{Contract: c, Register: func(_ fleet.Identity, reg grpc.ServiceRegistrar) { h.Register(reg) }}, Transport: clientTransport{stream}})
	if err != nil {
		return err
	}
	defer m.Close()
	h.SetEventClient(agentv1.NewEventIngestClient(m.Conn()))
	defer h.SetEventClient(nil)
	return m.Run(ctx)
}
