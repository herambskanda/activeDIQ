// Package tunnelclient is the component side of the reverse tunnel, shared by cmd/agent and
// cmd/connector: it dials the pinned server over fleet/dial's mTLS, opens Fleet.Tunnel and serves a
// fleet.Binding on the component's Mux until the context ends, reconnecting with capped, jittered
// backoff. A component has no listener; this outbound stream is its only network use.
package tunnelclient

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"google.golang.org/grpc"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

// Config is what Run serves.
type Config struct {
	State    *dial.State
	Identity fleet.Identity
	Binding  fleet.Binding
	Log      *slog.Logger
	// OnConnect, when set, receives the client side of each established tunnel (calls component → server)
	// and returns the function to run when that tunnel ends. nil means the component makes no calls.
	OnConnect func(c grpc.ClientConnInterface) (onClose func())
}

// Transport adapts the Fleet.Tunnel client stream to fleet.Transport.
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

// Run serves the binding until ctx is done. It returns only then.
func Run(ctx context.Context, c Config) {
	log := c.Log
	if log == nil {
		log = slog.Default()
	}
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := serveOnce(ctx, c)
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

func endpointAddr(e dial.Endpoint) string { return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))) }

func serveOnce(ctx context.Context, c Config) error {
	var lastErr error
	for _, ep := range c.State.Endpoints {
		conn, err := dial.DialOut(endpointAddr(ep), c.State)
		if err != nil {
			lastErr = err
			continue
		}
		err = serveConn(ctx, conn, c)
		_ = conn.Close()
		return err
	}
	if lastErr == nil {
		lastErr = errors.New("tunnelclient: no endpoints")
	}
	return lastErr
}

func serveConn(ctx context.Context, conn *grpc.ClientConn, c Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := fleetv1.NewFleetClient(conn).Tunnel(ctx)
	if err != nil {
		return err
	}
	m, err := fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleComponent, Identity: c.Identity, Binding: c.Binding, Transport: transport{stream}})
	if err != nil {
		return err
	}
	defer m.Close()
	if c.OnConnect != nil {
		if onClose := c.OnConnect(m.Conn()); onClose != nil {
			defer onClose()
		}
	}
	return m.Run(ctx)
}
