// Package tunnelclient is the component side of the reverse tunnel, shared by cmd/agent and
// cmd/connector: it dials the pinned server over fleet/dial's mTLS, opens the tunnel stream through
// Config.Open and serves a fleet.Binding on the component's Mux until the context ends, reconnecting
// with capped, jittered backoff. A component has no listener; this outbound stream is its only
// network use. The package is contract-agnostic: it speaks fleet.Frame, and the wire binding
// (activediq.fleet.v1) is supplied from outside the platform root by internal/compose/tunnelbind.
package tunnelclient

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
)

// Opener opens one tunnel stream on conn. The stream ends when ctx is done.
type Opener func(ctx context.Context, conn grpc.ClientConnInterface) (fleet.Transport, error)

// Config is what Run serves.
type Config struct {
	State    *dial.State
	Identity fleet.Identity
	Binding  fleet.Binding
	Log      *slog.Logger
	// Open opens the tunnel stream on a dialled connection as a fleet.Transport. Required: it is where
	// the wire contract binds (compose/tunnelbind.Open).
	Open Opener
	// OnConnect, when set, receives the client side of each established tunnel (calls component → server)
	// and returns the function to run when that tunnel ends. nil means the component makes no calls.
	OnConnect func(c grpc.ClientConnInterface) (onClose func())
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

// errKind reduces a tunnel error to a fixed token. It is the only thing about the error that is
// logged (and, in the agent, written to the event log): the error text can carry addresses and
// certificate details and is never emitted. gRPC flattens the transport's typed errors into a status
// message, so the TLS and name-resolution classes are told apart by the standard library's and
// gRPC's stable message prefixes; an unrecognised message falls into "unreachable"/"transport".
func errKind(err error) string {
	var pe *fleet.ProtocolError
	switch {
	case err == nil:
		return "closed"
	case errors.As(err, &pe):
		return "protocol"
	}
	st, ok := status.FromError(err)
	if !ok {
		return "transport"
	}
	switch st.Code() {
	case codes.Unauthenticated, codes.PermissionDenied:
		return "rejected"
	case codes.Unavailable, codes.DeadlineExceeded:
		m := st.Message()
		switch {
		case strings.Contains(m, "x509:"):
			return "tls_trust"
		case strings.Contains(m, "tls:") || strings.Contains(m, "authentication handshake failed"):
			return "tls_handshake"
		case strings.Contains(m, "no such host") || strings.Contains(m, "server misbehaving"):
			return "resolve"
		}
		return "unreachable"
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
	if c.Open == nil {
		return errors.New("tunnelclient: no stream opener")
	}
	stream, err := c.Open(ctx, conn)
	if err != nil {
		return err
	}
	m, err := fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleComponent, Identity: c.Identity, Binding: c.Binding, Transport: stream})
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
