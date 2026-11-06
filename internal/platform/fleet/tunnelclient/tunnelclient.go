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
	"sync"
	"time"

	"google.golang.org/grpc"

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
	// Burst, when set, is called before each connection attempt; the function it returns is called
	// when the attempt has failed or opened the tunnel stream. The component's resource limits may be
	// lifted for exactly that window: dial + TLS handshake + stream open is a short bounded burst that
	// a steady-state CPU cap stretches from about a second to half a minute (T-1249). nil = no limits.
	Burst func() (done func())
	// SetupTimeout bounds one connection set-up: the TLS handshake and the stream open. It is ours, not
	// gRPC's default connect timeout, so the Burst window cannot depend on a peer that accepts TCP and
	// then stalls (T-1249 security review). Zero means DefaultSetupTimeout.
	SetupTimeout time.Duration
}

// DefaultSetupTimeout is how long one connection set-up may take before it is abandoned and retried
// with backoff. An uncapped set-up measured 1.3 s on a lab DC.
const DefaultSetupTimeout = 15 * time.Second

var errSetupTimeout = errors.New("tunnelclient: connection set-up timed out")

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
	end := func() {}
	if c.Burst != nil {
		if done := c.Burst(); done != nil {
			end = sync.OnceFunc(done)
		}
	}
	defer end()
	for _, ep := range c.State.Endpoints {
		conn, err := dial.DialOut(endpointAddr(ep), c.State)
		if err != nil {
			lastErr = err
			continue
		}
		err = serveConn(ctx, conn, c, end)
		_ = conn.Close()
		return err
	}
	if lastErr == nil {
		lastErr = errors.New("tunnelclient: no endpoints")
	}
	return lastErr
}

// serveConn opens the stream and serves it; opened is called as soon as the stream open has returned.
func serveConn(ctx context.Context, conn *grpc.ClientConn, c Config, opened func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if c.Open == nil {
		return errors.New("tunnelclient: no stream opener")
	}
	setup := c.SetupTimeout
	if setup <= 0 {
		setup = DefaultSetupTimeout
	}
	// The stream context lives as long as the tunnel, so the set-up deadline is a timer that cancels it
	// only until the open has returned.
	timer := time.AfterFunc(setup, cancel)
	stream, err := c.Open(ctx, conn)
	inTime := timer.Stop()
	opened()
	if !inTime {
		return errSetupTimeout
	}
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
