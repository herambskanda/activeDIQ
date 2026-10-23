package fleet

import (
	"context"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Hub knows the current tunnel of each connected component, so server-side callers reach a component
// by identity without holding a stream. It never moves a call between tunnels: a call belongs to the
// Mux it was opened on, and when that tunnel ends the call has failed with an unknown outcome
// (TM-D24 B6). A new tunnel of the same component displaces the old one.
type Hub struct {
	mu  sync.Mutex
	cur map[hubKey]*Mux
}

type hubKey struct {
	tenant    tenant.ID
	component string
}

// NewHub returns an empty Hub.
func NewHub() *Hub { return &Hub{cur: map[hubKey]*Mux{}} }

func keyOf(id Identity) hubKey { return hubKey{id.Tenant, id.ComponentID} }

// Attach makes m the component's tunnel, closing the one it displaces, and returns the function that
// detaches m when its Run has returned. Calls pending on the displaced tunnel have already failed
// UNAVAILABLE by the time Attach returns.
func (h *Hub) Attach(m *Mux) (detach func()) {
	k := keyOf(m.Identity())
	h.mu.Lock()
	old := h.cur[k]
	h.cur[k] = m
	h.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return func() {
		h.mu.Lock()
		if h.cur[k] == m {
			delete(h.cur, k)
		}
		h.mu.Unlock()
	}
}

// Conn returns a client connection for the component. Each call resolves the component's tunnel as
// it starts and stays on it. A component with no tunnel gives UNAVAILABLE.
func (h *Hub) Conn(tid tenant.ID, componentID string) grpc.ClientConnInterface {
	return hubConn{h, hubKey{tid, componentID}}
}

type hubConn struct {
	h *Hub
	k hubKey
}

func (c hubConn) mux() *Mux {
	c.h.mu.Lock()
	defer c.h.mu.Unlock()
	return c.h.cur[c.k]
}

func (c hubConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	m := c.mux()
	if m == nil {
		return fixedErr(codes.Unavailable)
	}
	return m.Conn().Invoke(ctx, method, args, reply, opts...)
}

func (c hubConn) NewStream(ctx context.Context, d *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	m := c.mux()
	if m == nil {
		return nil, fixedErr(codes.Unavailable)
	}
	return m.Conn().NewStream(ctx, d, method, opts...)
}
