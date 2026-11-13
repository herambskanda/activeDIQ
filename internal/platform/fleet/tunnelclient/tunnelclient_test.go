package tunnelclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
)

func TestEndpointAddr(t *testing.T) {
	if got := endpointAddr(dial.Endpoint{Host: "fleet.example", Port: 8443}); got != "fleet.example:8443" {
		t.Fatal(got)
	}
	if got := endpointAddr(dial.Endpoint{Host: "::1", Port: 1}); got != "[::1]:1" {
		t.Fatal(got)
	}
}

// A Config without an opener fails closed: nothing is dialled-and-served without a wire binding.
func TestServeConnRequiresOpener(t *testing.T) {
	if err := serveConn(context.Background(), nil, Config{}, func() {}); err == nil {
		t.Fatal("served without an opener")
	}
}

// T-1249: the resource-limit burst window is opened for a connection attempt and closed exactly once
// when it fails, so a failed dial can never leave the process uncapped.
func TestBurstClosedOnceWhenDialFails(t *testing.T) {
	opened, closed := 0, 0
	c := Config{State: &dial.State{}, Burst: func() func() { opened++; return func() { closed++ } }}
	if err := serveOnce(context.Background(), c); err == nil {
		t.Fatal("served without endpoints")
	}
	if opened != 1 || closed != 1 {
		t.Fatalf("burst opened %d closed %d, want 1 and 1", opened, closed)
	}
}

// T-1249 security review: a peer that accepts the connection and then stalls (a tarpit, a dropped
// handshake) must not hold the set-up, and with it the Burst window, open past our own deadline.
func TestSetupTimeoutEndsAStalledStreamOpen(t *testing.T) {
	opened := 0
	stall := func(ctx context.Context, _ grpc.ClientConnInterface) (fleet.Transport, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	c := Config{Open: stall, SetupTimeout: 50 * time.Millisecond}
	start := time.Now()
	err := serveConn(context.Background(), nil, c, func() { opened++ })
	if !errors.Is(err, errSetupTimeout) {
		t.Fatalf("stalled open returned %v, want the set-up timeout", err)
	}
	if opened != 1 {
		t.Fatalf("the Burst window end ran %d times, want 1", opened)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("set-up deadline took %s", d)
	}
}

func TestSetupTimeoutDefaultIsBounded(t *testing.T) {
	if DefaultSetupTimeout <= 0 || DefaultSetupTimeout > 30*time.Second {
		t.Fatalf("DefaultSetupTimeout %s is not a short bounded value", DefaultSetupTimeout)
	}
}
