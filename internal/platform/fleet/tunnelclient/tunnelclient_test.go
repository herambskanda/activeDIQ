package tunnelclient

import (
	"context"
	"testing"

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
