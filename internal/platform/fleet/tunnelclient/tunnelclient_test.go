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
	if err := serveConn(context.Background(), nil, Config{}); err == nil {
		t.Fatal("served without an opener")
	}
}
