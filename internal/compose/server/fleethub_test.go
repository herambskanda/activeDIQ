package server

import (
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/gateway"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// The tunnel deps sit on the hub they are given, so the connector source and the tunnel cannot end up
// on different hubs by construction (T-1119).
func TestBuildTunnelDepsUsesTheGivenHub(t *testing.T) {
	hub := gateway.NewHub()
	deps, err := buildTunnelDeps(hub, &store.DB{}, nopSink{})
	if err != nil {
		t.Fatal(err)
	}
	if deps.Hub != hub {
		t.Fatal("deps are not on the given hub")
	}
	if deps.Reporter == nil || deps.Logger == nil {
		t.Fatalf("deps incomplete: %+v", deps)
	}
	if _, ok := deps.Bindings[fleet.KindConnector]; !ok {
		t.Fatalf("bindings = %v, want the connector contract", deps.Bindings)
	}
}

func TestBuildTunnelDepsRefusesAMissingPiece(t *testing.T) {
	if _, err := buildTunnelDeps(nil, &store.DB{}, nopSink{}); !errors.Is(err, ErrNoFleetHub) {
		t.Fatalf("no hub: err = %v, want ErrNoFleetHub", err)
	}
	if _, err := buildTunnelDeps(gateway.NewHub(), nil, nopSink{}); err == nil {
		t.Fatal("no store: want an error")
	}
	if _, err := buildTunnelDeps(gateway.NewHub(), &store.DB{}, nil); err == nil {
		t.Fatal("no audit sink: want an error")
	}
}
