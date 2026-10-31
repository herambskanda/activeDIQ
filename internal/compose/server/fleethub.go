package server

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/fleet/gateway"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// The one fleet Hub of the process (T-1119). A component's tunnel is attached to the Hub by ServeTunnel
// when the component dials in, and the server reaches that component through the same Hub when it reads
// the directory (client.TunnelSource). The two sides must hold the same *gateway.Hub: a Hub the tunnel
// is not attached to has no component, so every directory read answers UNAVAILABLE. Run therefore
// makes the Hub once and hands it to both the connector source and buildTunnelDeps.

// ErrNoFleetHub is returned when the tunnel dependencies are built without the shared Hub.
var ErrNoFleetHub = errors.New("server: fleet tunnel needs the shared hub")

// buildTunnelDeps assembles what Fleet.Tunnel needs around the shared hub: the connector contract
// binding, a reporter that audits a protocol violation against the component in its own tenant (the
// chainer is the audit sink), and the process logger. A missing piece fails startup here, not the
// first time a component connects. The fleet listener (T-0717) registers NewFleetService over these
// deps; nothing else in the process may attach a tunnel to a different Hub.
func buildTunnelDeps(hub *gateway.Hub, db *store.DB, sink audit.Sink) (TunnelDeps, error) {
	switch {
	case hub == nil:
		return TunnelDeps{}, ErrNoFleetHub
	case db == nil || sink == nil:
		return TunnelDeps{}, errors.New("server: fleet tunnel reporter needs the store and the audit sink")
	}
	b, err := FleetBindings()
	if err != nil {
		return TunnelDeps{}, fmt.Errorf("server: fleet bindings: %w", err)
	}
	return TunnelDeps{Hub: hub, Bindings: b, Reporter: &fleetsql.TunnelReporter{DB: db, Audit: sink}, Logger: slog.Default()}, nil
}
