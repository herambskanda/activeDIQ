//go:build !lab

package server

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/client"
)

// T-0684 acceptance 3: a production build ignores a lab environment entirely. Nil db and registry
// prove nothing is opened or seeded.
func TestLabBootstrapIsInertInProductionBuilds(t *testing.T) {
	env := map[string]string{"WIN_LAB_DC_ADDR": "192.0.2.1", "WIN_LAB_SVC_PASSWORD": "x", "WIN_LAB_CA": "/nope", "LAB_LDAPS_PORT": "1", "LAB_SVC_PASSWORD": "y", "LAB_CA": "/nope"}
	var next client.ConnectorSource = &client.TunnelSource{}
	got, closeFn, err := labBootstrap(context.Background(), nil, nil, func(k string) string { return env[k] }, next)
	if err != nil || got != next {
		t.Fatalf("production labBootstrap = (%v, %v), want next unchanged and no error", got, err)
	}
	closeFn()
}
