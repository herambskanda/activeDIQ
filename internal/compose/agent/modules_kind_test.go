package agent

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
)

// The generated module list switches on each agent module's own Kind constant, because an agent module
// may not import platform/fleet. This holds each one equal to the fleet kind it stands for: the fleet
// kind must resolve to a module, and an unknown kind to none.
func TestAgentModuleKindsMatchFleetKinds(t *testing.T) {
	if m, ok := buildModule(fleet.KindADDC, "dc"); !ok || m == nil {
		t.Fatalf("fleet.KindADDC has no agent module; the addc module's Kind constant has drifted from it")
	}
	if _, ok := buildModule("no-such-kind", "dc"); ok {
		t.Fatal("an unknown kind resolved to a module")
	}
}
