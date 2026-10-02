package server

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
)

// TestBootGeneratedList boots the generated module list with every capability enabled. Every
// module in it must register cleanly, so a namespacing or duplicate-ID violation in any module
// fails here (ADR-0003 rule 4).
func TestBootGeneratedList(t *testing.T) {
	c, err := boot(context.Background(), capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning))
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	if want := len(generatedModules(platform.Deps{}, directory.Services{})); len(c.Loaded()) != want {
		t.Fatalf("loaded %d modules, want %d", len(c.Loaded()), want)
	}
}
