package server

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// TestBootGeneratedList boots the generated module list with every capability enabled. Every
// module in it must register cleanly, so a namespacing or duplicate-ID violation in any module
// fails here (ADR-0003 rule 4).
func TestBootGeneratedList(t *testing.T) {
	c, err := boot(context.Background(), capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning), directory.Services{})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	if want := len(generatedModules(platform.Deps{}, directory.Services{})); len(c.Loaded()) != want {
		t.Fatalf("loaded %d modules, want %d", len(c.Loaded()), want)
	}
}

// TestDirectoryServicesConnection checks the connection registry is built from the store and reaches
// it: a tenant with no connections lists none, with no error and no panic.
func TestDirectoryServicesConnection(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		svc := directoryServices(e.db)
		if svc.Connection == nil {
			t.Fatal("Services.Connection is nil")
		}
		cs, err := svc.Connection.List(context.Background(), e.ten, false)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(cs) != 0 {
			t.Fatalf("listed %d connections, want 0", len(cs))
		}
	})
}
