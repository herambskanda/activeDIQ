package server

import (
	"context"
	"errors"
	"github.com/skenzeriq/activediq/internal/platform/report"
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

// TestBootReportSealsHost checks the EP-8 host is built before the modules (so they receive it as
// Deps.Report), is checked against the ownership map the caller passes, and is sealed after Boot.
func TestBootReportSealsHost(t *testing.T) {
	c, h, err := bootReport(context.Background(), capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning),
		directory.Services{}, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("bootReport: %v", err)
	}
	if len(c.Datasets()) != 0 || len(h.Datasets()) != 0 {
		t.Fatalf("no module registers a dataset at 2a, got %v", h.Datasets())
	}
	if err := h.Add("inventory"); !errors.Is(err, report.ErrSealed) {
		t.Fatalf("host is not sealed after boot: %v", err)
	}
}
