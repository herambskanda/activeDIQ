package server

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// TestBootGeneratedList boots the generated module list with every capability enabled. Every
// module in it must register cleanly, so a namespacing or duplicate-ID violation in any module
// fails here (ADR-0003 rule 4).
func TestBootGeneratedList(t *testing.T) {
	c, _, err := bootReport(context.Background(), capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning), directory.Services{}, owners.Lookup)
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
// Deps.Report), holds the inventory datasets under the real ownership map (T-1104: report.CheckTables
// passes), and is sealed after Boot.
func TestBootReportSealsHost(t *testing.T) {
	c, h, err := bootReport(context.Background(), capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning),
		directory.Services{}, owners.Lookup)
	if err != nil {
		t.Fatalf("bootReport: %v", err)
	}
	if len(c.Datasets()) != 0 {
		t.Fatalf("no module registers a dataset at 2a, got %v", c.Datasets())
	}
	want := []report.DatasetID{inventory.DatasetComputers, inventory.DatasetContacts, inventory.DatasetGroupMembers,
		inventory.DatasetGroups, inventory.DatasetObjectChanges, inventory.DatasetOUs, inventory.DatasetPrincipals, inventory.DatasetUsers}
	if got := h.Datasets(); !slices.Equal(got, want) {
		t.Fatalf("host datasets = %v, want %v", got, want)
	}
	if err := h.Add("inventory"); !errors.Is(err, report.ErrSealed) {
		t.Fatalf("host is not sealed after boot: %v", err)
	}
}

// TestBootRefusesDatasetOverTableItDoesNotOwn is the other half of T-1104 AC-1: when the ownership map
// does not give the inventory package a table its dataset names, boot refuses and names the table.
func TestBootRefusesDatasetOverTableItDoesNotOwn(t *testing.T) {
	caps := capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning)
	cases := map[string]report.TableOwners{
		"owned by another package": func(table string) (string, bool) {
			if table == "links" {
				return "connection", true
			}
			return owners.Lookup(table)
		},
		"owned by nobody": func(table string) (string, bool) {
			if table == "inventory_psos" {
				return "", false
			}
			return owners.Lookup(table)
		},
		"empty map": func(string) (string, bool) { return "", false },
	}
	for name, ownerOf := range cases {
		t.Run(name, func(t *testing.T) {
			_, h, err := bootReport(context.Background(), caps, directory.Services{}, ownerOf)
			if !errors.Is(err, report.ErrTableOwnership) {
				t.Fatalf("bootReport error = %v, want report.ErrTableOwnership", err)
			}
			var te *report.TableOwnershipError
			if !errors.As(err, &te) || te.Table == "" {
				t.Fatalf("error does not name the table: %v", err)
			}
			if h != nil {
				t.Fatal("a refused boot returned a host")
			}
		})
	}
}
