package server

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/modules/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

func TestBuildOperationRefusesWithoutMinter(t *testing.T) {
	reg, _ := operation.NewRegistry()
	_, err := buildOperation(func() bool { return false }, nil, directoryFacts(nil), allowAuthz{}, reg)
	if !errors.Is(err, ErrNoMinter) {
		t.Fatalf("err = %v, want ErrNoMinter", err)
	}
}

func TestBuildOperationRefusesWithoutFacts(t *testing.T) {
	reg, _ := operation.NewRegistry()
	_, err := buildOperation(operation.HoldsMinter, nil, nil, allowAuthz{}, reg)
	if !errors.Is(err, ErrNoFacts) {
		t.Fatalf("err = %v, want ErrNoFacts", err)
	}
}

func TestRealMinterIsHeld(t *testing.T) {
	if !operation.HoldsMinter() {
		t.Fatal("operation does not hold the minter")
	}
}

// Acceptance 6: the server's facts are the connector-backed reader: a scope target answers without a
// read, a directory target with no connector read fails closed (never empty, never Tier0=true).
func TestDirectoryFactsIsConnectorBacked(t *testing.T) {
	f := directoryFacts(nil)
	got, err := f.Facts(context.Background(), nil, authority.FactsQuery{
		Target: authority.TargetRef{Connection: "c1", GUID: "c1", Class: inventory.TargetClassScope}})
	if err != nil || !got.Exists || got.Tier0 {
		t.Fatalf("scope facts = %+v, %v", got, err)
	}
	_, err = f.Facts(context.Background(), authority.Pins{"nc": "dc1"}, authority.FactsQuery{Target: authority.TargetRef{Connection: "c1", GUID: "o", Class: "user", NC: "nc"}})
	if !errors.Is(err, client.ErrNoReads) {
		t.Fatalf("err = %v, want ErrNoReads", err)
	}
}

// The class and permission the rbac package keys on are the inventory module's.
func TestRBACAgreesWithTheDesignationAction(t *testing.T) {
	if rbac.TargetClassTier0Scope != inventory.TargetClassScope || client.TargetClassTier0Scope != inventory.TargetClassScope {
		t.Fatal("tier0_scope class differs from inventory.TargetClassScope")
	}
	if !slices.Contains(rbac.Tier0ScopePermissions, inventory.DesignationPermission) {
		t.Fatal("rbac does not treat inventory.DesignationPermission as a Tier-0 scope permission")
	}
	for _, r := range rbac.BuiltInRoles() {
		if r.Tier == rbac.Tier0 {
			continue
		}
		if slices.Contains(r.Permissions, inventory.DesignationPermission) {
			t.Fatalf("role %q holds the designation permission", r.Name)
		}
	}
}

func TestDirectoryReadsIsNilUntilBothSourcesExist(t *testing.T) {
	r, err := directoryReads(nil, nil)
	if err != nil || r != nil {
		t.Fatalf("%v, %v", r, err)
	}
}

// T-0453: the permission the connections Action asks for is in the built-in tenant-owner role, and
// in no role below it.
func TestTenantOwnerCatalogueGrantsTheReconfirmPermission(t *testing.T) {
	for _, r := range rbac.BuiltInRoles() {
		has := slices.Contains(r.Permissions, connections.ReconfirmPermission)
		if want := r.Name == rbac.TenantOwnerRole; has != want {
			t.Errorf("role %q holds %s = %v, want %v", r.Name, connections.ReconfirmPermission, has, want)
		}
	}
}
