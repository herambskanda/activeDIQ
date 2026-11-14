package server

import (
	"context"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Every permission a built-in role holds and every module-declared one is in the catalogue, sorted and unique.
func TestPermissionCatalogueIsComplete(t *testing.T) {
	c := bootedCatalogue()
	for _, p := range append([]string{"directory.read", "siem.destination.read", "operation.approve", "objects.user.delete"}, "connections.takeover.attest", "reports.run", "reports.export", "reports.schedule", "reports.schedule.manage_all", "reports.deliver.external") {
		if !c.Has(p) {
			t.Errorf("catalogue lacks %q", p)
		}
	}
	for i := 1; i < len(c); i++ {
		if c[i-1] >= c[i] {
			t.Fatalf("catalogue not sorted/unique at %q, %q", c[i-1], c[i])
		}
	}
	if err := checkCatalogue(c); err != nil {
		t.Fatal(err)
	}
	if checkCatalogue(nil) == nil || checkCatalogue(apihost.Permissions{"a", ""}) == nil {
		t.Error("an empty catalogue or an empty name must fail")
	}
}

// Build refuses the contract when the catalogue lacks the permission a mounted operation names.
func TestBuildRefusesOperationWithPermissionMissingFromCatalogue(t *testing.T) {
	cfg := config.Config{APIBodyBudget: config.DefaultAPIBodyBudget}
	p, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	var cat apihost.Permissions
	for _, s := range bootedCatalogue() {
		if s != "directory.read" {
			cat = append(cat, s)
		}
	}
	_, err = buildAPIPortsWith(cfg, p, cat, failClosedPorts(testLimiter(t)))
	if err == nil || !strings.Contains(err.Error(), "directory.read") {
		t.Fatalf("want a build error naming directory.read, got %v", err)
	}
}

// A malformed policy.yaml (as embedded JSON) fails the loader with a clear error: boot never starts.
func TestMalformedPolicyFailsClosed(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":        `anonymous: [`,
		"unknown section": `{"anonymus": []}`,
		"empty host":      `{"anonymous": [{"operation": "getLiveness", "host": ""}]}`,
		"no subject":      `{"authenticated": [{"reason": "r"}]}`,
	} {
		if _, err := apihost.ParsePolicy([]byte(doc)); err == nil || !strings.Contains(err.Error(), "apihost: policy") {
			t.Errorf("%s: want a policy error, got %v", name, err)
		}
	}
}

// The RBAC port denies a permission outside the catalogue without asking RBAC, even for a grant-all authorizer.
func TestConsoleAuthzDeniesUnlistedPermission(t *testing.T) {
	ra := &recAuthz{}
	p := apihost.Principal{ID: tenant.New().String(), Tenant: tenant.New().String(), Kind: apihost.KindSession}
	a := consoleAuthz{ra, bootedCatalogue()}
	if ok, err := a.Allow(context.Background(), p, "made.up.permission", "tenant"); ok || err != nil || ra.called {
		t.Fatalf("unlisted: ok=%v err=%v consulted=%v", ok, err, ra.called)
	}
	if ok, err := a.Allow(context.Background(), p, "directory.read", "tenant"); !ok || err != nil {
		t.Fatalf("listed: ok=%v err=%v", ok, err)
	}
}

// bootedCatalogue is the catalogue over the permissions the generated modules register. It boots
// the module list without a database, as the cross-module boot tests do.
func bootedCatalogue() apihost.Permissions {
	c, _, err := bootReport(context.Background(), capability.NewSet(), directory.Services{}, owners.Lookup)
	if err != nil {
		panic(err)
	}
	return permissionCatalogue(c)
}
