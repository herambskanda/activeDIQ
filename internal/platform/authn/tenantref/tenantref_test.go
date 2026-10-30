package tenantref

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func TestTenantFromText(t *testing.T) {
	want := tenant.New()
	got, err := TenantFromText(want.String())
	if err != nil || got != want {
		t.Fatalf("round trip: %v %v", got, err)
	}
	for _, bad := range []string{"", "x", "00000000-0000-0000-0000-000000000000", want.String() + " "} {
		if _, err := TenantFromText(bad); !errors.Is(err, ErrNoTenant) {
			t.Errorf("%q: want ErrNoTenant, got %v", bad, err)
		}
	}
}

// A context carries exactly the tenant it was given: tenant B's context never yields tenant A.
func TestTenantFromContextIsCrossTenantSafe(t *testing.T) {
	a, b := tenant.New(), tenant.New()
	ga, _ := TenantFromContext(authority.WithTenant(context.Background(), a.String()))
	gb, _ := TenantFromContext(authority.WithTenant(context.Background(), b.String()))
	if ga != a || gb != b || ga == gb {
		t.Fatalf("tenants crossed: %v %v", ga, gb)
	}
	if _, err := TenantFromContext(context.Background()); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("no tenant in ctx: %v", err)
	}
}
