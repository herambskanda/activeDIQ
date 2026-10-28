// Package tenantref turns the tenant text an authenticated principal carries back into a tenant.ID. It sits
// under authn, one of the packages ADR-0002 rule 5 lets mint a tenant.ID, and imports nothing of authn so
// low-level packages (rbac, directory client) can use it without an import cycle.
package tenantref

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ErrNoTenant is returned when no valid tenant is carried by the context or the text given.
var ErrNoTenant = errors.New("tenantref: no valid tenant")

// TenantFromText reads back a tenant ID from the canonical text that authentication put on an
// authenticated principal, an authority context or a tenant-scoped transaction setting (ADR-0002 rule 5).
// It is the one place outside tenant provisioning where such text becomes a tenant.ID, so a caller that
// holds the text of an already-authenticated tenant asks here instead of minting its own ID. It must
// never be given text from a request body, path or query: the unauthenticated attestation callback is a
// registry-listed mint instead. callers_test.go pins the packages that may call it. The zero tenant is refused.
func TenantFromText(s string) (tenant.ID, error) {
	t, err := tenant.Parse(s)
	if err != nil || t.IsZero() {
		return tenant.ID{}, ErrNoTenant
	}
	return t, nil
}

// TenantFromContext returns the tenant that authority.WithTenant set on ctx (the runner sets it for
// every authorisation decision and write).
func TenantFromContext(ctx context.Context) (tenant.ID, error) {
	s, ok := authority.TenantFrom(ctx)
	if !ok {
		return tenant.ID{}, ErrNoTenant
	}
	return TenantFromText(s)
}
