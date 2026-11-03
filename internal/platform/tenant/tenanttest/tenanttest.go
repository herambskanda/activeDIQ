// Package tenanttest is test support that creates tenants. It lives under internal/platform/tenant,
// which owns the tenants table and may mint a tenant.ID, so other packages' tests get tenants without
// naming the table or minting an ID themselves.
package tenanttest

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Exec runs one statement with bound arguments as a role that may insert into tenants, such as the
// migration role; storetest.Database.ExecOwner has this shape.
type Exec func(ctx context.Context, sql string, args ...any) error

// Seed inserts a tenant with a fresh random ID and returns it.
func Seed(t testing.TB, exec Exec, name string) tenant.ID {
	t.Helper()
	id := tenant.New()
	if err := exec(context.Background(), `INSERT INTO public.tenants (id, name) VALUES ($1::uuid, $2)`, id.String(), name); err != nil {
		t.Fatalf("tenanttest: seed tenant %q: %v", name, err)
	}
	return id
}

// NewID returns a fresh random tenant ID without touching a database. It is how test-support code
// outside this package (the operationtest harness) names a tenant for an in-memory run, so it does
// not mint IDs itself (ADR-0002 rule 5). It takes a testing.TB, like Seed, so a call cannot
// type-check outside a test, and the package is on policy.TestSupport, so product code may not import it.
func NewID(t testing.TB) tenant.ID {
	t.Helper()
	return tenant.New()
}
