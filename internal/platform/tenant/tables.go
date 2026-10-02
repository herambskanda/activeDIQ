package tenant

import "github.com/skenzeriq/activediq/internal/platform/tablekind"

// tenantsTable declares public.tenants (DM-01) for fitness-domain-keys. It is the one registered-global
// table (ADR-0002 rule 4), so its kind is Platform.
var tenantsTable = tablekind.Declare(tablekind.Table{
	Name:   "public.tenants",
	Entity: "DM-01",
	Kind:   tablekind.Platform,
})
