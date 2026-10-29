package provision

import "github.com/skenzeriq/activediq/internal/platform/tablekind"

// This declares public.tenants (DM-01), here and not in package tenant (the ID type the agent links: T-0688 ruling 2) for fitness-domain-keys. It is the one registered-global
// table (ADR-0002 rule 4), so its kind is Platform.
var _ = tablekind.Declare(tablekind.Table{
	Name:   "public.tenants",
	Entity: "DM-01",
	Kind:   tablekind.Platform,
})
