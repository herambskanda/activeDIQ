package migration

import "github.com/skenzeriq/activediq/internal/platform/tablekind"

// Declared for fitness-domain-keys.
var (
	_ = tablekind.Declare(tablekind.Table{Name: "public.migration_projects", Entity: "DM-90", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.migration_jobs", Entity: "DM-91", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.migration_fidelity", Entity: "DM-92", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.migration_proposals", Entity: "DM-93", Kind: tablekind.Tenant})
)
