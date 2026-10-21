package jobs

import "github.com/skenzeriq/activediq/internal/platform/tablekind"

// jobsTable declares public.jobs (DM-43) for fitness-domain-keys. It is a registered-global table
// (ADR-0002 Jobs row), so its kind is Platform.
var jobsTable = tablekind.Declare(tablekind.Table{
	Name:   "public.jobs",
	Entity: "DM-43",
	Kind:   tablekind.Platform,
})
