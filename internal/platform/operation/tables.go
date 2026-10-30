package operation

import "github.com/skenzeriq/activediq/internal/platform/tablekind"

// The pipeline's tables, declared for fitness-domain-keys. They are mutable tenant tables whose state
// columns only this package's transition functions write (O4).
var (
	_ = tablekind.Declare(tablekind.Table{Name: "public.operations", Entity: "DM-41", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.operation_items", Entity: "DM-42", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.operation_steps", Entity: "DM-42", Kind: tablekind.Tenant})
	_ = tablekind.Declare(tablekind.Table{Name: "public.operation_secrets", Entity: "DM-42", Kind: tablekind.Tenant, Sealed: []string{"sealed_secret"}})
)
