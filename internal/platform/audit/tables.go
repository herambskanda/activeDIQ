package audit

import "github.com/skenzeriq/activediq/internal/platform/tablekind"

// The chain's tables, declared for fitness-domain-keys. audit_head is the one mutable table (the
// chain head and its row lock); the others are append-only for the runtime role (X5).
var (
	_ = tablekind.Declare(tablekind.Table{Name: "public.audit_event", Entity: "DM-80", Kind: tablekind.Tenant, AppendOnly: true})
	_ = tablekind.Declare(tablekind.Table{Name: "public.audit_head", Entity: "DM-80", Kind: tablekind.Tenant, Bookkeeping: true})
	_ = tablekind.Declare(tablekind.Table{Name: "public.audit_checkpoint", Entity: "DM-81", Kind: tablekind.Tenant, AppendOnly: true})
	_ = tablekind.Declare(tablekind.Table{Name: "public.audit_checkpoint_key", Entity: "DM-81", Kind: tablekind.Tenant, AppendOnly: true, Sealed: []string{"sealed_private_key"}})
)
