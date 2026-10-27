package server

import (
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// buildOwnerAssignments wires rbac.OwnerAssignments, the one writer of tenant-owner assignments: the
// authn account store answers which owners are active (rbac.ActiveAccounts), and the authn session store
// ends a changed account's sessions in the same transaction (rbac.SessionRevoker, reason role_changed).
// Both audit into sink. rbac.NewOwnerAssignments refuses a nil port, so a half-wired writer fails startup.
func buildOwnerAssignments(db *store.DB, sink audit.Sink, sessions *authn.Store) (*rbac.OwnerAssignments, error) {
	accounts, err := authn.NewAccounts(db, sessions, rbac.Owners{})
	if err != nil {
		return nil, fmt.Errorf("server: account store: %w", err)
	}
	oa, err := rbac.NewOwnerAssignments(db, sink, accounts, sessions)
	if err != nil {
		return nil, fmt.Errorf("server: owner assignments: %w", err)
	}
	return oa, nil
}
