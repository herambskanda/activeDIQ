package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// RootKind is the kind of a scope root (DM-35).
type RootKind string

// Root kinds.
const (
	NamingContext RootKind = "naming_context"
	OUSubtree     RootKind = "ou_subtree"
	EntraTenant   RootKind = "entra_tenant"
	Tier0Scope    RootKind = "tier0_scope"
)

// Root is one include or exclude root of an assignment. GUIDs are canonical dashed UUID text.
type Root struct {
	Kind       RootKind
	Connection string
	GUID       string
	Exclude    bool
}

// Assignment is one active role grant to a principal, with the role's permissions and its scope roots.
type Assignment struct {
	ID          string
	Permissions []authz.Permission
	Roots       []Root
}

// Source loads a principal's current assignments. Implementations return only assignments that are
// active and inside their validity window at now.
type Source interface {
	Assignments(ctx context.Context, t tenant.ID, account string, now time.Time) ([]Assignment, error)
	// PendingOrActive returns every non-revoked assignment not yet expired at now, including those
	// whose valid_from is still in the future. TM-D19 rule 5 counts what a backed account holds or
	// is about to hold: a scheduled grant must not be reachable through its AD object. It is never
	// used to decide what an actor may do.
	PendingOrActive(ctx context.Context, t tenant.ID, account string, now time.Time) ([]Assignment, error)
}

// Store is the Postgres Source.
type Store struct{ db *store.DB }

// NewStore returns the Postgres-backed Source.
func NewStore(db *store.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("rbac: no database")
	}
	return &Store{db: db}, nil
}

const readTimeout = 5 * time.Second

// Assignments reads in its own short transaction on a context detached from the caller's: the runner
// authorises from inside its own tenant transaction (the inline path), and a nested tenant transaction
// is refused. The read is committed state only, which is what an authorisation decision wants.
func (s *Store) Assignments(_ context.Context, t tenant.ID, account string, now time.Time) ([]Assignment, error) {
	return s.read(t, account, now, false)
}

// PendingOrActive is Source.PendingOrActive: revoked and expired assignments are left out, scheduled
// ones are included.
func (s *Store) PendingOrActive(_ context.Context, t tenant.ID, account string, now time.Time) ([]Assignment, error) {
	return s.read(t, account, now, true)
}

func (s *Store) read(t tenant.ID, account string, now time.Time, includeFuture bool) ([]Assignment, error) {
	if _, err := tenant.Parse(account); err != nil { // an account is a UUID; anything else holds nothing
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	var out []Assignment
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT a.id::text, COALESCE(array_agg(DISTINCT p.permission) FILTER (WHERE p.permission IS NOT NULL), '{}')
FROM public.authz_assignments a
JOIN public.authz_roles r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
LEFT JOIN public.authz_role_permissions p ON p.tenant_id = r.tenant_id AND p.role_id = r.id
WHERE a.tenant_id = $1::uuid AND a.account_id = $2::uuid AND a.assignment_state = 'active'
  AND ($4::boolean OR a.valid_from <= $3) AND (a.valid_until IS NULL OR a.valid_until > $3)
GROUP BY a.id ORDER BY a.id`, t.String(), account, now, includeFuture)
		if err != nil {
			return fmt.Errorf("rbac: reading assignments: %w", err)
		}
		var ids []string
		for rows.Next() {
			var a Assignment
			var perms []string
			if err := rows.Scan(&a.ID, &perms); err != nil {
				rows.Close()
				return fmt.Errorf("rbac: reading assignments: %w", err)
			}
			for _, p := range perms {
				a.Permissions = append(a.Permissions, authz.Permission(p))
			}
			ids = append(ids, a.ID)
			out = append(out, a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("rbac: reading assignments: %w", err)
		}
		if len(ids) == 0 {
			return nil
		}
		rr, err := tx.Query(ctx, `SELECT assignment_id::text, root_kind, connection_id::text, root_guid::text, is_exclude
FROM public.authz_assignment_roots WHERE tenant_id = $1::uuid AND assignment_id = ANY($2::uuid[]) ORDER BY assignment_id, ordinal`, t.String(), ids)
		if err != nil {
			return fmt.Errorf("rbac: reading scope roots: %w", err)
		}
		defer rr.Close()
		byID := map[string]*Assignment{}
		for i := range out {
			byID[out[i].ID] = &out[i]
		}
		for rr.Next() {
			var id, kind string
			var r Root
			if err := rr.Scan(&id, &kind, &r.Connection, &r.GUID, &r.Exclude); err != nil {
				return fmt.Errorf("rbac: reading scope roots: %w", err)
			}
			r.Kind = RootKind(kind)
			if a := byID[id]; a != nil {
				a.Roots = append(a.Roots, r)
			}
		}
		return rr.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
