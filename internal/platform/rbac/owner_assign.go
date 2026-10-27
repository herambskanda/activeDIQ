package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Errors of the owner-assignment write path. None carries a stored value or SQL.
var (
	// ErrLastOwner: the revoke would leave the tenant without an active tenant-owner (DM-30.I4).
	ErrLastOwner = errors.New("rbac: at least one active tenant-owner is required")
	// ErrAlreadyOwner: the account already holds an active tenant-owner assignment.
	ErrAlreadyOwner = errors.New("rbac: account is already a tenant-owner")
	// ErrOwnerNotFound: no active tenant-owner assignment with that ID in this tenant.
	ErrOwnerNotFound = errors.New("rbac: no such tenant-owner assignment")
	// ErrNoOwnerRole: the built-in tenant-owner role is not seeded for this tenant.
	ErrNoOwnerRole = errors.New("rbac: tenant-owner role is not seeded")
	// ErrBadOwnerInput: the account is not a UUID, or the actor chain names no requester.
	ErrBadOwnerInput = errors.New("rbac: invalid owner assignment input")
)

// Audit kinds written by OwnerAssignments, in the caller's transaction.
const (
	KindOwnerGranted       audit.Kind = "rbac.owner.granted"
	KindOwnerRevoked       audit.Kind = "rbac.owner.revoked"
	KindOwnerRevokeRefused audit.Kind = "rbac.owner.revoke_refused"
)

// ActiveAccounts says which of the given accounts are active. Whether an account is active is the
// account store's to say (authn), so rbac asks through this port rather than reading its table.
type ActiveAccounts interface {
	// CountActive returns how many of ids are active accounts of t.
	CountActive(ctx context.Context, tx store.Tx, t tenant.ID, ids []string) (int, error)
}

// OwnerAssignments is the one writer of tenant-owner assignments. A grant is personal (an account
// subject, no scope roots) and unbounded: the schema refuses an expiry or a future start (migration
// 0034), so a tenant cannot lose its owner through time. A revoke takes the owner advisory lock first
// (Owners.TenantOwners) and is refused when it would remove the last active owner, so two concurrent
// revokes of the only two owners leave exactly one. Both write their audit event in the same
// transaction as the change. Safe for concurrent use.
type OwnerAssignments struct {
	db     *store.DB
	audit  audit.Sink
	active ActiveAccounts
	owners Owners
}

// NewOwnerAssignments returns the writer. All three collaborators are required: without the sink the
// change would be unaudited, without the account port DM-30.I4 could not be enforced.
func NewOwnerAssignments(db *store.DB, sink audit.Sink, active ActiveAccounts) (*OwnerAssignments, error) {
	if db == nil || sink == nil || active == nil {
		return nil, errors.New("rbac: owner assignments need a database, an audit sink and an active-account source")
	}
	return &OwnerAssignments{db: db, audit: sink, active: active}, nil
}

func (o *OwnerAssignments) emit(ctx context.Context, tx store.Tx, now time.Time, kind audit.Kind, eid, account string, by authority.Chain, outcome audit.Outcome, reason string, details []audit.Detail) error {
	ev := audit.Event{
		ID: "rbac.owner." + eid, Kind: kind, At: now, Actor: by,
		Target:    authority.TargetRef{GUID: account, Class: "account"},
		Component: "rbac", Outcome: outcome, Reason: reason, Details: details,
	}
	if err := o.audit.Append(ctx, tx, ev); err != nil {
		return fmt.Errorf("rbac: audit owner event: %w", err)
	}
	return nil
}

// clock reads the database's current time (never the same twice in one transaction).
func clock(ctx context.Context, tx store.Tx) (time.Time, error) {
	var t time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&t); err != nil {
		return time.Time{}, fmt.Errorf("rbac: owner clock: %w", err)
	}
	return t.UTC(), nil
}

// Grant makes account a tenant-owner of t. It returns the assignment ID. An account that already holds
// an active owner assignment is refused with ErrAlreadyOwner (no second row, no audit event).
func (o *OwnerAssignments) Grant(ctx context.Context, t tenant.ID, account string, by authority.Chain) (string, error) {
	if t.IsZero() || !accountIDRe.MatchString(account) || by.Validate() != nil {
		return "", ErrBadOwnerInput
	}
	var id string
	err := o.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var roleID string
		err := tx.QueryRow(ctx, `SELECT id::text FROM public.authz_roles WHERE tenant_id = $1::uuid AND role_name = $2 AND built_in`,
			t.String(), TenantOwnerRole).Scan(&roleID)
		if store.IsNoRows(err) {
			return ErrNoOwnerRole
		} else if err != nil {
			return fmt.Errorf("rbac: reading owner role: %w", err)
		}
		// Two grants of one account must not both insert. Same lock as revoke: grants are rare.
		if _, err := o.owners.TenantOwners(ctx, tx, t); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.authz_assignments WHERE tenant_id = $1::uuid AND role_id = $2::uuid AND account_id = $3::uuid AND assignment_state = 'active'`,
			t.String(), roleID, account).Scan(&n); err != nil {
			return fmt.Errorf("rbac: reading owner assignments: %w", err)
		}
		if n > 0 {
			return ErrAlreadyOwner
		}
		if err := tx.QueryRow(ctx, `INSERT INTO public.authz_assignments (tenant_id, account_id, role_id, granted_by)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4) RETURNING id::text`, t.String(), account, roleID, string(by.Requester.ID)).Scan(&id); err != nil {
			return fmt.Errorf("rbac: granting tenant-owner: %w", err)
		}
		now, err := clock(ctx, tx)
		if err != nil {
			return err
		}
		return o.emit(ctx, tx, now, KindOwnerGranted, id+".granted", account, by, audit.Success, "granted",
			[]audit.Detail{{Key: "assignment", Value: id}})
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// Revoke ends the tenant-owner assignment id. It takes the owner lock first; if the assignment's
// account is an active owner and no other active owner would remain, nothing changes, only a denied
// audit event is committed, and ErrLastOwner is returned.
func (o *OwnerAssignments) Revoke(ctx context.Context, t tenant.ID, assignment string, by authority.Chain) error {
	if t.IsZero() || !accountIDRe.MatchString(assignment) || by.Validate() != nil {
		return ErrBadOwnerInput
	}
	refused := false
	err := o.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		holders, err := o.owners.TenantOwners(ctx, tx, t) // takes the lock; read is fresh after it
		if err != nil {
			return err
		}
		now, err := clock(ctx, tx)
		if err != nil {
			return err
		}
		var account string
		err = tx.QueryRow(ctx, `SELECT a.account_id::text FROM public.authz_assignments a
JOIN public.authz_roles r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
WHERE a.tenant_id = $1::uuid AND a.id = $2::uuid AND r.role_name = $3 AND r.built_in AND a.assignment_state = 'active'`,
			t.String(), assignment, TenantOwnerRole).Scan(&account)
		if store.IsNoRows(err) {
			return ErrOwnerNotFound
		} else if err != nil {
			return fmt.Errorf("rbac: reading owner assignment: %w", err)
		}
		// Owners other than this assignment's account that are active accounts. Another assignment of
		// the same account does not make it a different owner.
		var others []string
		for _, h := range holders {
			if h != account {
				others = append(others, h)
			}
		}
		var n int
		if len(others) > 0 {
			if n, err = o.active.CountActive(ctx, tx, t, others); err != nil {
				return fmt.Errorf("rbac: counting active owners: %w", err)
			}
		}
		if n == 0 {
			// Removing an owner whose account is itself not active changes nothing about who can act.
			self, err := o.active.CountActive(ctx, tx, t, []string{account})
			if err != nil {
				return fmt.Errorf("rbac: counting active owners: %w", err)
			}
			if self > 0 {
				refused = true // commit only the refusal's audit event
				return o.emit(ctx, tx, now, KindOwnerRevokeRefused, fmt.Sprintf("%s.refused.%d", assignment, now.UnixNano()), account, by,
					audit.Denied, "last_tenant_owner", []audit.Detail{{Key: "assignment", Value: assignment}})
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE public.authz_assignments SET assignment_state = 'revoked' WHERE tenant_id = $1::uuid AND id = $2::uuid`,
			t.String(), assignment); err != nil {
			return fmt.Errorf("rbac: revoking tenant-owner: %w", err)
		}
		return o.emit(ctx, tx, now, KindOwnerRevoked, assignment+".revoked", account, by, audit.Success, "revoked",
			[]audit.Detail{{Key: "assignment", Value: assignment}})
	})
	switch {
	case err == nil && refused:
		return ErrLastOwner
	case err != nil:
		return err
	}
	return nil
}
