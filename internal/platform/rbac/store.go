package rbac

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// accountIDRe is the canonical text form of an account's UUID, in either case. An account is not a
// tenant, so it is checked here rather than by converting it to a tenant.ID.
var accountIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// RootKind is the kind of a scope root (DM-35).
type RootKind string

// Root kinds.
const (
	NamingContext RootKind = "naming_context"
	OUSubtree     RootKind = "ou_subtree"
	// OUOneLevel reaches the direct children of an OU and nothing else: not the OU itself, not a
	// deeper descendant. It is an include root only. Anything that reads it as a subtree widens it.
	OUOneLevel  RootKind = "ou_one_level"
	EntraTenant RootKind = "entra_tenant"
	Tier0Scope  RootKind = "tier0_scope"
	// TenantStore is the tenant-wide root. It covers targets in activeDIQ's own store (a target with
	// no directory connection) and nothing else; its Connection and GUID are the tenant's ID.
	TenantStore RootKind = "tenant"
)

// SubjectKind says whom an assignment grants to (DM-36).
type SubjectKind string

// Subject kinds.
const (
	SubjectAccount    SubjectKind = "account"
	SubjectGroup      SubjectKind = "group"
	SubjectAutomation SubjectKind = "automation"
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
	// TenantOwner is true when the role is the built-in tenant-owner (never granted to a group or automation).
	TenantOwner bool
	// Subject is how the assignment reached the principal. Via is set on a group assignment whose
	// membership came through a correlation (DM-36.I2); it is not stored.
	Subject SubjectKind
	Via     *authz.Derivation
	// GroupConn and GroupGUID name the subject group of a group assignment.
	GroupConn, GroupGUID string
}

// Subjects names the subjects a read looks for. Zero fields look for nothing.
type Subjects struct {
	Account    string        // account ID (UUID)
	Groups     []authz.Group // directory groups the account is a member of
	Automation string        // automation policy ID (UUID)
}

// Source loads a principal's current assignments. Implementations return only assignments that are
// active and inside their validity window at now.
type Source interface {
	Assignments(ctx context.Context, t tenant.ID, account string, now time.Time) ([]Assignment, error)
	// SubjectAssignments is Assignments for group and automation subjects: the active assignments of
	// the named groups and of the automation policy. Account is ignored here.
	SubjectAssignments(ctx context.Context, t tenant.ID, who Subjects, now time.Time, includeFuture bool) ([]Assignment, error)
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

// SubjectAssignments is Source.SubjectAssignments. Malformed group or policy IDs hold nothing.
func (s *Store) SubjectAssignments(_ context.Context, t tenant.ID, who Subjects, now time.Time, includeFuture bool) ([]Assignment, error) {
	who.Account = ""
	return s.readSubjects(t, who, now, includeFuture)
}

func (s *Store) read(t tenant.ID, account string, now time.Time, includeFuture bool) ([]Assignment, error) {
	if !accountIDRe.MatchString(account) { // an account is a UUID; anything else holds nothing
		return nil, nil
	}
	return s.readSubjects(t, Subjects{Account: account}, now, includeFuture)
}

// readSubjects is the one parameterised read of assignments by subject: an account, a set of groups
// and an automation policy, each optional.
func (s *Store) readSubjects(t tenant.ID, who Subjects, now time.Time, includeFuture bool) ([]Assignment, error) {
	var gconn, ggid []string
	for _, g := range who.Groups {
		if accountIDRe.MatchString(g.Connection) && accountIDRe.MatchString(g.GUID) {
			gconn, ggid = append(gconn, g.Connection), append(ggid, g.GUID)
		}
	}
	var acct, pol *string
	if accountIDRe.MatchString(who.Account) {
		acct = &who.Account
	}
	if accountIDRe.MatchString(who.Automation) {
		pol = &who.Automation
	}
	if acct == nil && pol == nil && len(gconn) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	var out []Assignment
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT a.id::text, a.subject_kind, COALESCE(a.group_connection_id::text, ''), COALESCE(a.group_guid::text, ''), COALESCE(bool_or(r.role_name = 'tenant-owner' AND r.built_in), false),
  COALESCE(array_agg(DISTINCT p.permission) FILTER (WHERE p.permission IS NOT NULL), '{}')
FROM public.authz_assignments a
JOIN public.authz_roles r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
LEFT JOIN public.authz_role_permissions p ON p.tenant_id = r.tenant_id AND p.role_id = r.id
WHERE a.tenant_id = $1::uuid AND a.assignment_state = 'active'
  AND (   (a.subject_kind = 'account' AND a.account_id = $2::uuid)
       OR (a.subject_kind = 'automation' AND a.automation_policy_id = $5::uuid)
       OR (a.subject_kind = 'group' AND EXISTS (SELECT 1 FROM unnest($6::uuid[], $7::uuid[]) AS g(conn, guid)
             WHERE g.conn = a.group_connection_id AND g.guid = a.group_guid)))
  AND ($4::boolean OR a.valid_from <= $3) AND (a.valid_until IS NULL OR a.valid_until > $3)
GROUP BY a.tenant_id, a.id ORDER BY a.id`, t.String(), acct, now, includeFuture, pol, gconn, ggid)
		if err != nil {
			return fmt.Errorf("rbac: reading assignments: %w", err)
		}
		var ids []string
		for rows.Next() {
			var a Assignment
			var perms []string
			var kind string
			if err := rows.Scan(&a.ID, &kind, &a.GroupConn, &a.GroupGUID, &a.TenantOwner, &perms); err != nil {
				rows.Close()
				return fmt.Errorf("rbac: reading assignments: %w", err)
			}
			a.Subject = SubjectKind(kind)
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
