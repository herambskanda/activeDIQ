package rbac

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Errors of the role and assignment write path. None carries SQL or a stored value.
var (
	// ErrEscalation: the grantor does not hold every privilege of the role over the whole scope (DM-36.I1).
	ErrEscalation = fmt.Errorf("rbac: %w", authz.ErrEscalation)
	// ErrControlPlanePersonal: tenant-owner or a control-plane permission was offered to a group or
	// automation subject (DM-36.I4).
	ErrControlPlanePersonal = errors.New("rbac: control-plane authority is personal to an account")
	// ErrBuiltInRole: a built-in role is read-only (DM-34.I1).
	ErrBuiltInRole = errors.New("rbac: built-in roles are read-only")
	// ErrOwnerRole: tenant-owner is assigned and revoked through OwnerAssignments only.
	ErrOwnerRole = errors.New("rbac: tenant-owner is assigned through the owner path")
	// ErrNotFound: the role or assignment does not exist in this tenant.
	ErrNotFound = errors.New("rbac: not found")
	// ErrExists: the ID is already taken by a different row.
	ErrExists = errors.New("rbac: already exists")
	// ErrInvalid: malformed input.
	ErrInvalid = errors.New("rbac: invalid input")
	// ErrActorNotDirect: only a person acting directly administers access; a token or automation
	// policy in the chain is refused (control-plane authority is personal).
	ErrActorNotDirect = errors.New("rbac: access is administered by a person acting directly")
)

var permissionRe = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)

// Grants writes custom roles and assignments inside the caller's transaction (the runner's), so the
// change, its audit event and its no-escalation proof commit or fail together. It never decides
// whether the actor may call it at all: the Action's permission does, in the runner.
type Grants struct{ a *Authorizer }

// NewGrants returns the writer over the Authorizer whose membership, token and root resolution it
// shares, so the no-escalation test sees exactly the grantor the pipeline sees.
func NewGrants(a *Authorizer) (*Grants, error) {
	if a == nil {
		return nil, errors.New("rbac: grants need an authorizer")
	}
	return &Grants{a: a}, nil
}

// SubjectRef names the subject of an assignment: exactly one of the fields is set.
type SubjectRef struct {
	Kind       SubjectKind
	Account    string // account ID
	Connection string // group: connection ID
	Group      string // group: objectGUID
	Automation string // automation policy ID
}

func (s SubjectRef) valid() bool {
	switch s.Kind {
	case SubjectAccount:
		return accountIDRe.MatchString(s.Account) && s.Connection == "" && s.Group == "" && s.Automation == ""
	case SubjectGroup:
		return accountIDRe.MatchString(s.Connection) && accountIDRe.MatchString(s.Group) && s.Account == "" && s.Automation == ""
	case SubjectAutomation:
		return accountIDRe.MatchString(s.Automation) && s.Account == "" && s.Connection == "" && s.Group == ""
	}
	return false
}

// GrantInput is one assignment to create. ID is chosen by the caller so a retry is the same grant.
type GrantInput struct {
	ID         string
	RoleID     string
	Subject    SubjectRef
	Roots      []Root
	ValidFrom  *time.Time // nil: now
	ValidUntil *time.Time
}

func tenantOf(ctx context.Context, tx store.Tx) (tenant.ID, error) {
	var s string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(current_setting('app.tenant_id', true), '')`).Scan(&s); err != nil {
		return tenant.ID{}, fmt.Errorf("rbac: reading tenant: %w", err)
	}
	return tenant.Parse(s)
}

type roleRow struct {
	name    string
	builtIn bool
	tier    int
	perms   []authz.Permission
}

func readRole(ctx context.Context, tx store.Tx, tn tenant.ID, id string) (roleRow, error) {
	var r roleRow
	err := tx.QueryRow(ctx, `SELECT role_name, built_in, tier FROM public.authz_roles WHERE tenant_id = $1::uuid AND id = $2::uuid`,
		tn.String(), id).Scan(&r.name, &r.builtIn, &r.tier)
	if store.IsNoRows(err) {
		return r, ErrNotFound
	} else if err != nil {
		return r, fmt.Errorf("rbac: reading role: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT permission FROM public.authz_role_permissions WHERE tenant_id = $1::uuid AND role_id = $2::uuid ORDER BY permission`, tn.String(), id)
	if err != nil {
		return r, fmt.Errorf("rbac: reading role permissions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return r, fmt.Errorf("rbac: reading role permissions: %w", err)
		}
		r.perms = append(r.perms, authz.Permission(p))
	}
	return r, rows.Err()
}

func controlPlane(perms []authz.Permission) bool {
	return slices.ContainsFunc(perms, authz.NeverCrosses)
}

// actorAssignments returns the actor's current assignments, refusing a chain that is not a person
// acting directly.
func (g *Grants) actorAssignments(ctx context.Context, tn tenant.ID, by authority.Chain) ([]Assignment, error) {
	if by.Validate() != nil || by.Requester.Kind != authority.Human || len(by.Via) > 0 {
		return nil, ErrActorNotDirect
	}
	return g.a.effective(ctx, tn, string(by.Requester.ID), false)
}

// mustHold is the DM-36.I1 test. A personal tenant-owner assignment is the one exception.
func (g *Grants) mustHold(ctx context.Context, tn tenant.ID, by authority.Chain, actor []Assignment, perms []authz.Permission, roots []Root) error {
	if slices.ContainsFunc(actor, func(a Assignment) bool { return a.TenantOwner && a.Via == nil && a.Subject == SubjectAccount }) {
		return nil
	}
	if len(perms) == 0 {
		return nil
	}
	err := g.a.holdsOver(ctx, tn, actor, string(by.Requester.ID), perms, roots)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, authz.ErrEscalation), errors.Is(err, authz.ErrOwnerDead):
		return ErrEscalation
	default:
		return fmt.Errorf("%w: %w", ErrEscalation, err) // the proof could not be made: refuse
	}
}

// CreateRole inserts a custom role. It grants nothing until assigned.
func (g *Grants) CreateRole(ctx context.Context, tx store.Tx, by authority.Chain, id, name string, tier Tier, perms []authz.Permission) error {
	if by.Validate() != nil || !accountIDRe.MatchString(id) || name == "" || len(name) > 128 || tier < Tier0 || tier > Tier2 || len(perms) == 0 {
		return ErrInvalid
	}
	for _, p := range perms {
		if !permissionRe.MatchString(string(p)) {
			return ErrInvalid
		}
	}
	if err := ValidateRoles([]Role{{Name: name, Tier: tier, Permissions: perms}}); err != nil {
		return ErrInvalid
	}
	tn, err := tenantOf(ctx, tx)
	if err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.authz_roles WHERE tenant_id = $1::uuid AND (id = $2::uuid OR role_name = $3)`, tn.String(), id, name).Scan(&n); err != nil {
		return fmt.Errorf("rbac: reading roles: %w", err)
	}
	if n > 0 {
		return ErrExists
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.authz_roles (tenant_id, id, role_name, built_in, tier) VALUES ($1::uuid, $2::uuid, $3, false, $4)`,
		tn.String(), id, name, int(tier)); err != nil {
		return fmt.Errorf("rbac: creating role: %w", err)
	}
	for _, p := range perms {
		if _, err := tx.Exec(ctx, `INSERT INTO public.authz_role_permissions (tenant_id, role_id, permission) VALUES ($1::uuid, $2::uuid, $3) ON CONFLICT DO NOTHING`,
			tn.String(), id, string(p)); err != nil {
			return fmt.Errorf("rbac: adding permission: %w", err)
		}
	}
	return nil
}

type heldBy struct {
	id      string
	subject SubjectKind
	roots   []Root
}

// holders returns the non-revoked assignments of a role, with their roots.
func holders(ctx context.Context, tx store.Tx, tn tenant.ID, role string) ([]heldBy, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, subject_kind FROM public.authz_assignments WHERE tenant_id = $1::uuid AND role_id = $2::uuid AND assignment_state = 'active' ORDER BY id`, tn.String(), role)
	if err != nil {
		return nil, fmt.Errorf("rbac: reading holders: %w", err)
	}
	var out []heldBy
	for rows.Next() {
		var h heldBy
		var k string
		if err := rows.Scan(&h.id, &k); err != nil {
			rows.Close()
			return nil, fmt.Errorf("rbac: reading holders: %w", err)
		}
		h.subject = SubjectKind(k)
		out = append(out, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rbac: reading holders: %w", err)
	}
	for i := range out {
		if out[i].roots, err = readRoots(ctx, tx, tn, out[i].id); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readRoots(ctx context.Context, tx store.Tx, tn tenant.ID, assignment string) ([]Root, error) {
	rr, err := tx.Query(ctx, `SELECT root_kind, connection_id::text, root_guid::text, is_exclude FROM public.authz_assignment_roots
WHERE tenant_id = $1::uuid AND assignment_id = $2::uuid ORDER BY ordinal`, tn.String(), assignment)
	if err != nil {
		return nil, fmt.Errorf("rbac: reading roots: %w", err)
	}
	defer rr.Close()
	var out []Root
	for rr.Next() {
		var r Root
		var k string
		if err := rr.Scan(&k, &r.Connection, &r.GUID, &r.Exclude); err != nil {
			return nil, fmt.Errorf("rbac: reading roots: %w", err)
		}
		r.Kind = RootKind(k)
		out = append(out, r)
	}
	return out, rr.Err()
}

// SetRolePermissions replaces the permissions of a custom role. Adding a permission is a grant to
// every holder of the role, so it needs the same proof as granting it afresh over each holder's
// scope (DM-36.I1), and it is refused outright if a group or automation subject holds the role and
// the permission is control-plane (DM-36.I4: clone the role instead). Removal only narrows.
func (g *Grants) SetRolePermissions(ctx context.Context, tx store.Tx, by authority.Chain, roleID string, perms []authz.Permission) error {
	if !accountIDRe.MatchString(roleID) || len(perms) == 0 {
		return ErrInvalid
	}
	for _, p := range perms {
		if !permissionRe.MatchString(string(p)) {
			return ErrInvalid
		}
	}
	tn, err := tenantOf(ctx, tx)
	if err != nil {
		return err
	}
	role, err := readRole(ctx, tx, tn, roleID)
	if err != nil {
		return err
	}
	if role.builtIn {
		return ErrBuiltInRole
	}
	if err := ValidateRoles([]Role{{Name: role.name, Tier: Tier(role.tier), Permissions: perms}}); err != nil {
		return ErrInvalid
	}
	var added []authz.Permission
	for _, p := range perms {
		if !slices.Contains(role.perms, p) && !slices.Contains(added, p) {
			added = append(added, p)
		}
	}
	if len(added) > 0 {
		actor, err := g.actorAssignments(ctx, tn, by)
		if err != nil {
			return err
		}
		hs, err := holders(ctx, tx, tn, roleID)
		if err != nil {
			return err
		}
		for _, h := range hs {
			if h.subject != SubjectAccount && controlPlane(added) {
				return ErrControlPlanePersonal
			}
			if err := g.mustHold(ctx, tn, by, actor, added, h.roots); err != nil {
				return err
			}
		}
	}
	for _, p := range role.perms {
		if !slices.Contains(perms, p) {
			if _, err := tx.Exec(ctx, `DELETE FROM public.authz_role_permissions WHERE tenant_id = $1::uuid AND role_id = $2::uuid AND permission = $3`, tn.String(), roleID, string(p)); err != nil {
				return fmt.Errorf("rbac: removing permission: %w", err)
			}
		}
	}
	for _, p := range added {
		if _, err := tx.Exec(ctx, `INSERT INTO public.authz_role_permissions (tenant_id, role_id, permission) VALUES ($1::uuid, $2::uuid, $3)`, tn.String(), roleID, string(p)); err != nil {
			return fmt.Errorf("rbac: adding permission: %w", err)
		}
	}
	return nil
}

func validRoots(tn tenant.ID, roots []Root) bool {
	include := 0
	for _, r := range roots {
		if !accountIDRe.MatchString(r.Connection) || !accountIDRe.MatchString(r.GUID) {
			return false
		}
		switch r.Kind {
		case NamingContext, OUSubtree:
		case EntraTenant, Tier0Scope:
			if r.Connection != r.GUID {
				return false
			}
		case TenantStore:
			if r.Connection != tn.String() || r.GUID != tn.String() {
				return false
			}
		default:
			return false
		}
		if r.Exclude {
			if r.Kind == Tier0Scope || r.Kind == TenantStore {
				return false
			}
		} else {
			include++
		}
	}
	return include > 0
}

// Grant creates an assignment. The grantor must hold every privilege of the role over the whole
// scope or be a personal tenant-owner (DM-36.I1); group and automation subjects never receive
// tenant-owner or a control-plane permission (DM-36.I4). It returns ErrExists for an ID that is
// taken, and nil for a repeat of the identical grant.
func (g *Grants) Grant(ctx context.Context, tx store.Tx, by authority.Chain, in GrantInput) error {
	if !accountIDRe.MatchString(in.ID) || !accountIDRe.MatchString(in.RoleID) || !in.Subject.valid() ||
		(in.ValidFrom != nil && in.ValidUntil != nil && !in.ValidUntil.After(*in.ValidFrom)) {
		return ErrInvalid
	}
	tn, err := tenantOf(ctx, tx)
	if err != nil {
		return err
	}
	if !validRoots(tn, in.Roots) {
		return ErrInvalid
	}
	role, err := readRole(ctx, tx, tn, in.RoleID)
	if err != nil {
		return err
	}
	if role.builtIn && role.name == TenantOwnerRole {
		return ErrOwnerRole
	}
	if in.Subject.Kind != SubjectAccount && controlPlane(role.perms) {
		return ErrControlPlanePersonal
	}
	actor, err := g.actorAssignments(ctx, tn, by)
	if err != nil {
		return err
	}
	if err := g.mustHold(ctx, tn, by, actor, role.perms, in.Roots); err != nil {
		return err
	}
	var exists int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.authz_assignments WHERE tenant_id = $1::uuid AND id = $2::uuid`, tn.String(), in.ID).Scan(&exists); err != nil {
		return fmt.Errorf("rbac: reading assignment: %w", err)
	}
	if exists > 0 {
		return ErrExists
	}
	var acct, conn, grp, pol *string
	switch in.Subject.Kind {
	case SubjectAccount:
		acct = &in.Subject.Account
	case SubjectGroup:
		conn, grp = &in.Subject.Connection, &in.Subject.Group
	case SubjectAutomation:
		pol = &in.Subject.Automation
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.authz_assignments (tenant_id, id, role_id, subject_kind, account_id, group_connection_id, group_guid, automation_policy_id, valid_from, valid_until, granted_by)
VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6::uuid, $7::uuid, $8::uuid, COALESCE($9::timestamptz, now()), $10::timestamptz, $11)`,
		tn.String(), in.ID, in.RoleID, string(in.Subject.Kind), acct, conn, grp, pol, in.ValidFrom, in.ValidUntil, string(by.Requester.ID)); err != nil {
		return fmt.Errorf("rbac: creating assignment: %w", err)
	}
	for i, r := range in.Roots {
		if _, err := tx.Exec(ctx, `INSERT INTO public.authz_assignment_roots (tenant_id, assignment_id, ordinal, is_exclude, root_kind, connection_id, root_guid)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7::uuid)`, tn.String(), in.ID, i, r.Exclude, string(r.Kind), r.Connection, r.GUID); err != nil {
			return fmt.Errorf("rbac: creating assignment root: %w", err)
		}
	}
	return nil
}

// Revoke ends an assignment. Revoking removes authority, so it needs no no-escalation proof, but the
// tenant-owner path is separate (OwnerAssignments guards the last owner).
func (g *Grants) Revoke(ctx context.Context, tx store.Tx, by authority.Chain, id string) error {
	if by.Validate() != nil || !accountIDRe.MatchString(id) {
		return ErrInvalid
	}
	tn, err := tenantOf(ctx, tx)
	if err != nil {
		return err
	}
	var owner bool
	err = tx.QueryRow(ctx, `SELECT r.role_name = $3 AND r.built_in FROM public.authz_assignments a
JOIN public.authz_roles r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
WHERE a.tenant_id = $1::uuid AND a.id = $2::uuid AND a.assignment_state = 'active'`, tn.String(), id, TenantOwnerRole).Scan(&owner)
	if store.IsNoRows(err) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("rbac: reading assignment: %w", err)
	}
	if owner {
		return ErrOwnerRole
	}
	if _, err := tx.Exec(ctx, `UPDATE public.authz_assignments SET assignment_state = 'revoked' WHERE tenant_id = $1::uuid AND id = $2::uuid`, tn.String(), id); err != nil {
		return fmt.Errorf("rbac: revoking assignment: %w", err)
	}
	return nil
}
