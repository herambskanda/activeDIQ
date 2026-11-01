package rbac

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
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

// Valid reports whether exactly the fields of the subject's kind are set, as canonical UUIDs.
func (s SubjectRef) Valid() bool {
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

func tenantOf(ctx context.Context, tx store.Tx) (t tenant.ID, _ error) {
	var s string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(current_setting('app.tenant_id', true), '')`).Scan(&s); err != nil {
		return t, fmt.Errorf("rbac: reading tenant: %w", err)
	}
	t, err := tenantref.TenantFromText(s)
	if err != nil {
		return t, fmt.Errorf("rbac: reading tenant: %w", err)
	}
	return t, nil
}

type roleRow struct {
	name    string
	builtIn bool
	tier    int
	perms   []authz.Permission
}

// roleLock is the row lock taken on the role before its permissions and holders are read. A Set of a
// role's permissions and a Grant of the role serialise on it, so neither proves against a state the
// other is about to change (DM-36.I1 under READ COMMITTED).
type roleLock int

const (
	lockNone   roleLock = iota
	lockShare           // Grant: concurrent grants proceed, a permission edit waits
	lockUpdate          // permission edit: waits for in-flight grants, blocks new ones
)

const (
	sqlRole       = `SELECT role_name, built_in, tier FROM public.authz_roles WHERE tenant_id = $1::uuid AND id = $2::uuid`
	sqlRoleShare  = sqlRole + ` FOR SHARE`
	sqlRoleUpdate = sqlRole + ` FOR UPDATE`
)

func readRole(ctx context.Context, tx store.Tx, tn tenant.ID, id string, lock roleLock) (roleRow, error) {
	var r roleRow
	var row interface{ Scan(...any) error }
	switch lock { // three whole constants; nothing from the caller reaches the statement text
	case lockShare:
		row = tx.QueryRow(ctx, sqlRoleShare, tn.String(), id)
	case lockUpdate:
		row = tx.QueryRow(ctx, sqlRoleUpdate, tn.String(), id)
	default:
		row = tx.QueryRow(ctx, sqlRole, tn.String(), id)
	}
	err := row.Scan(&r.name, &r.builtIn, &r.tier)
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

// platformOnlyErr refuses a role that lists a platform-scope-only permission: a tenant or delegation
// grant cannot carry one (T-0250). It is ErrInvalid and authz.ErrInvalidGrant at once.
func platformOnlyErr(perms []authz.Permission) error {
	if slices.ContainsFunc(perms, authz.IsPlatformOnly) {
		return fmt.Errorf("%w: %w", ErrInvalid, authz.ErrInvalidGrant)
	}
	return nil
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
	if err := platformOnlyErr(perms); err != nil {
		return err
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
	if err := platformOnlyErr(perms); err != nil {
		return err
	}
	tn, err := tenantOf(ctx, tx)
	if err != nil {
		return err
	}
	role, err := readRole(ctx, tx, tn, roleID, lockUpdate)
	if err != nil {
		return err
	}
	if role.builtIn {
		return ErrBuiltInRole
	}
	if err := ValidateRoles([]Role{{Name: role.name, Tier: Tier(role.tier), Permissions: perms}}); err != nil {
		return ErrInvalid
	}
	var added, removed []authz.Permission
	for _, p := range perms {
		if !slices.Contains(role.perms, p) && !slices.Contains(added, p) {
			added = append(added, p)
		}
	}
	for _, p := range role.perms {
		if !slices.Contains(perms, p) {
			removed = append(removed, p)
		}
	}
	if len(added)+len(removed) > 0 {
		// Adding is a grant to every holder. Removing is a revocation from every holder, and a lower
		// tier must not strip what it does not hold (DM-36.I1 covers both, as Revoke does).
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
			if err := g.mustHold(ctx, tn, by, actor, append(slices.Clone(added), removed...), h.roots); err != nil {
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
		case OUOneLevel:
			// An include root only, and never a connection or tenant ID: the one-level match reads the
			// nearest parent, and the chain's last element is the connection.
			if r.Exclude || r.Connection == r.GUID {
				return false
			}
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
// taken, including a repeat of the identical grant (the caller treats a retry of a committed Action as done).
func (g *Grants) Grant(ctx context.Context, tx store.Tx, by authority.Chain, in GrantInput) error {
	return g.grant(ctx, tx, by, in, false)
}

// BootstrapPrincipal is the only system principal GrantBootstrap accepts: the install-time CLI that creates
// the first console account. Any other system chain (jobs, connectors, authn) is refused.
const BootstrapPrincipal authority.PrincipalID = "cli-account-init-local"

// GrantBootstrap is Grant for a host operator: the one path where the grantor is a system principal, not a
// person holding the privilege. It exists for the install-time CLI that creates the first console account
// (T-0783), which has no human to act as; it borrows no human's authority and the assignment's granted_by
// names the system principal. A chain that is not exactly the BootstrapPrincipal system principal is
// refused. It bypasses the grantor-holds-the-privilege check, so the static half of the guard is the
// fitness function tools/fitness/grantbootstrap (T-0808): no reference outside the CLI path.
func (g *Grants) GrantBootstrap(ctx context.Context, tx store.Tx, by authority.Chain, in GrantInput) error {
	if by.Validate() != nil || by.Requester.Kind != authority.System || by.Requester.ID != BootstrapPrincipal || len(by.Via) > 0 {
		return ErrActorNotDirect
	}
	return g.grant(ctx, tx, by, in, true)
}

func (g *Grants) grant(ctx context.Context, tx store.Tx, by authority.Chain, in GrantInput, bootstrap bool) error {
	if !accountIDRe.MatchString(in.ID) || !accountIDRe.MatchString(in.RoleID) || !in.Subject.Valid() ||
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
	role, err := readRole(ctx, tx, tn, in.RoleID, lockShare)
	if err != nil {
		return err
	}
	if err := CheckGrantable(RoleView{Name: role.name, BuiltIn: role.builtIn, Tier: Tier(role.tier), Permissions: role.perms}, in.Subject); err != nil {
		return err
	}
	if err := platformOnlyErr(role.perms); err != nil {
		return err
	}
	if !bootstrap {
		actor, err := g.actorAssignments(ctx, tn, by)
		if err != nil {
			return err
		}
		if err := g.mustHold(ctx, tn, by, actor, role.perms, in.Roots); err != nil {
			return err
		}
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

// Revoke ends an assignment. The actor must hold every privilege of the assignment over its scope (or be
// a personal tenant-owner), so a lower tier cannot end a higher tier's access. The tenant-owner path is
// separate (OwnerAssignments guards the last owner).
func (g *Grants) Revoke(ctx context.Context, tx store.Tx, by authority.Chain, id string) error {
	if by.Validate() != nil || !accountIDRe.MatchString(id) {
		return ErrInvalid
	}
	tn, err := tenantOf(ctx, tx)
	if err != nil {
		return err
	}
	av, err := g.Assignment(ctx, tx, id)
	if err != nil {
		return err
	}
	if !av.Active {
		return ErrNotFound
	}
	if av.Owner {
		return ErrOwnerRole
	}
	// Revoking is the denial-of-service and tier-crossing lever of the same family as granting: a
	// help-desk admin must not end a Tier-0 administrator's access. The actor must hold what the
	// assignment grants, over where it grants it (DM-36.I1), unless a personal tenant-owner.
	role, err := readRole(ctx, tx, tn, av.RoleID, lockNone)
	if err != nil {
		return err
	}
	actor, err := g.actorAssignments(ctx, tn, by)
	if err != nil {
		return err
	}
	if err := g.mustHold(ctx, tn, by, actor, role.perms, av.Roots); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE public.authz_assignments SET assignment_state = 'revoked' WHERE tenant_id = $1::uuid AND id = $2::uuid`, tn.String(), id); err != nil {
		return fmt.Errorf("rbac: revoking assignment: %w", err)
	}
	return nil
}

// ValidID reports whether s is the canonical UUID text every row ID and directory GUID here uses.
func ValidID(s string) bool { return accountIDRe.MatchString(s) }

// RoleView is a role as stored.
type RoleView struct {
	Name        string
	BuiltIn     bool
	Tier        Tier
	Permissions []authz.Permission
}

// AssignmentView is an assignment as stored.
type AssignmentView struct {
	RoleID   string
	RoleName string
	Owner    bool // the built-in tenant-owner role
	Active   bool
	Subject  SubjectRef
	Roots    []Root
}

// CheckGrantable is the actor-free part of a grant, so a Plan can refuse it before anyone is asked:
// tenant-owner has its own path, and control-plane authority is personal (DM-36.I4).
func CheckGrantable(role RoleView, subject SubjectRef) error {
	if role.BuiltIn && role.Name == TenantOwnerRole {
		return ErrOwnerRole
	}
	if subject.Kind != SubjectAccount && controlPlane(role.Permissions) {
		return ErrControlPlanePersonal
	}
	return nil
}

// Role reads a role of the transaction's tenant.
func (g *Grants) Role(ctx context.Context, tx store.Tx, id string) (RoleView, error) {
	if !ValidID(id) {
		return RoleView{}, ErrInvalid
	}
	tn, err := tenantOf(ctx, tx)
	if err != nil {
		return RoleView{}, err
	}
	r, err := readRole(ctx, tx, tn, id, lockNone)
	if err != nil {
		return RoleView{}, err
	}
	return RoleView{Name: r.name, BuiltIn: r.builtIn, Tier: Tier(r.tier), Permissions: r.perms}, nil
}

// Assignment reads an assignment of the transaction's tenant, whatever its state.
func (g *Grants) Assignment(ctx context.Context, tx store.Tx, id string) (AssignmentView, error) {
	if !ValidID(id) {
		return AssignmentView{}, ErrInvalid
	}
	tn, err := tenantOf(ctx, tx)
	if err != nil {
		return AssignmentView{}, err
	}
	var v AssignmentView
	var kind, state string
	var acct, conn, grp, pol *string
	err = tx.QueryRow(ctx, `SELECT a.role_id::text, r.role_name, r.role_name = $3 AND r.built_in, a.assignment_state, a.subject_kind,
a.account_id::text, a.group_connection_id::text, a.group_guid::text, a.automation_policy_id::text
FROM public.authz_assignments a JOIN public.authz_roles r ON r.tenant_id = a.tenant_id AND r.id = a.role_id
WHERE a.tenant_id = $1::uuid AND a.id = $2::uuid`, tn.String(), id, TenantOwnerRole).
		Scan(&v.RoleID, &v.RoleName, &v.Owner, &state, &kind, &acct, &conn, &grp, &pol)
	if store.IsNoRows(err) {
		return v, ErrNotFound
	} else if err != nil {
		return v, fmt.Errorf("rbac: reading assignment: %w", err)
	}
	v.Active = state == "active"
	v.Subject = SubjectRef{Kind: SubjectKind(kind)}
	if acct != nil {
		v.Subject.Account = *acct
	}
	if conn != nil {
		v.Subject.Connection = *conn
	}
	if grp != nil {
		v.Subject.Group = *grp
	}
	if pol != nil {
		v.Subject.Automation = *pol
	}
	v.Roots, err = readRoots(ctx, tx, tn, id)
	return v, err
}
