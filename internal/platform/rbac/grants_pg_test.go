package rbac

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const (
	ownerAcct = "aaaaaaaa-0000-4000-8000-000000000001"
	adminAcct = "aaaaaaaa-0000-4000-8000-000000000002"
	userAcct  = "aaaaaaaa-0000-4000-8000-000000000003"
	gGroup    = "bbbbbbbb-0000-4000-8000-000000000001"
	gPolicy   = "cccccccc-0000-4000-8000-000000000001"
	roleA     = "dddddddd-0000-4000-8000-000000000001"
	roleB     = "dddddddd-0000-4000-8000-000000000002"
)

func gid(n int) string { return "eeeeeeee-0000-4000-8000-00000000000" + string(rune('0'+n)) }

func (e *env) roleID(t *testing.T, name string) string {
	t.Helper()
	var id string
	if err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM public.authz_roles WHERE tenant_id = $1::uuid AND role_name = $2`, e.a.String(), name).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func grantsSetup(t *testing.T, s *storetest.Server) (*env, *Grants, Root) {
	t.Helper()
	e := setup(t, s)
	if err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error { return SeedBuiltIns(ctx, tx, e.a) }); err != nil {
		t.Fatal(err)
	}
	root := Root{Kind: TenantStore, Connection: e.a.String(), GUID: e.a.String()}
	e.assign(t, e.a, TenantOwnerRole, ownerAcct, nil, "active", root)
	// adminAcct holds the help-desk permission over the whole tenant store, and nothing else.
	e.assign(t, e.a, "helpdesk-operator", adminAcct, nil, "active", root)
	src, err := NewStore(e.db)
	if err != nil {
		t.Fatal(err)
	}
	az, err := New(src)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGrants(az)
	if err != nil {
		t.Fatal(err)
	}
	return e, g, root
}

func (e *env) do(t *testing.T, f func(ctx context.Context, tx store.Tx) error) error {
	t.Helper()
	return e.exec(t, e.a, f)
}

func TestGrantsRoleLifecycleAndNoEscalation(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, g, root := grantsSetup(t, s)
		owner, admin := human(ownerAcct), human(adminAcct)
		perms := []authz.Permission{"objects.user.reset_password", "objects.user.disable"}

		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, roleA, "desk-plus", Tier2, perms)
		}); err != nil {
			t.Fatalf("create role: %v", err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, roleB, "desk-plus", Tier2, perms)
		}); !errors.Is(err, ErrExists) {
			t.Errorf("duplicate name: %v", err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, roleB, "t0", Tier2, []authz.Permission{"inventory.tier0_designation.manage"})
		}); !errors.Is(err, ErrInvalid) {
			t.Errorf("tier-2 role with a tier-0 permission: %v", err)
		}

		// The help-desk operator holds reset_password only: it cannot hand out desk-plus (needs disable).
		in := GrantInput{ID: gid(1), RoleID: roleA, Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}, Roots: []Root{root}}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Grant(ctx, tx, admin, in) }); !errors.Is(err, ErrEscalation) {
			t.Fatalf("escalating grant: want ErrEscalation, got %v", err)
		}
		// ...but it can hand out the role it holds, to a person, a group and an automation policy.
		hd := e.roleID(t, "helpdesk-operator")
		for i, sub := range []SubjectRef{
			{Kind: SubjectAccount, Account: userAcct},
			{Kind: SubjectGroup, Connection: conn, Group: gGroup},
			{Kind: SubjectAutomation, Automation: gPolicy},
		} {
			in := GrantInput{ID: gid(2 + i), RoleID: hd, Subject: sub, Roots: []Root{root}}
			if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Grant(ctx, tx, admin, in) }); err != nil {
				t.Fatalf("grant held role to %s: %v", sub.Kind, err)
			}
			// A repeat of the same ID is not a second grant.
			if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Grant(ctx, tx, admin, in) }); !errors.Is(err, ErrExists) {
				t.Errorf("repeat grant: %v", err)
			}
		}
		// The owner can hand out desk-plus.
		in = GrantInput{ID: gid(1), RoleID: roleA, Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}, Roots: []Root{root}}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Grant(ctx, tx, owner, in) }); err != nil {
			t.Fatalf("owner grant: %v", err)
		}

		// Tenant-owner goes through the owner path; control-plane is personal; shapes are validated.
		owRole := e.roleID(t, TenantOwnerRole)
		for name, c := range map[string]struct {
			in   GrantInput
			by   authority.Chain
			want error
		}{
			"owner role":    {GrantInput{ID: gid(7), RoleID: owRole, Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}, Roots: []Root{root}}, owner, ErrOwnerRole},
			"no roots":      {GrantInput{ID: gid(7), RoleID: hd, Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}}, owner, ErrInvalid},
			"other tenant":  {GrantInput{ID: gid(7), RoleID: hd, Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}, Roots: []Root{{Kind: TenantStore, Connection: e.b.String(), GUID: e.b.String()}}}, owner, ErrInvalid},
			"two subjects":  {GrantInput{ID: gid(7), RoleID: hd, Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct, Group: gGroup}, Roots: []Root{root}}, owner, ErrInvalid},
			"missing role":  {GrantInput{ID: gid(7), RoleID: gid(9), Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}, Roots: []Root{root}}, owner, ErrNotFound},
			"token in path": {GrantInput{ID: gid(7), RoleID: hd, Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}, Roots: []Root{root}}, authority.Chain{Requester: owner.Requester, Via: []authority.Principal{{Kind: authority.APIToken, ID: "tok"}}}, ErrActorNotDirect},
			"no actor":      {GrantInput{ID: gid(7), RoleID: hd, Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}, Roots: []Root{root}}, human("nobody"), ErrEscalation},
		} {
			err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Grant(ctx, tx, c.by, c.in) })
			if !errors.Is(err, c.want) {
				t.Errorf("%s: want %v, got %v", name, c.want, err)
			}
		}

		// A role with a control-plane permission goes to an account only.
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, gid(5), "access-admin", Tier1, []authz.Permission{"rbac.assignment.grant"})
		}); err != nil {
			t.Fatal(err)
		}
		for _, sub := range []SubjectRef{{Kind: SubjectGroup, Connection: conn, Group: gGroup}, {Kind: SubjectAutomation, Automation: gPolicy}} {
			in := GrantInput{ID: gid(6), RoleID: gid(5), Subject: sub, Roots: []Root{root}}
			if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Grant(ctx, tx, owner, in) }); !errors.Is(err, ErrControlPlanePersonal) {
				t.Errorf("control-plane role to %s: %v", sub.Kind, err)
			}
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.Grant(ctx, tx, owner, GrantInput{ID: gid(6), RoleID: gid(5), Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}, Roots: []Root{root}})
		}); err != nil {
			t.Errorf("control-plane role to an account by the owner: %v", err)
		}

		// Role edits: built-ins are read-only; adding needs the proof; the group-held role may not gain
		// control-plane permissions; removal narrows.
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.SetRolePermissions(ctx, tx, owner, hd, []authz.Permission{"objects.user.delete"})
		}); !errors.Is(err, ErrBuiltInRole) {
			t.Errorf("built-in edit: %v", err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.SetRolePermissions(ctx, tx, admin, roleA, append(slices.Clone(perms), "objects.user.delete"))
		}); !errors.Is(err, ErrEscalation) {
			t.Errorf("adding a permission the editor lacks: %v", err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.SetRolePermissions(ctx, tx, owner, roleA, append(slices.Clone(perms), "objects.user.delete"))
		}); err != nil {
			t.Errorf("owner adds a permission: %v", err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.SetRolePermissions(ctx, tx, owner, roleA, perms[:1])
		}); err != nil {
			t.Errorf("removing permissions: %v", err)
		}
		// A role held by a group gains no control-plane permission.
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, gid(8), "grp-role", Tier2, []authz.Permission{"objects.user.reset_password"})
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.Grant(ctx, tx, owner, GrantInput{ID: gid(0), RoleID: gid(8), Subject: SubjectRef{Kind: SubjectGroup, Connection: conn, Group: gGroup}, Roots: []Root{root}})
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.SetRolePermissions(ctx, tx, owner, gid(8), []authz.Permission{"objects.user.reset_password", "rbac.role.manage"})
		}); !errors.Is(err, ErrControlPlanePersonal) {
			t.Errorf("control-plane permission into a group-held role: %v", err)
		}

		// Revoke: ends the grant; unknown and owner assignments are refused.
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Revoke(ctx, tx, admin, gid(4)) }); err != nil {
			t.Errorf("revoke: %v", err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Revoke(ctx, tx, admin, gid(4)) }); !errors.Is(err, ErrNotFound) {
			t.Errorf("revoke twice: %v", err)
		}
		var ownerAssign string
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT id::text FROM public.authz_assignments WHERE account_id = $1::uuid`, ownerAcct).Scan(&ownerAssign)
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Revoke(ctx, tx, owner, ownerAssign) }); !errors.Is(err, ErrOwnerRole) {
			t.Errorf("revoke owner: %v", err)
		}

		// The store reads the three subject kinds back for the right subjects.
		src, _ := NewStore(e.db)
		now := time.Now()
		got, err := src.SubjectAssignments(context.Background(), e.a, Subjects{Groups: []authz.Group{{Connection: conn, GUID: gGroup}}}, now, false)
		if err != nil || len(got) != 2 || got[0].Subject != SubjectGroup {
			t.Errorf("group read: %d %v", len(got), err)
		}
		got, err = src.SubjectAssignments(context.Background(), e.a, Subjects{Automation: gPolicy}, now, false)
		if err != nil || len(got) != 0 { // its only grant was revoked above
			t.Errorf("automation read after revoke: %d %v", len(got), err)
		}
	})
}

// The database refuses what the Go layer refuses, whoever writes (DM-36.I4).
func TestControlPlaneGuardAndSubjectShapeInDatabase(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, g, root := grantsSetup(t, s)
		owner := human(ownerAcct)
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, gid(5), "access-admin", Tier1, []authz.Permission{"rbac.assignment.grant"})
		}); err != nil {
			t.Fatal(err)
		}
		ins := func(role, kind, _ string) error {
			return e.do(t, func(ctx context.Context, tx store.Tx) error {
				var err error
				if kind == "group" {
					_, err = tx.Exec(ctx, `INSERT INTO public.authz_assignments (tenant_id, role_id, subject_kind, group_connection_id, group_guid, granted_by)
SELECT $1::uuid, id, 'group', $3::uuid, $4::uuid, 'test' FROM public.authz_roles WHERE tenant_id = $1::uuid AND role_name = $2`, e.a.String(), role, conn, gGroup)
				} else {
					_, err = tx.Exec(ctx, `INSERT INTO public.authz_assignments (tenant_id, role_id, subject_kind, automation_policy_id, granted_by)
SELECT $1::uuid, id, 'automation', $3::uuid, 'test' FROM public.authz_roles WHERE tenant_id = $1::uuid AND role_name = $2`, e.a.String(), role, gPolicy)
				}
				return err
			})
		}
		_ = root
		for _, c := range []struct{ role, kind, extra string }{
			{TenantOwnerRole, "group", "group_connection_id, group_guid"},
			{TenantOwnerRole, "automation", "automation_policy_id"},
			{"access-admin", "group", "group_connection_id, group_guid"},
		} {
			if err := ins(c.role, c.kind, c.extra); store.SQLState(err) != "AD403" {
				t.Errorf("%s to %s: want AD403, got %v", c.role, c.kind, err)
			}
		}
		if err := ins("helpdesk-operator", "group", "group_connection_id, group_guid"); err != nil {
			t.Errorf("help-desk to a group: %v", err)
		}
		// Shape: a group row cannot also carry an account; a tenant root names the tenant.
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.authz_assignments (tenant_id, role_id, subject_kind, account_id, group_guid, granted_by)
SELECT $1::uuid, id, 'group', $2::uuid, $2::uuid, 'test' FROM public.authz_roles WHERE tenant_id = $1::uuid AND role_name = 'helpdesk-operator'`, e.a.String(), userAcct)
			return err
		}); err == nil {
			t.Error("mixed subject shape accepted")
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.authz_assignment_roots (tenant_id, assignment_id, ordinal, is_exclude, root_kind, connection_id, root_guid)
SELECT $1::uuid, id, 9, false, 'tenant', $2::uuid, $2::uuid FROM public.authz_assignments WHERE tenant_id = $1::uuid LIMIT 1`, e.a.String(), userAcct)
			return err
		}); err == nil {
			t.Error("tenant root naming another id accepted")
		}
	})
}

// The SQL trigger's prefixes and authz.NeverCrosses are one list.
func TestGuardPrefixesMatchNeverCrosses(t *testing.T) {
	for _, p := range []string{"rbac.x", "authz.x", "delegation.x", "scope.x", "connections.x", "tenant.x", "inventory.tier0_x"} {
		if !authz.NeverCrosses(authz.Permission(p)) {
			t.Errorf("%s: trigger prefix not in NeverCrosses", p)
		}
	}
	for _, p := range []string{"objects.user.delete", "inventory.user.read", "reports.run"} {
		if authz.NeverCrosses(authz.Permission(p)) {
			t.Errorf("%s: NeverCrosses but not guarded by the trigger", p)
		}
	}
}

// T-0250 (TM-D1): a role listing a platform-scope-only permission can be neither created, edited to
// include one, nor granted at tenant or delegation scope, even by the tenant owner.
func TestGrantsRefusePlatformOnlyPermission(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, g, _ := grantsSetup(t, s)
		owner := human(ownerAcct)
		const p authz.Permission = "connections.tier0_override.acknowledge"
		err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, roleA, "override", Tier1, []authz.Permission{p})
		})
		if !errors.Is(err, authz.ErrInvalidGrant) || !errors.Is(err, ErrInvalid) {
			t.Fatalf("create role: %v, want ErrInvalidGrant", err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, roleB, "plain", Tier2, []authz.Permission{"objects.user.reset_password"})
		}); err != nil {
			t.Fatal(err)
		}
		err = e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.SetRolePermissions(ctx, tx, owner, roleB, []authz.Permission{"objects.user.reset_password", p})
		})
		if !errors.Is(err, authz.ErrInvalidGrant) {
			t.Fatalf("set permissions: %v, want ErrInvalidGrant", err)
		}
	})
}
