package rbac

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// grantsWithDirectory is grantsSetup with live root resolution (ouCSub sits under ouC) and an optional
// membership, so the no-escalation proof is exercised over directory scopes.
func grantsWithDirectory(t *testing.T, s *storetest.Server, m authz.Membership) (*env, *Grants, Root) {
	t.Helper()
	e, _, root := grantsSetup(t, s)
	src, err := NewStore(e.db)
	if err != nil {
		t.Fatal(err)
	}
	opts := []Option{withRoots(fakeRoots{})}
	if m != nil {
		opts = append(opts, WithMembership(m))
	}
	az, err := New(src, opts...)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGrants(az)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
		return g.CreateRole(ctx, tx, human(ownerAcct), roleA, "ou-desk", Tier2, []authz.Permission{"objects.user.disable"})
	}); err != nil {
		t.Fatal(err)
	}
	return e, g, root
}

func dirRoot(guid string, exclude bool) Root {
	return Root{Kind: OUSubtree, Connection: conn, GUID: guid, Exclude: exclude}
}

// DM-36.I1 over directory scopes (the CVE-2024-24409 class): containment is by live ancestry.
func TestGrantNoEscalationOverDirectoryScopes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, g, tenantRoot := grantsWithDirectory(t, s, nil)
		admin := human(adminAcct)
		sub := SubjectRef{Kind: SubjectAccount, Account: userAcct}
		// The admin holds ou-desk over ouC minus ouCSub, on connection conn.
		e.assign(t, e.a, "ou-desk", adminAcct, nil, "active", dirRoot(ouC, false), dirRoot(ouCSub, true))
		try := func(n int, roots ...Root) error {
			return e.do(t, func(ctx context.Context, tx store.Tx) error {
				return g.Grant(ctx, tx, admin, GrantInput{ID: gid(n), RoleID: roleA, Subject: sub, Roots: roots})
			})
		}
		if err := try(1, dirRoot(ouC, false), dirRoot(ouCSub, true)); err != nil {
			t.Fatalf("the same scope: %v", err)
		}
		for name, c := range map[string][]Root{
			"whole OU without the exclusion":      {dirRoot(ouC, false)},
			"a sibling OU":                        {dirRoot(ouB, false)},
			"another connection":                  {{Kind: OUSubtree, Connection: conn2, GUID: ouC}},
			"the Tier-0 scope root":               {{Kind: Tier0Scope, Connection: conn, GUID: conn}},
			"the tenant root":                     {tenantRoot},
			"the OU plus a root it does not hold": {dirRoot(ouC, false), dirRoot(ouCSub, true), dirRoot(ouB, false)},
		} {
			if err := try(2, c...); !errors.Is(err, ErrEscalation) {
				t.Errorf("%s: want ErrEscalation, got %v", name, err)
			}
		}
		// A child-only holder cannot grant the parent.
		e.assign(t, e.a, "ou-desk", userAcct, nil, "active", dirRoot(ouCSub, false))
		child := human(userAcct)
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.Grant(ctx, tx, child, GrantInput{ID: gid(3), RoleID: roleA, Subject: SubjectRef{Kind: SubjectAccount, Account: adminAcct}, Roots: []Root{dirRoot(ouC, false)}})
		}); !errors.Is(err, ErrEscalation) {
			t.Errorf("child scope granting the parent: %v", err)
		}
	})
}

type viaMembers struct{}

func (viaMembers) GroupsOf(context.Context, string, string) (authz.Groups, error) {
	return authz.Groups{Complete: true, Groups: []authz.Group{{Connection: conn, GUID: gGroup, Via: &authz.Derivation{Correlation: &authz.Correlation{}}}}}, nil
}

// A correlation-derived group grant never backs a grant (TM-D17 rule 5).
func TestDerivedGroupGrantDoesNotBackAGrant(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, g, _ := grantsWithDirectory(t, s, viaMembers{})
		owner := human(ownerAcct)
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.Grant(ctx, tx, owner, GrantInput{ID: gid(1), RoleID: roleA, Subject: SubjectRef{Kind: SubjectGroup, Connection: conn, Group: gGroup}, Roots: []Root{dirRoot(ouC, false)}})
		}); err != nil {
			t.Fatal(err)
		}
		err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.Grant(ctx, tx, human(userAcct), GrantInput{ID: gid(2), RoleID: roleA, Subject: SubjectRef{Kind: SubjectAccount, Account: adminAcct}, Roots: []Root{dirRoot(ouC, false)}})
		})
		if !errors.Is(err, ErrEscalation) {
			t.Fatalf("derived group grant backed a grant: %v", err)
		}
	})
}

// Two requests by one admin must not combine into an escalation: a role edit and a grant of that role
// serialise on the role row (DM-36.I1 under READ COMMITTED).
func TestRoleEditAndGrantSerialise(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, g, root := grantsSetup(t, s)
		owner, admin := human(ownerAcct), human(adminAcct)
		// A role with no holders: the admin holds reset_password only.
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, roleA, "race", Tier2, []authz.Permission{"objects.user.reset_password"})
		}); err != nil {
			t.Fatal(err)
		}
		grantErr := make(chan error, 1)
		editErr := e.do(t, func(ctx context.Context, tx store.Tx) error {
			// Edit first (no holders, so no proof), holding the role row lock until commit.
			if err := g.SetRolePermissions(ctx, tx, admin, roleA, []authz.Permission{"objects.user.reset_password", "objects.user.disable"}); err != nil {
				return err
			}
			go func() {
				grantErr <- e.do(t, func(ctx context.Context, tx store.Tx) error {
					return g.Grant(ctx, tx, admin, GrantInput{ID: gid(1), RoleID: roleA, Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}, Roots: []Root{root}})
				})
			}()
			select {
			case err := <-grantErr:
				t.Errorf("grant did not wait for the role edit: %v", err)
				grantErr <- err
			case <-time.After(500 * time.Millisecond): // blocked on the lock, as it must be
			}
			return nil
		})
		if editErr != nil {
			t.Fatalf("edit: %v", editErr)
		}
		if err := <-grantErr; !errors.Is(err, ErrEscalation) {
			t.Fatalf("grant after the edit committed: want ErrEscalation, got %v", err)
		}
		var n int
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.authz_assignments WHERE account_id = $1::uuid AND role_id = $2::uuid`, userAcct, roleA).Scan(&n)
		}); err != nil || n != 0 {
			t.Fatalf("subject holds the escalated role: %d %v", n, err)
		}
	})
}

// A lower tier cannot end, or strip, what it does not hold.
func TestRevokeAndNarrowingNeedTheHeldPrivileges(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, g, root := grantsSetup(t, s)
		owner, admin := human(ownerAcct), human(adminAcct)
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, roleA, "t1-ops", Tier1, []authz.Permission{"objects.user.disable", "objects.user.reset_password"})
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.Grant(ctx, tx, owner, GrantInput{ID: gid(1), RoleID: roleA, Subject: SubjectRef{Kind: SubjectAccount, Account: userAcct}, Roots: []Root{root}})
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Revoke(ctx, tx, admin, gid(1)) }); !errors.Is(err, ErrEscalation) {
			t.Errorf("revoking a higher assignment: %v", err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.SetRolePermissions(ctx, tx, admin, roleA, []authz.Permission{"objects.user.reset_password"})
		}); !errors.Is(err, ErrEscalation) {
			t.Errorf("stripping a permission the editor lacks: %v", err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Revoke(ctx, tx, owner, gid(1)) }); err != nil {
			t.Errorf("owner revoke: %v", err)
		}
	})
}

// A group assignment whose role became control-plane stays revocable (DM-36.I4 remediation).
func TestControlPlaneGroupAssignmentCanBeRevoked(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, g, root := grantsSetup(t, s)
		owner := human(ownerAcct)
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.CreateRole(ctx, tx, owner, roleA, "grp-role", Tier2, []authz.Permission{"objects.user.reset_password"})
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error {
			return g.Grant(ctx, tx, owner, GrantInput{ID: gid(1), RoleID: roleA, Subject: SubjectRef{Kind: SubjectGroup, Connection: conn, Group: gGroup}, Roots: []Root{root}})
		}); err != nil {
			t.Fatal(err)
		}
		// The permission becomes control-plane after the grant (an upgrade): inserted as the database
		// owner with the guard trigger off for the statement only.
		ctx := context.Background()
		for _, q := range []string{
			`ALTER TABLE public.authz_role_permissions DISABLE TRIGGER authz_role_permissions_control_plane`,
			`ALTER TABLE public.authz_role_permissions NO FORCE ROW LEVEL SECURITY`,
			`INSERT INTO public.authz_role_permissions (tenant_id, role_id, permission) VALUES ('` + e.a.String() + `', '` + roleA + `', 'rbac.role.manage')`,
			`ALTER TABLE public.authz_role_permissions FORCE ROW LEVEL SECURITY`,
			`ALTER TABLE public.authz_role_permissions ENABLE ALWAYS TRIGGER authz_role_permissions_control_plane`,
		} { // fixture text built from test constants, never input
			if err := e.owner(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
		if err := e.do(t, func(ctx context.Context, tx store.Tx) error { return g.Revoke(ctx, tx, owner, gid(1)) }); err != nil {
			t.Fatalf("revoke blocked by the trigger: %v", err)
		}
	})
}
