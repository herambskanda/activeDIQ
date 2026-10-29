package inventory_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	zInner  = "11111111-bbbb-4bbb-8bbb-111111111111"
	zMiddle = "22222222-bbbb-4bbb-8bbb-222222222222"
	zOuter  = "33333333-bbbb-4bbb-8bbb-333333333333"
	zUnsync = "44444444-bbbb-4bbb-8bbb-444444444444"

	zTech   = "aaaaaaaa-0000-4000-8000-0000000000a2"
	zRoleG  = "dddddddd-0000-4000-8000-0000000000a1" // the privileged role, granted only to the outer group
	zRoleT  = "dddddddd-0000-4000-8000-0000000000a2" // the technician's role: add_member only
	zAsgG   = "eeeeeeee-0000-4000-8000-0000000000a1"
	zAsgT   = "eeeeeeee-0000-4000-8000-0000000000a2"
	zAddMem = authz.Permission("objects.group.add_member")
	zDelete = authz.Permission("objects.user.disable")
)

type noFacts struct{}

func (noFacts) Facts(context.Context, authority.Pins, authority.FactsQuery) (authority.Facts, error) {
	return authority.Facts{}, errors.New("unexpected facts read")
}

type noBacking struct{}

func (noBacking) BackedBy(context.Context, tenant.ID, authority.TargetRef) (rbac.BackedAccounts, error) {
	return rbac.BackedAccounts{Complete: true}, nil
}

// TestReachWithRealAuthorizerEscalation runs the real rbac.Authorizer with the group guard over the
// Postgres Reach (TM-D18, AC2/AC1): inner ⊂ middle ⊂ outer, a privileged role granted only to outer.
func TestReachWithRealAuthorizerEscalation(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := authority.WithTenant(context.Background(), e.a.String())
		if _, err := e.populate(t, e.adA, t1, adGroup(zInner, -2147483646, false), adGroup(zMiddle, -2147483646, false, zInner),
			adGroup(zOuter, -2147483646, false, zMiddle)); err != nil {
			t.Fatal(err)
		}
		conn := string(e.adA)
		src, err := rbac.NewStore(e.db)
		if err != nil {
			t.Fatal(err)
		}
		reach := inventory.NewReach(inventory.NewGroups(e.db))
		// The containment test needs a root resolver, which only the backing guard option installs; the
		// connection-wide roots below read no facts and nothing here is a backing target.
		rr, err := rbac.NewRootResolver(noFacts{})
		if err != nil {
			t.Fatal(err)
		}
		az, err := rbac.New(src, rbac.WithGroupGuard(reach), rbac.WithBackingGuard(noBacking{}, rr))
		if err != nil {
			t.Fatal(err)
		}
		tech := authority.Chain{Requester: authority.Principal{ID: zTech, Kind: authority.Human}}
		// Roles and assignments are seeded as fixture SQL (the writer is rbac.Grants, whose own tests cover it).
		role := func(tx store.Tx, ctx context.Context, id, name string, perm authz.Permission) error {
			if _, err := tx.Exec(ctx, `INSERT INTO public.authz_roles (tenant_id, id, role_name, built_in, tier) VALUES ($1::uuid, $2::uuid, $3, false, 2)`,
				e.a.String(), id, name); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO public.authz_role_permissions (tenant_id, role_id, permission) VALUES ($1::uuid, $2::uuid, $3)`,
				e.a.String(), id, string(perm))
			return err
		}
		assign := func(tx store.Tx, ctx context.Context, id, roleID, kind string, acct, grp *string) error {
			if _, err := tx.Exec(ctx, `INSERT INTO public.authz_assignments (tenant_id, id, role_id, subject_kind, account_id, group_connection_id, group_guid, valid_from, granted_by)
				VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, $6::uuid, $7::uuid, now() - interval '2 hours', 'test')`,
				e.a.String(), id, roleID, kind, acct, map[bool]*string{true: &conn}[grp != nil], grp); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO public.authz_assignment_roots (tenant_id, assignment_id, ordinal, is_exclude, root_kind, connection_id, root_guid)
				VALUES ($1::uuid, $2::uuid, 0, false, 'entra_tenant', $3::uuid, $3::uuid)`, e.a.String(), id, conn)
			return err
		}
		outerG, techA := zOuter, zTech
		if err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) error {
			if err := role(tx, ctx, zRoleG, "privileged", zDelete); err != nil {
				return err
			}
			if err := role(tx, ctx, zRoleT, "adder", zAddMem); err != nil {
				return err
			}
			if err := assign(tx, ctx, zAsgG, zRoleG, "group", nil, &outerG); err != nil {
				return err
			}
			return assign(tx, ctx, zAsgT, zRoleT, "account", &techA, nil)
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		facts := authority.Facts{Exists: true, AncestorsComplete: true}
		target := func(g string) authority.TargetRef {
			return authority.TargetRef{Connection: conn, GUID: g, Class: "group"}
		}
		denied := func(err error, reason authz.Reason) bool {
			return err != nil && strings.Contains(err.Error(), string(reason))
		}
		// AC2: adding oneself to inner reaches outer through middle, whose role the technician lacks.
		if err := az.Authorize(ctx, tech, zAddMem, target(zInner), facts); !denied(err, rbac.ReasonGroupEscalation) {
			t.Fatalf("inner: want %s, got %v", rbac.ReasonGroupEscalation, err)
		}
		if err := az.Authorize(ctx, tech, zAddMem, target(zOuter), facts); !denied(err, rbac.ReasonGroupEscalation) {
			t.Fatalf("outer: want %s, got %v", rbac.ReasonGroupEscalation, err)
		}
		// AC1: a group the inventory has no active row for is incomplete, not "itself only".
		if err := az.Authorize(ctx, tech, zAddMem, target(zUnsync), facts); !denied(err, rbac.ReasonGroupIncomplete) {
			t.Fatalf("unsynced: want %s, got %v", rbac.ReasonGroupIncomplete, err)
		}
		// AC3: no invented chain.
		got, err := reach.ReachedFrom(context.Background(), e.a, target(zInner))
		if err != nil || !got.Complete || len(got.Groups) != 3 {
			t.Fatalf("reach: %v %+v", err, got)
		}
		for _, g := range got.Groups {
			if len(g.Path) != 0 {
				t.Errorf("path %v", g.Path)
			}
		}
	})
}
