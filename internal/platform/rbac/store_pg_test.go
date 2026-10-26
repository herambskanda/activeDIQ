package rbac

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type env struct {
	db   *store.DB
	a, b tenant.ID
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	e := &env{a: tenanttest.Seed(t, d.ExecOwner, "A"), b: tenanttest.Seed(t, d.ExecOwner, "B")}
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e.db = db
	return e
}

func (e *env) exec(t *testing.T, ten tenant.ID, f func(ctx context.Context, tx store.Tx) error) error {
	t.Helper()
	return e.db.WithTenant(context.Background(), ten, f)
}

// assign grants role to acct in ten with the roots, returning the assignment ID.
func (e *env) assign(t *testing.T, ten tenant.ID, role, account string, until *time.Time, state string, roots ...Root) {
	t.Helper()
	err := e.exec(t, ten, func(ctx context.Context, tx store.Tx) error {
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO public.authz_assignments (tenant_id, account_id, role_id, valid_from, valid_until, granted_by, assignment_state)
SELECT $1::uuid, $2::uuid, r.id, now() - interval '2 hours', $4, 'test', $5 FROM public.authz_roles r WHERE r.tenant_id = $1::uuid AND r.role_name = $3 RETURNING id::text`,
			ten.String(), account, role, until, state).Scan(&id); err != nil {
			return err
		}
		for i, r := range roots {
			if _, err := tx.Exec(ctx, `INSERT INTO public.authz_assignment_roots (tenant_id, assignment_id, ordinal, is_exclude, root_kind, connection_id, root_guid)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7::uuid)`, ten.String(), id, i, r.Exclude, string(r.Kind), r.Connection, r.GUID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Acceptance 1: a grant in the RBAC store is what the real Authorizer decides on, including when it
// is called from inside the runner's own tenant transaction.
func TestAuthorizerDecidesOnPersistedGrants(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		for _, ten := range []tenant.ID{e.a, e.b} {
			if err := e.exec(t, ten, func(ctx context.Context, tx store.Tx) error { return SeedBuiltIns(ctx, tx, ten) }); err != nil {
				t.Fatal(err)
			}
		}
		// Seeding is idempotent.
		if err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error { return SeedBuiltIns(ctx, tx, e.a) }); err != nil {
			t.Fatal(err)
		}
		other := "88888888-8888-4888-8888-888888888888"
		e.assign(t, e.a, "tier0-administrator", acct, nil, "active", Root{Kind: Tier0Scope, Connection: conn, GUID: conn})
		e.assign(t, e.a, "platform-administrator", other, nil, "active", Root{Kind: EntraTenant, Connection: conn, GUID: conn})
		// Same account in tenant B holds a Tier-0 grant too, but it is B's.
		e.assign(t, e.b, "tier0-administrator", other, nil, "active", Root{Kind: Tier0Scope, Connection: conn, GUID: conn})
		// Expired and revoked grants hold nothing.
		past := time.Now().Add(-time.Hour)
		e.assign(t, e.a, "tier0-administrator", "77777777-7777-4777-8777-777777777777", &past, "active", Root{Kind: Tier0Scope, Connection: conn, GUID: conn})
		e.assign(t, e.a, "tier0-administrator", "66666666-6666-4666-8666-666666666666", nil, "revoked", Root{Kind: Tier0Scope, Connection: conn, GUID: conn})

		src, err := NewStore(e.db)
		if err != nil {
			t.Fatal(err)
		}
		az, err := New(src)
		if err != nil {
			t.Fatal(err)
		}
		facts := authority.Facts{Exists: true}
		check := func(ctx context.Context, ten tenant.ID, who string, want bool) {
			t.Helper()
			err := az.Authorize(authority.WithTenant(ctx, ten.String()), human(who), manage, scopeTarget, facts)
			if want && err != nil {
				t.Errorf("%s in %s: %v", who, ten, err)
			}
			if !want && !errors.Is(err, ErrDenied) {
				t.Errorf("%s in %s: want denied, got %v", who, ten, err)
			}
		}
		check(context.Background(), e.a, acct, true)
		check(context.Background(), e.a, other, false) // connection-wide platform admin: denied at Tier-0 scope
		check(context.Background(), e.a, "77777777-7777-4777-8777-777777777777", false)
		check(context.Background(), e.a, "66666666-6666-4666-8666-666666666666", false)
		check(context.Background(), e.b, acct, false) // tenant isolation
		check(context.Background(), e.b, other, true)
		check(context.Background(), e.a, "not-a-uuid", false)
		// From inside a tenant transaction (the inline runner path) it still decides, in its own read.
		if err := e.exec(t, e.a, func(ctx context.Context, _ store.Tx) error {
			check(ctx, e.a, acct, true)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// The platform admin's connection-wide root does cover an object it reaches.
		obj := authority.TargetRef{Connection: conn, GUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Class: "user", NC: "nc"}
		err = az.Authorize(authority.WithTenant(context.Background(), e.a.String()), human(other), "objects.user.delete", obj,
			authority.Facts{Exists: true, Ancestors: []string{ouA}, AncestorsComplete: true})
		if err != nil {
			t.Errorf("connection-wide admin over an object: %v", err)
		}
	})
}

// TM-D19 rule 5 reads the backed side with PendingOrActive: scheduled grants count, revoked and
// expired ones do not; the actor-side read stays current-only.
func TestPendingOrActiveIncludesScheduledGrants(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		if err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error { return SeedBuiltIns(ctx, tx, e.a) }); err != nil {
			t.Fatal(err)
		}
		root := Root{Kind: EntraTenant, Connection: conn, GUID: conn}
		const sched, revoked, expired, current = "55555555-5555-4555-8555-555555555551", "55555555-5555-4555-8555-555555555552", "55555555-5555-4555-8555-555555555553", "55555555-5555-4555-8555-555555555554"
		past := time.Now().Add(-time.Hour)
		e.assign(t, e.a, "platform-administrator", sched, nil, "active", root)
		e.assign(t, e.a, "platform-administrator", revoked, nil, "revoked", root)
		e.assign(t, e.a, "platform-administrator", expired, &past, "active", root)
		e.assign(t, e.a, "platform-administrator", current, nil, "active", root)
		if err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.authz_assignments SET valid_from = now() + interval '1 day' WHERE tenant_id = $1::uuid AND account_id = $2::uuid`, e.a.String(), sched)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		src, err := NewStore(e.db)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		for acct, want := range map[string][2]int{sched: {0, 1}, revoked: {0, 0}, expired: {0, 0}, current: {1, 1}} {
			cur, err := src.Assignments(context.Background(), e.a, acct, now)
			if err != nil {
				t.Fatal(err)
			}
			pend, err := src.PendingOrActive(context.Background(), e.a, acct, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(cur) != want[0] || len(pend) != want[1] {
				t.Errorf("%s: current %d (want %d), pending-or-active %d (want %d)", acct, len(cur), want[0], len(pend), want[1])
			}
		}
	})
}

// Acceptance 4, at the schema: a Tier-2 role cannot be given the permission, in either order.
func TestSchemaRefusesTier0PermissionOnATier2Role(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		var role string
		err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `INSERT INTO public.authz_roles (tenant_id, role_name, tier) VALUES ($1::uuid, 'desk', 2) RETURNING id::text`, e.a.String()).Scan(&role)
		})
		if err != nil {
			t.Fatal(err)
		}
		err = e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.authz_role_permissions (tenant_id, role_id, permission) VALUES ($1::uuid, $2::uuid, 'inventory.tier0_designation.manage')`, e.a.String(), role)
			return err
		})
		if err == nil {
			t.Fatal("a Tier-2 role took the Tier-0 scope permission")
		}
		// A tier-1 role may hold it, but cannot then be moved to tier 2.
		err = e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE public.authz_roles SET tier = 1 WHERE tenant_id = $1::uuid AND id = $2::uuid`, e.a.String(), role); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO public.authz_role_permissions (tenant_id, role_id, permission) VALUES ($1::uuid, $2::uuid, 'inventory.tier0_designation.manage')`, e.a.String(), role); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE public.authz_roles SET tier = 2 WHERE tenant_id = $1::uuid AND id = $2::uuid`, e.a.String(), role)
			return err
		})
		if err == nil {
			t.Fatal("a role holding the permission was moved to Tier-2")
		}
	})
}
