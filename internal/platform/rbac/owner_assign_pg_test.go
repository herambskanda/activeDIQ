package rbac

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type ownerSink struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (s *ownerSink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, ev)
	return nil
}

func (s *ownerSink) kinds() []audit.Kind {
	s.mu.Lock()
	defer s.mu.Unlock()
	var k []audit.Kind
	for _, e := range s.evs {
		k = append(k, e.Kind)
	}
	return k
}

// inactive lists accounts that are not active; every other account counts as active.
type inactive map[string]bool

func (i inactive) CountActive(_ context.Context, _ store.Tx, _ tenant.ID, ids []string) (int, error) {
	n := 0
	for _, id := range ids {
		if !i[id] {
			n++
		}
	}
	return n, nil
}

const (
	owner1 = "11111111-1111-4111-8111-111111111111"
	owner2 = "22222222-2222-4222-8222-222222222222"
)

var admin = authority.Chain{Requester: authority.Principal{ID: "human-1", Kind: authority.Human}}

func ownerSetup(t *testing.T, s *storetest.Server, act ActiveAccounts) (*env, *OwnerAssignments, *ownerSink) {
	t.Helper()
	e := setup(t, s)
	if err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error { return SeedBuiltIns(ctx, tx, e.a) }); err != nil {
		t.Fatal(err)
	}
	snk := &ownerSink{}
	oa, err := NewOwnerAssignments(e.db, snk, act)
	if err != nil {
		t.Fatal(err)
	}
	return e, oa, snk
}

func (e *env) owners(t *testing.T) []string {
	t.Helper()
	var out []string
	if err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = Owners{}.TenantOwners(ctx, tx, e.a)
		return
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// Acceptance 1: seeding creates a read-only built-in tenant-owner role.
func TestSeedCreatesReadOnlyTenantOwnerRole(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, _, _ := ownerSetup(t, s, inactive{})
		var builtIn bool
		var perms int
		if err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT built_in FROM public.authz_roles WHERE tenant_id = $1::uuid AND role_name = 'tenant-owner'`, e.a.String()).Scan(&builtIn); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.authz_role_permissions p JOIN public.authz_roles r ON r.tenant_id = p.tenant_id AND r.id = p.role_id WHERE r.role_name = 'tenant-owner'`).Scan(&perms)
		}); err != nil || !builtIn || perms != 0 {
			t.Fatalf("role: builtIn=%v perms=%d err=%v", builtIn, perms, err)
		}
		// Read-only: no rename, no new permission, and the name is reserved.
		for name, sql := range map[string]string{
			"rename":     `UPDATE public.authz_roles SET role_name = 'x' WHERE role_name = 'tenant-owner'`,
			"unbuiltin":  `UPDATE public.authz_roles SET built_in = false WHERE role_name = 'tenant-owner'`,
			"retier":     `UPDATE public.authz_roles SET tier = 2 WHERE role_name = 'tenant-owner'`,
			"permission": `INSERT INTO public.authz_role_permissions (tenant_id, role_id, permission) SELECT tenant_id, id, 'objects.user.delete' FROM public.authz_roles WHERE role_name = 'tenant-owner'`,
			"steal-name": `UPDATE public.authz_roles SET role_name = 'tenant-owner' WHERE role_name = 'helpdesk-operator'`,
		} {
			err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error { _, err := tx.Exec(ctx, sql); return err })
			if store.SQLState(err) != "AD403" {
				t.Errorf("%s: want AD403, got %v", name, err)
			}
		}
		// Re-seeding is a no-op.
		if err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error { return SeedBuiltIns(ctx, tx, e.a) }); err != nil {
			t.Fatal(err)
		}
		// A custom role cannot take the name in a tenant that has not been seeded.
		err := e.exec(t, e.b, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.authz_roles (tenant_id, role_name, built_in, tier) VALUES ($1::uuid, 'tenant-owner', false, 2)`, e.b.String())
			return err
		})
		if store.SQLState(err) != "AD403" {
			t.Errorf("custom tenant-owner role: want AD403, got %v", err)
		}
	})
}

// Acceptance 3: an owner assignment cannot expire or start later, by any writer.
func TestOwnerAssignmentCannotBeTimeBounded(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, oa, _ := ownerSetup(t, s, inactive{})
		for name, sql := range map[string]string{
			"valid_until": `INSERT INTO public.authz_assignments (tenant_id, account_id, role_id, valid_until, granted_by)
SELECT tenant_id, '` + owner1 + `', id, now() + interval '1 second', 'x' FROM public.authz_roles WHERE role_name = 'tenant-owner'`,
			"future start": `INSERT INTO public.authz_assignments (tenant_id, account_id, role_id, valid_from, granted_by)
SELECT tenant_id, '` + owner1 + `', id, now() + interval '1 hour', 'x' FROM public.authz_roles WHERE role_name = 'tenant-owner'`,
		} {
			err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error { _, err := tx.Exec(ctx, sql); return err })
			if store.SQLState(err) != "AD403" {
				t.Errorf("%s: want AD403, got %v", name, err)
			}
		}
		// ...nor can a granted one be edited to expire.
		if _, err := oa.Grant(context.Background(), e.a, owner1, admin); err != nil {
			t.Fatal(err)
		}
		err := e.exec(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.authz_assignments SET valid_until = now() + interval '1 second' WHERE account_id = $1::uuid`, owner1)
			return err
		})
		if store.SQLState(err) != "AD403" {
			t.Errorf("update to expire: want AD403, got %v", err)
		}
		if got := e.owners(t); len(got) != 1 || got[0] != owner1 {
			t.Fatalf("owners = %v", got)
		}
	})
}

// Acceptance 2 and 5: grant and revoke audit; the last owner cannot be revoked.
func TestGrantRevokeAndLastOwner(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		inact := inactive{}
		e, oa, snk := ownerSetup(t, s, inact)
		id1, err := oa.Grant(ctx, e.a, owner1, admin)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oa.Grant(ctx, e.a, owner1, admin); !errors.Is(err, ErrAlreadyOwner) {
			t.Fatalf("second grant: %v", err)
		}
		if err := oa.Revoke(ctx, e.a, id1, admin); !errors.Is(err, ErrLastOwner) {
			t.Fatalf("revoke of the only owner: %v", err)
		}
		if got := e.owners(t); len(got) != 1 {
			t.Fatalf("owner was removed: %v", got)
		}
		id2, err := oa.Grant(ctx, e.a, owner2, admin)
		if err != nil {
			t.Fatal(err)
		}
		// owner2's account is disabled: owner1 is again the last active owner.
		inact[owner2] = true
		if err := oa.Revoke(ctx, e.a, id1, admin); !errors.Is(err, ErrLastOwner) {
			t.Fatalf("revoke with only a disabled co-owner: %v", err)
		}
		inact[owner2] = false
		if err := oa.Revoke(ctx, e.a, id1, admin); err != nil {
			t.Fatal(err)
		}
		if err := oa.Revoke(ctx, e.a, id1, admin); !errors.Is(err, ErrOwnerNotFound) {
			t.Fatalf("revoke twice: %v", err)
		}
		if got := e.owners(t); len(got) != 1 || got[0] != owner2 {
			t.Fatalf("owners = %v", got)
		}
		_ = id2
		want := []audit.Kind{KindOwnerGranted, KindOwnerRevokeRefused, KindOwnerGranted, KindOwnerRevokeRefused, KindOwnerRevoked}
		got := snk.kinds()
		if len(got) != len(want) {
			t.Fatalf("audit kinds = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("audit kinds = %v, want %v", got, want)
			}
		}
		if ev := snk.evs[1]; ev.Outcome != audit.Denied || ev.Reason != "last_tenant_owner" || ev.Target.GUID != owner1 {
			t.Errorf("refusal event = %+v", ev)
		}
		if ev := snk.evs[0]; ev.Outcome != audit.Success || ev.Actor.Requester.ID != "human-1" || ev.Kind != KindOwnerGranted {
			t.Errorf("grant event = %+v", ev)
		}
		// Tenant isolation: tenant B has no owner role seeded and no assignment id of A's resolves there.
		if _, err := oa.Grant(ctx, e.b, owner1, admin); !errors.Is(err, ErrNoOwnerRole) {
			t.Errorf("grant in unseeded tenant: %v", err)
		}
		if err := oa.Revoke(ctx, e.b, id2, admin); !errors.Is(err, ErrOwnerNotFound) {
			t.Errorf("cross-tenant revoke: %v", err)
		}
		// Bad input is refused before any write.
		if _, err := oa.Grant(ctx, e.a, "nope", admin); !errors.Is(err, ErrBadOwnerInput) {
			t.Errorf("bad account: %v", err)
		}
		if _, err := oa.Grant(ctx, e.a, owner1, authority.Chain{}); !errors.Is(err, ErrBadOwnerInput) {
			t.Errorf("no requester: %v", err)
		}
	})
}

// Acceptance 4: two concurrent revokes of the only two owners: exactly one succeeds.
func TestConcurrentRevokesLeaveOneOwner(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		e, oa, _ := ownerSetup(t, s, inactive{})
		id1, err := oa.Grant(ctx, e.a, owner1, admin)
		if err != nil {
			t.Fatal(err)
		}
		id2, err := oa.Grant(ctx, e.a, owner2, admin)
		if err != nil {
			t.Fatal(err)
		}
		{
			var wg sync.WaitGroup
			errs := make([]error, 2)
			start := make(chan struct{})
			for i, id := range []string{id1, id2} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					errs[i] = oa.Revoke(ctx, e.a, id, admin)
				}()
			}
			close(start)
			wg.Wait()
			ok, refused := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ErrLastOwner):
					refused++
				default:
					t.Fatalf("unexpected: %v", err)
				}
			}
			if ok != 1 || refused != 1 {
				t.Fatalf("ok=%d refused=%d, want 1 and 1", ok, refused)
			}
			if got := e.owners(t); len(got) != 1 {
				t.Fatalf("owners left = %v", got)
			}
		}
	})
}

func TestNewOwnerAssignmentsRequiresCollaborators(t *testing.T) {
	if _, err := NewOwnerAssignments(nil, &ownerSink{}, inactive{}); err == nil {
		t.Error("nil db accepted")
	}
}
