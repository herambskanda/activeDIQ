package server

// T-0916: the owner-status and object-connection adapters over the real account and inventory tables,
// and the composed rbac.ReadScopes built from the authorizer and the booted modules' contributions.

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// object inserts a directory object of conn with only the columns that have no default.
func (e *bkEnv) object(t *testing.T, conn, guid string) {
	t.Helper()
	e.exec(t, `INSERT INTO public.directory_objects (tenant_id, connection_id, object_guid, kind, object_class, observed_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'ou', 'organizationalUnit', now())`, e.ten.String(), conn, guid)
}

func (e *bkEnv) local(t *testing.T, id, state string) {
	t.Helper()
	e.exec(t, `INSERT INTO public.authn_accounts (tenant_id, id, kind, display_name, state, created_by)
		VALUES ($1::uuid, $2::uuid, 'local', 'l', $3, 'system')`, e.ten.String(), id, state)
}

// Acceptance 1: only an active account is active; disabled, deleted, invited, unknown and malformed ids are not.
func TestOwnerStatusActive(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := bkSetup(t, s)
		const (
			active, disabled = "b0000000-0000-4000-8000-000000000001", "b0000000-0000-4000-8000-000000000002"
			deleted, invited = "b0000000-0000-4000-8000-000000000003", "b0000000-0000-4000-8000-000000000004"
			unknown          = "b0000000-0000-4000-8000-0000000000ff"
		)
		for id, st := range map[string]string{active: "active", disabled: "disabled", deleted: "deleted", invited: "invited"} {
			e.local(t, id, st)
		}
		for _, c := range []struct {
			name, id string
			want     bool
		}{
			{"active", active, true}, {"disabled", disabled, false}, {"deleted", deleted, false},
			{"invited", invited, false}, {"unknown", unknown, false}, {"not a uuid", "alice", false}, {"empty", "", false},
			{"upper-case id", "B0000000-0000-4000-8000-000000000001", false},
		} {
			var got bool
			err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) (err error) {
				got, err = accountOwnerStatus{}.Active(ctx, tx, e.ten, c.id)
				return err
			})
			if err != nil || got != c.want {
				t.Errorf("%s: Active = %v, %v; want %v", c.name, got, err, c.want)
			}
		}
	})
}

// Acceptance 2: a GUID in one connection resolves to it; an absent GUID and a GUID in two connections do not.
func TestObjectConnectionsConnectionOf(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := bkSetup(t, s)
		const one, none, two = "d0000000-0000-4000-8000-000000000001", "d0000000-0000-4000-8000-000000000002", "d0000000-0000-4000-8000-000000000003"
		e.object(t, e.ad, one)
		e.object(t, e.ad, two)
		e.object(t, e.en, two)
		adID, err := authz.ParseObjectID(e.ad)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			name, guid string
			want       authz.ObjectID
			ok         bool
		}{
			{"one connection", one, adID, true}, {"absent", none, authz.ObjectID{}, false}, {"two connections", two, authz.ObjectID{}, false},
		} {
			id, err := authz.ParseObjectID(c.guid)
			if err != nil {
				t.Fatal(err)
			}
			var got authz.ObjectID
			var ok bool
			err = e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) (err error) {
				got, ok, err = inventoryObjectConnections{}.ConnectionOf(ctx, tx, e.ten, id)
				return err
			})
			if err != nil || ok != c.ok || got != c.want {
				t.Errorf("%s: ConnectionOf = %v, %v, %v; want %v, %v", c.name, got, ok, err, c.want, c.ok)
			}
		}
		// A zero object is nothing, not an error.
		err = e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			if _, ok, err := (inventoryObjectConnections{}).ConnectionOf(ctx, tx, e.ten, authz.ObjectID{}); ok || err != nil {
				t.Errorf("zero object: ok=%v err=%v", ok, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

// Acceptance 3: the composed producer is built from the Authorizer and the booted Contributions, and
// runs over the store: an unknown or disabled owner is dead (nothing is granted), never an empty grant.
func TestBuildReadScopesComposed(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := bkSetup(t, s)
		c, _, err := bootReport(context.Background(), capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning), directory.Services{}, owners.Lookup)
		if err != nil {
			t.Fatal(err)
		}
		az, err := rbacAuthorizer(e.db, noFacts{})
		if err != nil {
			t.Fatal(err)
		}
		rs, err := buildReadScopes(az, c)
		if err != nil || rs == nil {
			t.Fatalf("buildReadScopes = %v, %v", rs, err)
		}
		if _, err := buildReadScopes(az, nil); err == nil {
			t.Error("nil contributions were accepted")
		}
		if _, err := buildReadScopes(nil, c); err == nil {
			t.Error("nil authorizer was accepted")
		}

		const off, ghost = "b0000000-0000-4000-8000-000000000002", "b0000000-0000-4000-8000-0000000000ff"
		e.local(t, off, "disabled")
		for name, id := range map[string]string{"disabled": off, "unknown": ghost} {
			chain := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(id), Kind: authority.Human}}
			got, err := txReadScopes{db: e.db, rs: rs}.ReadScope(context.Background(), e.ten, chain, "directory.read")
			if !errors.Is(err, authz.ErrOwnerDead) {
				t.Errorf("%s owner: ReadScope = %+v, %v; want ErrOwnerDead", name, got, err)
			}
		}
		var _ rbac.ScopeEvaluators = c // module.Contributions is what rbac asks for
	})
}
