package invtest_test

import (
	"context"
	"os"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/directory/inventory/invtest"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

func count(t *testing.T, e *invtest.Env, q string, args ...any) (n int) {
	t.Helper()
	if err := e.Tx(t, e.A, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, q, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// The kit seeds the structure, a user with a primary group and a group with a foreign member, and the rows land
// where the inventory reads them: this pins the kit itself, so a module's tests can rely on what it writes.
func TestKitSeedsStructureUsersAndGroups(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := invtest.Setup(t, s)
		e.Structure(t, e.AdA)
		if n := count(t, e, `SELECT count(*) FROM directory_objects WHERE connection_id = $1`, string(e.AdA)); n != 3 {
			t.Fatalf("structure wrote %d objects, want 3 (NC head, OU, container)", n)
		}
		g := invtest.GUID(0x67, 1)
		u := invtest.User{GUID: invtest.GUID(0x75, 1), Sam: "alice", RID: 1001, UAC: invtest.I64(invtest.UACNormal), Primary: g}
		fsp := invtest.GUID(0x66, 1)
		_, err := e.Populate(t, e.AdA, invtest.Base, u.Obs(), invtest.Group(g, "staff", 513, u.GUID, fsp), invtest.FSP(fsp, 9001))
		if err != nil {
			t.Fatalf("populate: %v", err)
		}
		if n := count(t, e, `SELECT count(*) FROM directory_objects WHERE connection_id = $1`, string(e.AdA)); n != 6 {
			t.Fatalf("after populate %d objects, want 6", n)
		}
		// Determinism: the same call yields the same identifiers, so seeds are reproducible across runs.
		if invtest.GUID(0x75, 1) != u.GUID || len(invtest.SID(1001)) != 28 {
			t.Fatalf("GUID/SID are not deterministic or SID has the wrong length")
		}
		if _, ok := e.Registry(t).Dataset(inventory.Datasets()[0].ID); !ok {
			t.Fatal("registry does not hold the first inventory dataset")
		}
		// Tenant isolation: tenant B's connection holds nothing of tenant A's seed.
		if n := count(t, e, `SELECT count(*) FROM directory_objects WHERE connection_id = $1`, string(e.AdB)); n != 0 {
			t.Fatalf("tenant A's transaction sees %d of tenant B's objects", n)
		}
	})
}
