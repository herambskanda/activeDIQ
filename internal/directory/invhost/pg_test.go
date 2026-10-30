package invhost_test

import (
	"context"
	"os"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/invhost"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

func TestPGStore(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		a := tenanttest.Seed(t, d.ExecOwner, "A")
		b := tenanttest.Seed(t, d.ExecOwner, "B")
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ps := invhost.PGStore{}
		ctx := context.Background()
		if err := db.WithTenant(ctx, a, func(ctx context.Context, tx store.Tx) error {
			if id, ok, err := ps.Insert(ctx, tx, a, "fs1.corp.example", "acct-1"); err != nil || !ok || id == "" {
				t.Errorf("insert = %q %v %v", id, ok, err)
			}
			if _, ok, err := ps.Insert(ctx, tx, a, "fs1.corp.example", "acct-1"); err != nil || ok {
				t.Errorf("duplicate insert = %v %v", ok, err)
			}
			if ok, err := ps.Find(ctx, tx, a, "fs1.corp.example"); err != nil || !ok {
				t.Errorf("find = %v %v", ok, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// The database refuses a name the Go side would never produce.
		if err := db.WithTenant(ctx, a, func(ctx context.Context, tx store.Tx) error {
			_, _, err := ps.Insert(ctx, tx, a, `\\evil\share`, "acct-1")
			return err
		}); err == nil {
			t.Error("CHECK must refuse a UNC name")
		}
		// Another tenant does not see it.
		if err := db.WithTenant(ctx, b, func(ctx context.Context, tx store.Tx) error {
			if ok, err := ps.Find(ctx, tx, b, "fs1.corp.example"); err != nil || ok {
				t.Errorf("tenant B sees tenant A's server: %v %v", ok, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
