package library_test

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

var (
	regOnce sync.Once
	reg     *reportsql.Registry
	regErr  error
)

// registry builds the SQL registry of the inventory datasets against the real migrated schema, once.
func registry(t *testing.T) *reportsql.Registry {
	t.Helper()
	regOnce.Do(func() {
		storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
			if reg != nil {
				return
			}
			d := s.NewDatabase(t)
			d.Migrate(t)
			tid := tenanttest.Seed(t, d.ExecOwner, "A")
			db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
			if err != nil {
				regErr = err
				return
			}
			defer db.Close()
			regErr = db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
				sc, err := reportsql.CatalogSchema(ctx, tx)
				if err != nil {
					return err
				}
				reg, err = reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: inventory.SecretKey}, inventory.Datasets()...)
				return err
			})
		})
	})
	if regErr != nil || reg == nil {
		t.Fatalf("registry: %v", regErr)
	}
	return reg
}

func shipped(t *testing.T) *library.Library {
	t.Helper()
	l, err := library.Load(library.Shipped(), library.Options{Datasets: inventory.Datasets(), Registry: registry(t)})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return l
}
