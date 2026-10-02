package provision

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

func open(t *testing.T, d *storetest.Database) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func countTenants(t *testing.T, d *storetest.Database) (n int, ids []string) {
	t.Helper()
	ids, err := d.OwnerStrings(context.Background(), `SELECT id::text FROM public.tenants`)
	if err != nil {
		t.Fatal(err)
	}
	return len(ids), ids
}

// Acceptance 4: a fresh install's first-run bootstrap, run twice, leaves exactly one tenant with a random
// UUID.
func TestFirstRunCreatesExactlyOneTenant(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		db := open(t, d)
		ctx := context.Background()

		first, err := FirstRun(ctx, db, "Acme")
		if err != nil || !first.Created || first.Tenant.IsZero() {
			t.Fatalf("first run = %+v, %v; want a created tenant", first, err)
		}
		again, err := FirstRun(ctx, db, "Acme")
		if err != nil || again.Created || again.Tenant != first.Tenant {
			t.Fatalf("second run = %+v, %v; want the same tenant, not created", again, err)
		}
		// A different name on a later start renames nothing and creates nothing.
		third, err := FirstRun(ctx, db, "Renamed")
		if err != nil || third.Created || third.Tenant != first.Tenant {
			t.Fatalf("third run = %+v, %v", third, err)
		}
		n, ids := countTenants(t, d)
		if n != 1 || ids[0] != first.Tenant.String() {
			t.Fatalf("tenants = %v; want exactly [%s]", ids, first.Tenant)
		}
		if _, err := tenant.Parse(ids[0]); err != nil {
			t.Fatal(err)
		}
	})
}

// Each install gets its own random UUID: there is no default-tenant constant.
func TestFirstRunTenantIDIsRandomPerInstall(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		seen := map[tenant.ID]bool{}
		for range 3 {
			d := s.NewDatabase(t)
			d.Migrate(t)
			res, err := FirstRun(context.Background(), open(t, d), "Acme")
			if err != nil {
				t.Fatal(err)
			}
			if seen[res.Tenant] {
				t.Fatalf("two installs got the same tenant ID %s", res.Tenant)
			}
			seen[res.Tenant] = true
		}
	})
}

// Several nodes starting together create one tenant.
func TestFirstRunConcurrentStartsCreateOneTenant(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		db := open(t, d)
		var wg sync.WaitGroup
		results := make(chan Result, 8)
		errs := make(chan error, 8)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, err := FirstRun(context.Background(), db, "Acme")
				results <- r
				errs <- err
			}()
		}
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		created := 0
		var id tenant.ID
		for r := range results {
			if r.Created {
				created++
			}
			if !id.IsZero() && r.Tenant != id {
				t.Fatalf("nodes disagree on the tenant: %s and %s", id, r.Tenant)
			}
			id = r.Tenant
		}
		if n, _ := countTenants(t, d); n != 1 || created != 1 {
			t.Fatalf("%d tenants, %d creators; want 1 and 1", n, created)
		}
	})
}

func TestFirstRunRefusesAMultiTenantDatabase(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		tenanttest.Seed(t, d.ExecOwner, "one")
		tenanttest.Seed(t, d.ExecOwner, "two")
		if _, err := FirstRun(context.Background(), open(t, d), "Acme"); !errors.Is(err, ErrNotSingleTenant) {
			t.Fatalf("FirstRun = %v; want ErrNotSingleTenant", err)
		}
	})
}

func TestFirstRunRejectsBadNames(t *testing.T) {
	for _, n := range []string{"", "   ", "nul\x00name", "\xff", string(make([]byte, 0)) + func() string {
		b := make([]byte, 201)
		for i := range b {
			b[i] = 'x'
		}
		return string(b)
	}()} {
		// No database: the name is refused before any SQL.
		if _, err := FirstRun(context.Background(), nil, n); !errors.Is(err, ErrInvalidName) {
			t.Errorf("FirstRun(%q) = %v; want ErrInvalidName", n, err)
		}
	}
}

// ADR-0005 rule 11: initialisers run in the new tenant's own WithTenant transaction after the tenants
// row commits, on every run; a failed initialiser leaves the tenant, and the next run completes it.
func TestFirstRunInitialisers(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		db := open(t, d)
		ctx := context.Background()
		var ranFor []tenant.ID
		var sawTenant []string
		ok := func(ctx context.Context, tx store.Tx, id tenant.ID) error {
			ranFor = append(ranFor, id)
			var got string
			if err := tx.QueryRow(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&got); err != nil {
				return err
			}
			sawTenant = append(sawTenant, got)
			return nil
		}
		fail := errors.New("init failed")
		res, err := FirstRun(ctx, db, "Acme", ok, func(context.Context, store.Tx, tenant.ID) error { return fail })
		if !errors.Is(err, fail) {
			t.Fatalf("FirstRun = %v; want the initialiser's error", err)
		}
		if n, _ := countTenants(t, d); n != 1 {
			t.Fatalf("%d tenants after a failed initialiser; the tenant row must stay committed", n)
		}
		ranFor, sawTenant = nil, nil
		res2, err := FirstRun(ctx, db, "Acme", ok)
		if err != nil || res2.Created || res2.Tenant != res.Tenant {
			t.Fatalf("retry = %+v, %v", res2, err)
		}
		if len(ranFor) != 1 || ranFor[0] != res.Tenant || sawTenant[0] != res.Tenant.String() {
			t.Fatalf("initialiser ran for %v in contexts %v; want once, as tenant %s", ranFor, sawTenant, res.Tenant)
		}
	})
}
