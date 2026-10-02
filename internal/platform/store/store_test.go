package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

// testTable is a tenant table in the shape ADR-0002 prescribes, created by the migration role as a
// later migration would. It exists only in these tests (fixtures live only in tests).
const testTable = `
CREATE TABLE public.items (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL,
  label text NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.items FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.items
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)`

type env struct {
	db   *DB
	a, b tenant.ID
	d    *storetest.Database
}

func setup(t *testing.T, s *storetest.Server, cfg Config) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	ctx := context.Background()
	if err := d.ExecOwner(ctx, testTable); err != nil {
		t.Fatal(err)
	}
	a := tenanttest.Seed(t, d.ExecOwner, "A")
	b := tenanttest.Seed(t, d.ExecOwner, "B")
	cfg.DSN = d.AppDSN()
	db, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open as the runtime role: %v", err)
	}
	t.Cleanup(db.Close)
	return &env{db: db, a: a, b: b, d: d}
}

func insert(ctx context.Context, tx Tx, tenantID tenant.ID, label string) error {
	_, err := tx.Exec(ctx, `INSERT INTO public.items (tenant_id, id, label) VALUES ($1::uuid, gen_random_uuid(), $2)`, tenantID.String(), label)
	return err
}

func labels(ctx context.Context, tx Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT label FROM public.items ORDER BY label`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func isRLSViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "42501"
}

// Acceptance 2: only the tenant's rows are visible and a row for another tenant is rejected; with no
// tenant context reads return zero rows and writes fail (SQL-13, SQL-19).
func TestWithTenantIsolation(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{})
		ctx := context.Background()
		for _, x := range []struct {
			id   tenant.ID
			rows []string
		}{{e.a, []string{"a1", "a2"}}, {e.b, []string{"b1"}}} {
			err := e.db.WithTenant(ctx, x.id, func(ctx context.Context, tx Tx) error {
				for _, l := range x.rows {
					if err := insert(ctx, tx, x.id, l); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				t.Fatalf("insert as %s: %v", x.id, err)
			}
		}

		check := func(id tenant.ID, want ...string) {
			t.Helper()
			var got []string
			err := e.db.WithTenant(ctx, id, func(ctx context.Context, tx Tx) (err error) { got, err = labels(ctx, tx); return })
			if err != nil || strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("tenant %s sees %v, %v; want %v", id, got, err, want)
			}
		}
		check(e.a, "a1", "a2")
		check(e.b, "b1")

		// A row for tenant B written in A's transaction is rejected by the policy's WITH CHECK.
		err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx Tx) error { return insert(ctx, tx, e.b, "smuggled") })
		if !isRLSViolation(err) {
			t.Fatalf("cross-tenant insert: want an RLS violation (42501), got %v", err)
		}
		// A's UPDATE and DELETE cannot reach B's row.
		err = e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE public.items SET label = 'x' WHERE label = 'b1'`)
			if err == nil && tag.RowsAffected() != 0 {
				t.Errorf("A updated %d of B's rows", tag.RowsAffected())
			}
			if err != nil {
				return err
			}
			tag, err = tx.Exec(ctx, `DELETE FROM public.items WHERE label = 'b1'`)
			if err == nil && tag.RowsAffected() != 0 {
				t.Errorf("A deleted %d of B's rows", tag.RowsAffected())
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		check(e.b, "b1")

		// No tenant context: zero rows, and a write fails (WithPlatform sets no tenant).
		err = e.db.WithPlatform(ctx, "test: read a tenant table with no context", func(ctx context.Context, tx Tx) error {
			got, err := labels(ctx, tx)
			if err != nil || len(got) != 0 {
				t.Errorf("no tenant context sees %v, %v; want zero rows", got, err)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		err = e.db.WithPlatform(ctx, "test: write a tenant table with no context", func(ctx context.Context, tx Tx) error { return insert(ctx, tx, e.a, "nobody") })
		if !isRLSViolation(err) {
			t.Fatalf("write with no tenant context: want an RLS violation (42501), got %v", err)
		}

		// A raw connection that never went through the entry points has no context either (SQL-19).
		err = e.db.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
			var n int
			if err := c.QueryRow(ctx, `SELECT count(*) FROM public.items`).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("a connection with no tenant context counts %d rows; want 0", n)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

// Acceptance 3 (SQL-14): a pooled connection that served tenant A has an empty app.tenant_id when it is
// reused, after a commit, a rollback and a panic.
func TestSQL14TenantDoesNotLeakToPooledConnection(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{MaxConns: 1})
		ctx := context.Background()
		var servedPID int
		serve := func(fn func(ctx context.Context, tx Tx) error) (err error) {
			defer func() { _ = recover() }() // the panic case below
			return e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx Tx) error {
				if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&servedPID); err != nil {
					return err
				}
				var inTx string
				if err := tx.QueryRow(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&inTx); err != nil || inTx != e.a.String() {
					t.Errorf("inside WithTenant app.tenant_id = %q, %v; want %s", inTx, err, e.a)
				}
				return fn(ctx, tx)
			})
		}
		afterwards := func(how string) {
			t.Helper()
			err := e.db.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
				var pid int
				var setting string
				if err := c.QueryRow(ctx, `SELECT pg_backend_pid(), current_setting('app.tenant_id', true)`).Scan(&pid, &setting); err != nil {
					return err
				}
				if pid != servedPID {
					t.Errorf("%s: the pooled connection was not reused (pid %d, served %d): the test proves nothing", how, pid, servedPID)
				}
				if setting != "" {
					t.Errorf("%s: app.tenant_id = %q on the reused connection; want empty (SQL-14)", how, setting)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := serve(func(context.Context, Tx) error { return nil }); err != nil {
			t.Fatal(err)
		}
		afterwards("after commit")
		if err := serve(func(context.Context, Tx) error { return errors.New("boom") }); err == nil {
			t.Fatal("rollback case: want the error back")
		}
		afterwards("after rollback")
		_ = serve(func(context.Context, Tx) error { panic("boom") })
		afterwards("after panic")
	})
}

// SQL-03: a hostile tenant string fails UUID parsing before any SQL: there is no way to hand
// WithTenant text, and the zero ID is refused before the pool is touched (the DB below has none).
func TestSQL03HostileTenantStringFailsBeforeSQL(t *testing.T) {
	for _, s := range []string{"x'; SET ROLE postgres; --", "' OR '1'='1", ""} {
		id, err := tenant.Parse(s)
		if err == nil || !id.IsZero() {
			t.Fatalf("tenant.Parse(%q) = %v, %v; want an error", s, id, err)
		}
		// What a caller that ignored the error would pass: the zero ID.
		var db DB // no pool: any SQL would panic or return ErrClosed
		if got := db.WithTenant(context.Background(), id, func(context.Context, Tx) error {
			t.Error("fn ran for a tenant ID that failed to parse")
			return nil
		}); !errors.Is(got, ErrNoTenant) {
			t.Fatalf("WithTenant(zero) = %v; want ErrNoTenant", got)
		}
	}
}

func TestWithPlatformNeedsAReason(t *testing.T) {
	var db DB
	for _, r := range []string{"", "   ", "\t", "bad\nreason", strings.Repeat("x", maxReasonLen+1), "nul\x00", "\xff"} {
		if err := db.WithPlatform(context.Background(), r, func(context.Context, Tx) error { return nil }); !errors.Is(err, ErrReasonRequired) {
			t.Errorf("WithPlatform(%q) = %v; want ErrReasonRequired", r, err)
		}
	}
}

func TestClosedDB(t *testing.T) {
	var db *DB
	if err := db.WithPlatform(context.Background(), "test", func(context.Context, Tx) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil DB: %v; want ErrClosed", err)
	}
}

// SQL-20: constructing the pool from a DSN that selects the simple protocol fails. The fitness job
// requires this exact test name in this package (T4 sql-20). It needs no server: the refusal comes
// before any connection.
func TestPoolRefusesSimpleProtocol(t *testing.T) {
	for name, dsn := range map[string]string{
		"url":        "postgres://activediq_app:pw@127.0.0.1:1/db?default_query_exec_mode=simple_protocol",
		"keyvalue":   "host=127.0.0.1 port=1 user=activediq_app dbname=db default_query_exec_mode=simple_protocol",
		"mixed-case": "postgres://activediq_app:pw@127.0.0.1:1/db?sslmode=disable&default_query_exec_mode=simple_protocol",
	} {
		t.Run(name, func(t *testing.T) {
			db, err := Open(context.Background(), Config{DSN: dsn})
			if !errors.Is(err, ErrSimpleProtocolForbidden) || db != nil {
				t.Fatalf("Open = %v, %v; want ErrSimpleProtocolForbidden", db, err)
			}
		})
	}
}

func TestOpenRefusesPresetTenant(t *testing.T) {
	for name, dsn := range map[string]string{
		"runtime param": "postgres://activediq_app:pw@127.0.0.1:1/db?app.tenant_id=3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5f",
		"options":       "postgres://activediq_app:pw@127.0.0.1:1/db?options=-c%20app.tenant_id%3D3f2b8a40-5c1d-4e6a-9b7f-0a1b2c3d4e5f",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(context.Background(), Config{DSN: dsn}); !errors.Is(err, ErrTenantInDSN) {
				t.Fatalf("Open = %v; want ErrTenantInDSN", err)
			}
		})
	}
}

func TestInvalidDSNDoesNotEchoPassword(t *testing.T) {
	_, err := Open(context.Background(), Config{DSN: "postgres://activediq_app:s3cr3t-pw@host:notaport/db"})
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "s3cr3t-pw") {
		t.Fatalf("the error leaks the password: %v", err)
	}
}

// ADR-0002 rule 4: the runtime refuses to start as a role that bypasses RLS or owns the schema objects.
func TestOpenRefusesPrivilegedRoles(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		for name, dsn := range map[string]string{"superuser": d.AdminDSN(), "migration role": d.OwnerDSN()} {
			if db, err := Open(context.Background(), Config{DSN: dsn}); !errors.Is(err, ErrPrivilegedRole) {
				if db != nil {
					db.Close()
				}
				t.Errorf("Open as the %s = %v; want ErrPrivilegedRole", name, err)
			}
		}
		db, err := Open(context.Background(), Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatalf("Open as the runtime role: %v", err)
		}
		db.Close()
	})
}

// Open refuses a runtime role that can reach privilege through a membership that does not inherit
// (SET ROLE), through owning the database, or through CREATE on a schema, not only through its own
// attributes.
func TestOpenRefusesRoleThatCanEscapeRLS(t *testing.T) {
	for _, b := range storetest.Breaches() {
		t.Run(b.Name, func(t *testing.T) {
			storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
				d := s.NewDatabase(t)
				d.Migrate(t)
				d.Break(t, b)
				db, err := Open(context.Background(), Config{DSN: d.AppDSN()})
				if err == nil {
					db.Close()
				}
				if !errors.Is(err, ErrPrivilegedRole) {
					t.Fatalf("Open under %q = %v; want ErrPrivilegedRole", b.Name, err)
				}
			})
		})
	}
}

// SQL-22: both entry points set a per-transaction statement_timeout that does not outlive the
// transaction.
func TestStatementTimeoutIsPerTransaction(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{MaxConns: 1, StatementTimeout: 1234 * time.Millisecond})
		ctx := context.Background()
		read := func(ctx context.Context, tx Tx) (string, error) {
			var v string
			err := tx.QueryRow(ctx, `SELECT current_setting('statement_timeout')`).Scan(&v)
			return v, err
		}
		var inTenant, inPlatform string
		if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx Tx) (err error) { inTenant, err = read(ctx, tx); return }); err != nil {
			t.Fatal(err)
		}
		if err := e.db.WithPlatform(ctx, "test: read the timeout", func(ctx context.Context, tx Tx) (err error) { inPlatform, err = read(ctx, tx); return }); err != nil {
			t.Fatal(err)
		}
		if inTenant != "1234ms" || inPlatform != "1234ms" {
			t.Fatalf("statement_timeout = %q (tenant), %q (platform); want 1234ms", inTenant, inPlatform)
		}
		var after string
		err := e.db.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
			return c.QueryRow(ctx, `SELECT current_setting('statement_timeout')`).Scan(&after)
		})
		if err != nil || after == "1234ms" {
			t.Fatalf("statement_timeout after the transaction = %q, %v; it must not outlive it", after, err)
		}
	})
}

// A cancelled context returns the connection to the pool clean, and concurrent tenants never see each
// other's context.
func TestConcurrentTenantsStayIsolated(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{MaxConns: 2})
		ctx := context.Background()
		var wg sync.WaitGroup
		errs := make(chan error, 200)
		for i := range 200 {
			id := e.a
			if i%2 == 1 {
				id = e.b
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- e.db.WithTenant(ctx, id, func(ctx context.Context, tx Tx) error {
					var got string
					if err := tx.QueryRow(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&got); err != nil {
						return err
					}
					if got != id.String() {
						return errors.New("a transaction saw another tenant's context")
					}
					return nil
				})
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	})
}
