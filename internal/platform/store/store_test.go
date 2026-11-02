package store

import (
	"context"
	"errors"
	"fmt"
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

// Open checks the LOGIN, not only the role the session runs as: a privileged login that starts the
// session as the runtime role (a startup option or ALTER ROLE ... SET role) can SET ROLE back.
func TestOpenRefusesPrivilegedLoginRunningAsRuntimeRole(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		t.Run("superuser login with options role", func(t *testing.T) {
			db, err := Open(context.Background(), Config{DSN: d.AdminDSN() + " options='-c role=activediq_app'"})
			if err == nil {
				db.Close()
			}
			if !errors.Is(err, ErrPrivilegedRole) {
				t.Fatalf("Open = %v; want ErrPrivilegedRole", err)
			}
		})
		t.Run("login with ALTER ROLE SET role", func(t *testing.T) {
			b := storetest.Breach{
				Setup: []string{
					`CREATE ROLE adq_breach_login LOGIN PASSWORD 'adq-breach-pw'`,
					`GRANT activediq_app TO adq_breach_login WITH INHERIT FALSE`,
					`GRANT activediq_owner TO adq_breach_login WITH INHERIT FALSE`,
					`ALTER ROLE adq_breach_login SET role = activediq_app`,
				},
				Teardown: []string{`DROP OWNED BY adq_breach_login`, `DROP ROLE adq_breach_login`},
			}
			d.Break(t, b)
			db, err := Open(context.Background(), Config{DSN: d.LoginDSN("adq_breach_login", "adq-breach-pw")})
			if err == nil {
				db.Close()
			}
			if !errors.Is(err, ErrPrivilegedRole) {
				t.Fatalf("Open = %v; want ErrPrivilegedRole", err)
			}
		})
	})
}

// A temporary table is pooled-session state: pg_temp is searched first, so one tenant's CREATE TEMP
// TABLE would capture the next tenant's unqualified writes on a reused connection. Migration 0001
// revokes TEMPORARY from PUBLIC, so the runtime role cannot create one.
func TestTenantTransactionCannotCreateTempTable(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{MaxConns: 1})
		err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx Tx) error {
			_, err := tx.Exec(ctx, `CREATE TEMP TABLE items (label text)`)
			return err
		})
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Fatalf("CREATE TEMP TABLE in a tenant transaction = %v; want SQLSTATE 42501 (insufficient_privilege)", err)
		}
	})
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

func TestNestedWithTenantIsRefused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{})
		ran := false
		for _, inner := range []tenant.ID{e.a, e.b} { // same tenant and another tenant
			err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx Tx) error {
				return e.db.WithTenant(ctx, inner, func(context.Context, Tx) error { ran = true; return nil })
			})
			if !errors.Is(err, ErrNestedTenant) {
				t.Fatalf("nested WithTenant = %v; want ErrNestedTenant", err)
			}
		}
		if ran {
			t.Fatal("the nested function ran")
		}
		// sequential use is still fine
		for i := 0; i < 2; i++ {
			if err := e.db.WithTenant(context.Background(), e.a, func(context.Context, Tx) error { return nil }); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// WithTenantSeparate commits although the surrounding transaction rolls back, sets the lock timeout
// itself, and refuses a missing or oversized lock wait before any SQL runs.
func TestWithTenantSeparateCommitsBesideRolledBackOuter(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{})
		for _, w := range []time.Duration{0, -time.Second, time.Minute} {
			if err := e.db.WithTenantSeparate(context.Background(), e.a, w, func(context.Context, Tx) error { return nil }); !errors.Is(err, ErrLockWait) {
				t.Fatalf("lock wait %v = %v; want ErrLockWait", w, err)
			}
		}
		var got string
		outer := errors.New("outer rolls back")
		err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, _ Tx) error {
			if err := e.db.WithTenantSeparate(ctx, e.a, 1500*time.Millisecond, func(ctx context.Context, tx Tx) error {
				return tx.QueryRow(ctx, `SELECT current_setting('lock_timeout')`).Scan(&got)
			}); err != nil {
				return err
			}
			return outer
		})
		if !errors.Is(err, outer) {
			t.Fatalf("outer = %v", err)
		}
		if got != "1500ms" && got != "1.5s" {
			t.Fatalf("lock_timeout = %q", got)
		}
	})
}

// TestIsTxControlMatchesPostgres pins the transaction-control guard to the real PostgreSQL lexer: each
// corpus string goes to a server by the simple protocol inside an open transaction, with
// standard_conforming_strings on and off, and whenever PostgreSQL left the transaction IsTxControl must
// have said so. The hand-written scanner drifted from scan.l three times; this is what stops a fourth.
func TestIsTxControlMatchesPostgres(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		db := s.NewDatabase(t)
		conn, err := db.App(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		pg := conn.PgConn()
		simple := func(sql string) error {
			_, err := pg.Exec(ctx, sql).ReadAll() // Exec is the simple query protocol: the whole text, unparsed by pgx
			return err
		}
		ended := 0
		for sql, want := range txControlCases {
			for _, scs := range []string{"on", "off"} {
				if err := simple("SET standard_conforming_strings = " + scs); err != nil {
					t.Fatal(err)
				}
				if err := simple("BEGIN"); err != nil {
					t.Fatal(err)
				}
				_ = simple(sql) // a syntax error is an expected outcome for many corpus strings
				left := pg.TxStatus() == 'I'
				if pg.TxStatus() != 'I' {
					_ = simple("ROLLBACK")
				}
				if left {
					ended++
					if !IsTxControl(sql) {
						t.Errorf("PostgreSQL left the transaction (standard_conforming_strings=%s) but IsTxControl(%q) = false", scs, sql)
					}
				}
				if want && !IsTxControl(sql) {
					t.Errorf("IsTxControl(%q) = false; the corpus says true", sql)
				}
			}
		}
		if ended == 0 {
			t.Fatal("no corpus string ended the transaction on PostgreSQL: the probe is not working")
		}
	})
}

// TestGuardRefusesNonUTF8ClientEncoding: the scanner reads UTF-8, so a body that switches the session to
// a client-only multibyte encoding (where 0x5C can be a trail byte) must have every later statement
// refused, or `SELECT E'<lead>\\' ; COMMIT; --'` would close the literal early in PostgreSQL's eyes and
// commit around the audit hook. The row inserted before the switch must not survive.
func TestGuardRefusesNonUTF8ClientEncoding(t *testing.T) {
	cases := []struct{ name, set, payload string }{
		{"SJIS SET LOCAL", `SET LOCAL client_encoding = 'SJIS'`, "SELECT E'\x95\\' ; COMMIT; --'"},
		{"BIG5 set_config", `SELECT set_config('client_encoding', 'BIG5', true)`, "SELECT E'\xa4\\' ; COMMIT; --'"},
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{})
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				ctx := context.Background()
				id := "00000000-0000-0000-0000-" + fmt.Sprintf("%012d", len(c.name))
				var got error
				err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx Tx) error {
					if _, err := tx.Exec(ctx, `INSERT INTO public.items (tenant_id, id, label) VALUES ($1, $2, 'x')`, e.a.String(), id); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, c.set); err != nil {
						return err
					}
					for _, call := range []func() error{
						func() error { _, err := tx.Exec(ctx, c.payload); return err },
						func() error {
							rows, err := tx.Query(ctx, c.payload)
							if err == nil {
								rows.Close()
							}
							return err
						},
						func() error { var x int; return tx.QueryRow(ctx, c.payload).Scan(&x) },
					} {
						if err := call(); !errors.Is(err, ErrClientEncoding) || !errors.Is(err, ErrTxControl) {
							return fmt.Errorf("payload under a non-UTF8 encoding = %v; want ErrClientEncoding", err)
						}
					}
					got = ErrClientEncoding
					return errors.New("body done")
				})
				if err == nil || got == nil {
					t.Fatalf("body did not reach the payload checks: %v", err)
				}
				if err.Error() != "body done" {
					t.Fatal(err)
				}
				var n int
				if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx Tx) error {
					return tx.QueryRow(ctx, `SELECT count(*) FROM public.items WHERE id = $1`, id).Scan(&n)
				}); err != nil {
					t.Fatal(err)
				}
				if n != 0 {
					t.Fatalf("%d rows survived a body that ended in error: the payload committed", n)
				}
			})
		}
	})
}

// TestGuardDecisionMatchesPostgres asserts the full guard decision (encoding check plus IsTxControl)
// through a real tenant transaction for every corpus string: under UTF8 the statement is refused with
// ErrTxControl exactly when IsTxControl says so, and under SJIS every one is refused with ErrClientEncoding.
func TestGuardDecisionMatchesPostgres(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{})
		ctx := context.Background()
		for sql := range txControlCases {
			for _, enc := range []string{"UTF8", "SJIS"} {
				stop := errors.New("stop")
				var got error
				err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx Tx) error {
					if enc != "UTF8" {
						if _, err := tx.Exec(ctx, "SET LOCAL client_encoding = '"+enc+"'"); err != nil {
							return err
						}
					}
					_, got = tx.Exec(ctx, sql)
					return stop
				})
				if !errors.Is(err, stop) {
					t.Fatalf("%s %q: body = %v", enc, sql, err)
				}
				switch {
				case enc != "UTF8":
					if !errors.Is(got, ErrClientEncoding) {
						t.Errorf("%s %q: err = %v; want ErrClientEncoding", enc, sql, got)
					}
				case IsTxControl(sql):
					if !errors.Is(got, ErrTxControl) || errors.Is(got, ErrClientEncoding) {
						t.Errorf("%s %q: err = %v; want ErrTxControl", enc, sql, got)
					}
				default:
					if errors.Is(got, ErrTxControl) {
						t.Errorf("%s %q: refused although IsTxControl is false", enc, sql)
					}
				}
			}
		}
	})
}
