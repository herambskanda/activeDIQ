package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

type sessionView struct {
	pid                       int
	encoding, scs, searchPath string
	tempTables                int
	foreignPrepared           int
	appName                   string
}

func readSession(ctx context.Context, tx Tx) (v sessionView, err error) {
	err = tx.QueryRow(ctx, `SELECT pg_backend_pid(), current_setting('client_encoding'), current_setting('standard_conforming_strings'),
		current_setting('search_path'),
		(SELECT count(*) FROM pg_class WHERE relnamespace = pg_my_temp_schema()),
		(SELECT count(*) FROM pg_prepared_statements WHERE `+foreignPreparedPredicate+`), current_setting('application_name')`).
		Scan(&v.pid, &v.encoding, &v.scs, &v.searchPath, &v.tempTables, &v.foreignPrepared, &v.appName)
	return v, err
}

// T-1313 acceptance 1: session state a tenant body sets does not reach the next borrower.
func TestStorePoolResetIsolatesTenants(t *testing.T) {
	testStorePoolReset(t, false)
}

// A body's own PREPARE cannot be cleared without dropping pgx's statement cache, so that connection is
// destroyed instead of reset; the next tenant still sees a clean session, on another backend.
func TestStorePoolDestroysConnectionWithForeignPreparedStatement(t *testing.T) {
	testStorePoolReset(t, true)
}

func testStorePoolReset(t *testing.T, withPrepare bool) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{MaxConns: 1})
		ctx := context.Background()
		// The runtime role has no TEMPORARY privilege (Open refuses one); grant it after Open so the
		// temp-object leak can be exercised too.
		if err := e.d.ExecOwner(ctx, `GRANT TEMPORARY ON DATABASE `+pgx.Identifier{e.d.Name}.Sanitize()+` TO activediq_app`); err != nil {
			t.Fatal(err)
		}
		var base sessionView
		if err := e.db.WithTenant(ctx, e.b, func(ctx context.Context, tx Tx) (err error) { base, err = readSession(ctx, tx); return }); err != nil {
			t.Fatal(err)
		}
		if base.encoding != "UTF8" || base.scs != "on" {
			t.Fatalf("baseline session = %+v", base)
		}
		err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx Tx) error {
			for _, q := range []string{
				`SET client_encoding = 'SJIS'`,
				`SET standard_conforming_strings = off`,
				`SET search_path = pg_temp, public`,
				`SELECT set_config('application_name', 'tenant-a', false)`,
				`CREATE TEMP TABLE items (label text)`,
				`SELECT pg_advisory_lock(42)`,
			} {
				if _, err := tx.Exec(ctx, q); err != nil {
					return err
				}
			}
			if withPrepare {
				_, err := tx.Exec(ctx, `PREPARE leak AS SELECT 1`)
				return err
			}
			return nil
		})
		if err != nil {
			t.Fatalf("tenant A body: %v", err)
		}
		var got sessionView
		err = e.db.WithTenant(ctx, e.b, func(ctx context.Context, tx Tx) (err error) {
			got, err = readSession(ctx, tx)
			return err
		})
		if err != nil {
			t.Fatalf("tenant B body: %v", err)
		}
		if got.encoding != "UTF8" || got.scs != "on" || got.searchPath != base.searchPath || got.tempTables != 0 || got.foreignPrepared != 0 || got.appName != base.appName {
			t.Errorf("tenant B inherited session state: got %+v, want baseline %+v", got, base)
		}
		if withPrepare == (got.pid == base.pid) {
			t.Errorf("tenant B ran on backend %d, A on %d, withPrepare=%v: the connection must be reused after a reset and replaced when a foreign prepared statement is left", got.pid, base.pid, withPrepare)
		}
		var locks int
		if err := e.db.pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()`).Scan(&locks); err != nil || locks != 0 {
			t.Errorf("advisory locks on the next borrower's connection = %d, %v; want 0", locks, err)
		}
	})
}

// T-1313 acceptance 2: whatever happens in a body, no connection with a non-default lexing setting is
// handed to the next borrower, whether it is reset or destroyed.
func TestPoolNeverLendsNonDefaultLexingSettings(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{MaxConns: 1})
		ctx := context.Background()
		for _, bad := range []string{`SET client_encoding = 'SJIS'`, `SET standard_conforming_strings = off`} {
			if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx Tx) error {
				_, err := tx.Exec(ctx, bad)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// A raw borrow, as the pool's next caller would get it.
			err := e.db.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
				ps := c.Conn().PgConn()
				if ce, sc := ps.ParameterStatus("client_encoding"), ps.ParameterStatus("standard_conforming_strings"); ce != "UTF8" || sc != "on" {
					t.Errorf("after %q the next borrower got client_encoding=%q standard_conforming_strings=%q", bad, ce, sc)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	})
}

// The reset must not break pgx's statement cache: the same statement used across borrows keeps working.
func TestResetKeepsStatementCacheWorking(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, Config{MaxConns: 1})
		ctx := context.Background()
		for i := 0; i < 5; i++ {
			if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx Tx) error {
				var n int
				return tx.QueryRow(ctx, `SELECT $1::int + 1`, i).Scan(&n)
			}); err != nil {
				t.Fatalf("borrow %d: %v", i, err)
			}
		}
	})
}

// pgxStatementName mirrors pgx v5's deterministic name for a cached statement. The test depends on it only to
// play the attacker; if pgx changes the scheme the forged-name tests still pass (a forged name is foreign
// either way) and TestResetKeepsStatementCacheWorking guards the real cache.
func pgxStatementName(sql string) string {
	h := sha256.Sum256([]byte(sql))
	return "stmtcache_" + hex.EncodeToString(h[:24])
}

// T-1313 review: a body must not hide a PREPARE behind a 'stmtcache_' name, nor replace one of pgx's cached
// statements with different SQL under its real name. Either way the connection is destroyed, so tenant B runs
// on another backend and sees no foreign statement.
func TestPoolDestroysConnectionWithForgedStatementCacheName(t *testing.T) {
	const victimSQL = `SELECT $1::int + 1000`
	cases := map[string]func(ctx context.Context, tx Tx) error{
		"forged name": func(ctx context.Context, tx Tx) error {
			_, err := tx.Exec(ctx, `PREPARE stmtcache_forged AS SELECT 1`)
			return err
		},
		"forged name with valid shape": func(ctx context.Context, tx Tx) error {
			_, err := tx.Exec(ctx, `PREPARE `+pgxStatementName("not the text of this statement")+` AS SELECT 1`)
			return err
		},
		"replace a real cached name": func(ctx context.Context, tx Tx) error {
			var n int
			if err := tx.QueryRow(ctx, victimSQL, 1).Scan(&n); err != nil { // pgx caches it under its real name
				return err
			}
			name := pgxStatementName(victimSQL)
			if _, err := tx.Exec(ctx, `DEALLOCATE `+name); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `PREPARE `+name+` AS SELECT 2`)
			return err
		},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
				e := setup(t, s, Config{MaxConns: 1})
				ctx := context.Background()
				var base, got sessionView
				if err := e.db.WithTenant(ctx, e.b, func(ctx context.Context, tx Tx) (err error) { base, err = readSession(ctx, tx); return }); err != nil {
					t.Fatal(err)
				}
				if err := e.db.WithTenant(ctx, e.a, body); err != nil {
					t.Fatalf("tenant A body: %v", err)
				}
				if err := e.db.WithTenant(ctx, e.b, func(ctx context.Context, tx Tx) (err error) { got, err = readSession(ctx, tx); return }); err != nil {
					t.Fatalf("tenant B body: %v", err)
				}
				if got.pid == base.pid {
					t.Errorf("tenant B ran on backend %d, the one tenant A left a prepared statement on", got.pid)
				}
				if got.foreignPrepared != 0 {
					t.Errorf("tenant B sees %d foreign prepared statements", got.foreignPrepared)
				}
				var planted int
				if err := e.db.WithTenant(ctx, e.b, func(ctx context.Context, tx Tx) error {
					return tx.QueryRow(ctx, `SELECT count(*) FROM pg_prepared_statements WHERE statement LIKE 'PREPARE %'`).Scan(&planted)
				}); err != nil || planted != 0 {
					t.Errorf("planted statements visible to tenant B = %d, %v", planted, err)
				}
			})
		})
	}
}
