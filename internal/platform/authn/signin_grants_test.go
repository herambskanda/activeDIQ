package authn

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// TestSigninCredentialRuntimeGrants pins the runtime-role grants of migration 0057 (T-0910). These tables
// are not append-only in the domain model (DM-30/DM-31), so the X5 append-only fitness check does not
// cover them: if a later migration drops a REVOKE or re-grants the privilege, only this test fails.
//
//   - authn_local_credentials: no DELETE (removing a credential is a state change of the account).
//   - authn_signin_pepper: no UPDATE and no DELETE (the HMAC key of the throttle is written once).
//   - authn_signin_throttle: UPDATE and DELETE stay granted (the failure counter and the purge job).
//
// Each statement runs as activediq_app inside a tenant transaction whose tenant owns a row, so a refusal
// is the privilege check (42501) and not an RLS filter that matched nothing.
func TestSigninCredentialRuntimeGrants(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		ctx := context.Background()
		db, err := store.Open(ctx, store.Config{DSN: e.d.AppDSN()})
		if err != nil {
			t.Fatalf("store.Open as the runtime role: %v", err)
		}
		t.Cleanup(db.Close)

		acct := e.account(t)
		ten := e.ten.String()
		for _, seed := range []struct{ name, sql string }{
			{"credential", `INSERT INTO public.authn_local_credentials (tenant_id, account_id, username_norm, password_hash)
				VALUES ($1::uuid, $2::uuid, 'grants.fixture', '$argon2id$fixture')`},
			{"pepper", `INSERT INTO public.authn_signin_pepper (tenant_id, sealed_secret, key_version)
				VALUES ($1::uuid, '\x01', 1)`},
			{"throttle", `INSERT INTO public.authn_signin_throttle (tenant_id, key_hash, failures, window_start, not_before)
				VALUES ($1::uuid, decode(repeat('ab', 32), 'hex'), 1, now(), now())`},
		} {
			args := []any{ten}
			if seed.name == "credential" {
				args = append(args, acct)
			}
			if err := fixtureAs(db, e.ten, seed.sql, args...); err != nil {
				t.Fatalf("seed %s as the runtime role: %v", seed.name, err)
			}
		}

		count := func(table string) int {
			t.Helper()
			var n int
			err := db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM public.`+table).Scan(&n)
			})
			if err != nil {
				t.Fatalf("count %s: %v", table, err)
			}
			return n
		}

		for name, c := range map[string]struct{ table, sql, priv string }{
			"credentials delete": {"authn_local_credentials", `DELETE FROM public.authn_local_credentials`, "DELETE"},
			"pepper update":      {"authn_signin_pepper", `UPDATE public.authn_signin_pepper SET key_version = 2`, "UPDATE"},
			"pepper delete":      {"authn_signin_pepper", `DELETE FROM public.authn_signin_pepper`, "DELETE"},
		} {
			t.Run("refused/"+name, func(t *testing.T) {
				err := fixtureAs(db, e.ten, c.sql)
				if got := store.SQLState(err); got != "42501" {
					t.Errorf("%s: err = %v (SQLSTATE %q); want 42501 insufficient_privilege", c.sql, err, got)
				}
				if n := count(c.table); n != 1 {
					t.Errorf("%s left %d rows; want the 1 seeded row", c.table, n)
				}
				has, err := e.d.OwnerStrings(ctx, `SELECT has_table_privilege('activediq_app', 'public.`+c.table+`', '`+c.priv+`')::text`)
				if err != nil || len(has) != 1 {
					t.Fatalf("has_table_privilege: %v %v", has, err)
				}
				if has[0] != "false" {
					t.Errorf("activediq_app holds %s on %s", c.priv, c.table)
				}
			})
		}

		// The throttle must stay writable: the failure counter updates rows and the purge job deletes them.
		t.Run("allowed/throttle", func(t *testing.T) {
			if err := fixtureAs(db, e.ten, `UPDATE public.authn_signin_throttle SET failures = failures + 1`); err != nil {
				t.Errorf("runtime UPDATE on authn_signin_throttle: %v", err)
			}
			if err := fixtureAs(db, e.ten, `DELETE FROM public.authn_signin_throttle`); err != nil {
				t.Errorf("runtime DELETE on authn_signin_throttle: %v", err)
			}
			if n := count("authn_signin_throttle"); n != 0 {
				t.Errorf("authn_signin_throttle has %d rows after the runtime DELETE; want 0", n)
			}
		})
	})
}
