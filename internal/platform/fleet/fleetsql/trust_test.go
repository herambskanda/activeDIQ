package fleetsql_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// execer adapts a pgx transaction to a plain function so the test files do not import pgx.
func execer[C any, T interface {
	Exec(context.Context, string, ...any) (C, error)
}](ctx context.Context, tx T) func(string, ...any) error {
	return func(q string, args ...any) error { _, err := tx.Exec(ctx, q, args...); return err }
}

func pgCode(err error) string {
	var pe interface{ SQLState() string }
	if errors.As(err, &pe) {
		return pe.SQLState()
	}
	return ""
}

func (e *enrollEnv) initCAs(t *testing.T) {
	t.Helper()
	for _, tid := range []tenant.ID{e.a, e.b} {
		tid := tid
		if err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error { return e.enr.InitTenant(ctx, tx, tid) }); err != nil {
			t.Fatal(err)
		}
	}
}

func anchorTenants(as []fleetsql.Anchor) map[tenant.ID]int {
	m := map[tenant.ID]int{}
	for _, a := range as {
		m[a.Tenant]++
	}
	return m
}

func TestTrustAnchorsLoad(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		ctx := context.Background()
		ta := &fleetsql.TrustAnchors{DB: e.db, Alerts: e.al}
		if got, err := ta.Load(ctx); err != nil || len(got) != 0 {
			t.Fatalf("no CA yet: %d, %v", len(got), err)
		}
		e.initCAs(t)
		got, err := ta.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if m := anchorTenants(got); len(got) != 2 || m[e.a] != 1 || m[e.b] != 1 {
			t.Fatalf("want one CA per tenant, got %v", m)
		}

		// A tenant transaction can never call the reader (42501), whatever the tenant.
		err = e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			rows, qerr := tx.Query(ctx, `SELECT * FROM public.fleet_ca_trust_anchors()`)
			if qerr == nil {
				rows.Close()
				qerr = rows.Err()
			}
			return qerr
		})
		if pgCode(err) != "42501" {
			t.Fatalf("function in a tenant context: want 42501, got %v", err)
		}
		// The runtime role still reads fleet_ca as empty with no tenant context: the new policy is catrust's only.
		ac, err := e.d.App(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer ac.Close(ctx)
		var visible int
		if err := ac.QueryRow(ctx, `SELECT count(*) FROM public.fleet_ca`).Scan(&visible); err != nil || visible != 0 {
			t.Fatalf("runtime role reads %d fleet_ca rows without a tenant: %v", visible, err)
		}

		// Withdraw A's CA and install a replacement whose stored pin does not match its certificate: the
		// withdrawn row is gone from the pool, the bad row is left out with an alert, B is untouched.
		c, err := e.d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		tx, err := c.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{
			`UPDATE public.fleet_ca SET state = 'withdrawn', sealed_key = NULL WHERE tenant_id = $1::uuid AND state = 'active'`,
			`INSERT INTO public.fleet_ca (tenant_id, cert_der, spki_sha256, sealed_key, key_version, not_after)
			   SELECT tenant_id, cert_der, sha256('wrong'::bytea), '\x0102030405060708091011121314151617181920212223242526272829303132'::bytea, key_version, not_after
			     FROM public.fleet_ca WHERE tenant_id = $1::uuid AND state = 'withdrawn'`,
		} {
			if _, err := tx.Exec(ctx, sql, e.a.String()); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		got, err = ta.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if m := anchorTenants(got); len(got) != 1 || m[e.b] != 1 {
			t.Fatalf("want only B in the pool, got %v", m)
		}
		if !e.al.has(fleetsql.AlertCAMaterial) {
			t.Fatal("a bad stored row raised no alert")
		}
		// And the per-tenant bundle never serves a withdrawn row.
		cas, err := e.enr.TenantCAs(ctx, e.b)
		if err != nil || len(cas) != 1 {
			t.Fatalf("tenant B CAs: %d, %v", len(cas), err)
		}
	})
}

func TestTrustReaderRoleAndFunctionCatalog(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		ctx := context.Background()
		e.initCAs(t)
		c, err := e.d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)

		var login, super, bypass, createRole, createDB bool
		if err := c.QueryRow(ctx, `SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = 'activediq_catrust'`).
			Scan(&login, &super, &bypass, &createRole, &createDB); err != nil {
			t.Fatal(err)
		}
		if login || super || bypass || createRole || createDB {
			t.Errorf("activediq_catrust must be NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB: %v", []bool{login, super, bypass, createRole, createDB})
		}
		var secdef bool
		var owner string
		var cfg, acl []string
		if err := c.QueryRow(ctx, `SELECT p.prosecdef, pg_get_userbyid(p.proowner), COALESCE(p.proconfig, '{}'), COALESCE(p.proacl::text[], '{}')
			FROM pg_proc p WHERE p.oid = 'public.fleet_ca_trust_anchors()'::regprocedure`).Scan(&secdef, &owner, &cfg, &acl); err != nil {
			t.Fatal(err)
		}
		if !secdef || owner != "activediq_catrust" || len(cfg) != 1 || cfg[0] != "search_path=pg_catalog, pg_temp" {
			t.Errorf("function: secdef=%v owner=%s config=%v", secdef, owner, cfg)
		}
		for _, a := range acl {
			// acl entries are grantee=privileges/grantor; an empty grantee is PUBLIC.
			if len(a) > 0 && a[0] == '=' {
				t.Errorf("EXECUTE granted to PUBLIC: %v", acl)
			}
		}
		var lang string
		if err := c.QueryRow(ctx, `SELECT l.lanname FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang WHERE p.oid = 'public.fleet_ca_trust_anchors()'::regprocedure`).Scan(&lang); err != nil || lang != "plpgsql" {
			t.Errorf("language %q, %v", lang, err)
		}
		var appExec, ownerExec, otherExec bool
		if err := c.QueryRow(ctx, `SELECT has_function_privilege('activediq_app', 'public.fleet_ca_trust_anchors()', 'EXECUTE'),
			has_function_privilege('activediq_owner', 'public.fleet_ca_trust_anchors()', 'EXECUTE'),
			has_function_privilege('public', 'public.fleet_ca_trust_anchors()', 'EXECUTE')`).Scan(&appExec, &ownerExec, &otherExec); err != nil {
			t.Fatal(err)
		}
		if !appExec || !ownerExec || otherExec {
			t.Errorf("EXECUTE: app=%v owner=%v public=%v", appExec, ownerExec, otherExec)
		}

		var owned, createOn, appMember int
		if err := c.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM pg_shdepend d WHERE d.refclassid = 'pg_authid'::regclass AND d.deptype = 'o'
			   AND d.refobjid = 'activediq_catrust'::regrole),
			(SELECT count(*) FROM pg_namespace n WHERE has_schema_privilege('activediq_catrust', n.oid, 'CREATE')),
			(SELECT count(*) FROM pg_auth_members m WHERE m.roleid = 'activediq_catrust'::regrole AND m.member = 'activediq_app'::regrole)`).
			Scan(&owned, &createOn, &appMember); err != nil {
			t.Fatal(err)
		}
		if owned != 1 || createOn != 0 || appMember != 0 {
			t.Errorf("catrust owns %d objects (want 1), CREATE on %d schemas (want 0), app member %d (want 0)", owned, createOn, appMember)
		}
		for _, col := range []string{"sealed_key", "key_version", "created_at"} {
			var ok bool
			if err := c.QueryRow(ctx, `SELECT has_column_privilege('activediq_catrust', 'public.fleet_ca', $1, 'SELECT')`, col).Scan(&ok); err != nil || ok {
				t.Errorf("catrust can read %s: %v, %v", col, ok, err)
			}
		}
		var writes int
		if err := c.QueryRow(ctx, `SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'activediq_catrust' AND privilege_type <> 'SELECT'`).Scan(&writes); err != nil || writes != 0 {
			t.Errorf("catrust holds %d write grants, %v", writes, err)
		}

		// As catrust: a key read is a privilege error (not an empty result), certificates read, no writes.
		codes, err := e.d.ProbeAsRole(ctx, "activediq_catrust",
			`SELECT sealed_key FROM public.fleet_ca`,
			`SELECT * FROM public.fleet_ca`,
			`SELECT key_version FROM public.fleet_ca`,
			`UPDATE public.fleet_ca SET state = 'retired'`,
			`DELETE FROM public.fleet_ca`,
			`CREATE TABLE public.adq_x (a int)`,
			`SELECT tenant_id, id, state, cert_der, spki_sha256, not_after FROM public.fleet_ca`)
		if err != nil {
			t.Fatal(err)
		}
		for i, want := range []string{"42501", "42501", "42501", "42501", "42501", "42501", ""} {
			if codes[i] != want {
				t.Errorf("catrust probe %d: want SQLSTATE %q, got %q", i, want, codes[i])
			}
		}
		var n int
		if err := c.QueryRow(ctx, `SELECT count(*) FROM public.fleet_ca`).Scan(&n); err != nil || n != 2 {
			t.Errorf("seeded rows: %d, %v", n, err)
		}
	})
}

func TestFleetCAGuardTransitions(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		ctx := context.Background()
		c, err := e.d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		certA := func() []byte {
			e.initCAs(t)
			var der []byte
			if err := c.QueryRow(ctx, `SELECT cert_der FROM public.fleet_ca WHERE tenant_id = $1::uuid`, e.a.String()).Scan(&der); err != nil {
				t.Fatal(err)
			}
			return der
		}()
		const sealed = `'\x0102030405060708091011121314151617181920212223242526272829303132'::bytea`
		insert := func(x func(string, ...any) error, state string, n byte) {
			t.Helper()
			key := "NULL"
			if state == "active" {
				key = sealed
			}
			if err := x(`INSERT INTO public.fleet_ca (tenant_id, cert_der, spki_sha256, sealed_key, key_version, not_after, state)
				VALUES ($1::uuid, $2, $3, `+key+`, 1, now() + interval '1 year', $4)`, e.a.String(), certA, append(make([]byte, 31), n), state); err != nil {
				t.Fatal(err)
			}
		}
		states := []string{"active", "retired", "withdrawn"}
		allowed := map[[2]string]bool{{"active", "retired"}: true, {"retired", "withdrawn"}: true, {"active", "withdrawn"}: true}
		for _, from := range states {
			for _, to := range states {
				from, to := from, to
				t.Run(from+"_to_"+to, func(t *testing.T) {
					tx, err := c.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(ctx)
					if _, err := tx.Exec(ctx, `DELETE FROM public.fleet_ca WHERE tenant_id = $1::uuid`, e.a.String()); err != nil {
						t.Fatal(err)
					}
					if from != "active" {
						insert(execer(ctx, tx), "active", 1) // the bystander active CA
					}
					insert(execer(ctx, tx), from, 2)
					key := "NULL"
					if to == "active" {
						key = sealed
					}
					_, err = tx.Exec(ctx, `UPDATE public.fleet_ca SET state = $2, sealed_key = `+key+` WHERE tenant_id = $1::uuid AND spki_sha256 = $3`,
						e.a.String(), to, append(make([]byte, 31), 2))
					if from == to {
						// A same-state update that changes nothing is harmless.
						if err != nil {
							t.Fatalf("no-op update: %v", err)
						}
						return
					}
					if allowed[[2]string{from, to}] {
						if err != nil {
							t.Fatalf("allowed transition refused: %v", err)
						}
						if to == "withdrawn" && from == "active" {
							insert(execer(ctx, tx), "active", 3) // the replacement
						}
						if err := tx.Commit(ctx); err != nil {
							t.Fatalf("commit: %v", err)
						}
						return
					}
					if pgCode(err) != "AD403" && pgCode(err) != "23514" {
						t.Fatalf("%s -> %s: want AD403 (or the CHECK), got %v", from, to, err)
					}
					if from == "withdrawn" && pgCode(err) != "AD403" {
						t.Fatalf("withdrawn is terminal: want AD403, got %v", err)
					}
				})
			}
		}

		t.Run("withdrawal without a replacement is refused at commit", func(t *testing.T) {
			tx, err := c.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `DELETE FROM public.fleet_ca WHERE tenant_id = $1::uuid`, e.a.String()); err != nil {
				t.Fatal(err)
			}
			insert(execer(ctx, tx), "active", 1)
			if _, err := tx.Exec(ctx, `UPDATE public.fleet_ca SET state = 'withdrawn', sealed_key = NULL WHERE tenant_id = $1::uuid`, e.a.String()); err != nil {
				t.Fatalf("the row-level step is allowed: %v", err)
			}
			if err := tx.Commit(ctx); pgCode(err) != "AD403" {
				t.Fatalf("commit: want AD403, got %v", err)
			}
		})

		t.Run("immutable columns and the sealed key", func(t *testing.T) {
			tx, err := c.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `DELETE FROM public.fleet_ca WHERE tenant_id = $1::uuid`, e.a.String()); err != nil {
				t.Fatal(err)
			}
			insert(execer(ctx, tx), "active", 1)
			for name, sql := range map[string]string{
				"cert_der":           `UPDATE public.fleet_ca SET cert_der = cert_der || '\x00'::bytea WHERE tenant_id = $1::uuid`,
				"spki":               `UPDATE public.fleet_ca SET spki_sha256 = sha256('x'::bytea) WHERE tenant_id = $1::uuid`,
				"sealed key rewrite": `UPDATE public.fleet_ca SET sealed_key = sealed_key || '\x00'::bytea WHERE tenant_id = $1::uuid`,
				"retire keeping key": `UPDATE public.fleet_ca SET state = 'retired' WHERE tenant_id = $1::uuid`,
			} {
				if _, err := tx.Exec(ctx, `SAVEPOINT q`); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.Exec(ctx, sql, e.a.String()); err == nil {
					t.Errorf("%s: accepted", name)
				}
				if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT q`); err != nil {
					t.Fatal(err)
				}
			}
		})
	})
}

func selfSignedCA(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "activeDIQ fleet CA", Organization: []string{"activeDIQ"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestTrustAnchorsPoolContents covers F-POOL-3 (active and retired in, expired and withdrawn out) and
// F-POOL-6 (every generated CA subject is the constant and carries nothing of the tenant).
func TestTrustAnchorsPoolContents(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		ctx := context.Background()
		e.initCAs(t)
		c, err := e.d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		add := func(cert *x509.Certificate, state string, notAfter string) {
			t.Helper()
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if _, err := c.Exec(ctx, `INSERT INTO public.fleet_ca (tenant_id, cert_der, spki_sha256, sealed_key, key_version, not_after, state)
				VALUES ($1::uuid, $2, $3, NULL, 1, `+notAfter+`, $4)`, e.a.String(), cert.Raw, sum[:], state); err != nil {
				t.Fatal(err)
			}
		}
		retired, expired, withdrawn := selfSignedCA(t, 11), selfSignedCA(t, 12), selfSignedCA(t, 13)
		add(retired, "retired", "now() + interval '1 day'")
		add(expired, "retired", "now() - interval '1 minute'")
		add(withdrawn, "withdrawn", "now() + interval '1 day'")

		ta := &fleetsql.TrustAnchors{DB: e.db, Alerts: e.al}
		certs, err := ta.Certificates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(certs) != 3 { // A active + A retired + B active
			t.Fatalf("want 3 certificates (two active, one retired), got %d", len(certs))
		}
		has := func(c *x509.Certificate) bool {
			for _, x := range certs {
				if x.Equal(c) {
					return true
				}
			}
			return false
		}
		if !has(retired) || has(expired) || has(withdrawn) {
			t.Fatalf("retired in %v, expired in %v, withdrawn in %v", has(retired), has(expired), has(withdrawn))
		}
		// F-POOL-6, on the CAs the product generated.
		for _, x := range certs {
			if x.Equal(retired) {
				continue
			}
			if x.Subject.CommonName != "activeDIQ fleet CA" || len(x.Subject.Organization) != 1 || x.Subject.Organization[0] != "activeDIQ" ||
				len(x.Subject.OrganizationalUnit)+len(x.Subject.Country)+len(x.Subject.Province)+len(x.Subject.Locality)+len(x.Subject.StreetAddress)+len(x.Subject.PostalCode)+len(x.Subject.ExtraNames) != 0 ||
				x.Subject.SerialNumber != "" || len(x.DNSNames)+len(x.EmailAddresses)+len(x.IPAddresses)+len(x.URIs) != 0 {
				t.Fatalf("CA subject or names are not the constant: %q", x.Subject)
			}
			for _, tid := range []string{e.a.String(), e.b.String()} {
				if bytes.Contains(x.Raw, []byte(tid)) {
					t.Fatal("a tenant id appears in a CA certificate")
				}
			}
		}
	})
}
