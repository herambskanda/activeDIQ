package keys_test

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type rig struct {
	t    *testing.T
	d    *storetest.Database
	db   *store.DB
	kms  *keystest.KMS
	st   *keys.Store
	a, b tenant.ID
}

func setup(t *testing.T, s *storetest.Server) *rig {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	kms := keystest.New("kek-1")
	return &rig{t: t, d: d, db: db, kms: kms, st: keys.NewStore(kms),
		a: tenanttest.Seed(t, d.ExecOwner, "A"), b: tenanttest.Seed(t, d.ExecOwner, "B")}
}

func (r *rig) in(id tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error {
	return r.db.WithTenant(context.Background(), id, fn)
}

func (r *rig) provision(id tenant.ID) error {
	return r.in(id, func(ctx context.Context, tx store.Tx) error { return r.st.Provision(ctx, tx, id) })
}

func (r *rig) dek(id tenant.ID, v uint32) (keys.DEK, error) {
	var d keys.DEK
	err := r.in(id, func(ctx context.Context, tx store.Tx) (err error) {
		d, err = r.st.KeySource().DEK(ctx, tx, id, v)
		return
	})
	return d, err
}

// ownerSQL runs fixture SQL as the owner with forced row-level security off for the statement's table,
// as an attacker holding the owner credential would. Only test fixtures reach it.
func (r *rig) ownerSQL(sql string) error {
	return r.d.ExecOwner(context.Background(), `ALTER TABLE public.tenant_keys NO FORCE ROW LEVEL SECURITY; `+sql)
}

func (r *rig) count(id tenant.ID, where string) (n int) {
	r.t.Helper()
	if err := r.in(id, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.tenant_keys WHERE `+where).Scan(&n)
	}); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if keys.Code(err) != code {
		t.Fatalf("got %v (code %q), want code %s", err, keys.Code(err), code)
	}
	if err.Error() != "keys: "+code {
		t.Fatalf("error text %q is not exactly the code", err.Error())
	}
}

// Acceptance 1: the schema.
func TestSchemaShape(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		ctx := context.Background()
		q := func(sql string) string {
			t.Helper()
			out, err := r.d.OwnerStrings(ctx, sql)
			if err != nil || len(out) != 1 {
				t.Fatalf("%s: %v %v", sql, out, err)
			}
			return out[0]
		}
		if got := q(`SELECT relrowsecurity::text || relforcerowsecurity::text FROM pg_class WHERE oid = 'public.tenant_keys'::regclass`); got != "truetrue" {
			t.Errorf("RLS enabled/forced = %s", got)
		}
		if got := q(`SELECT indexdef FROM pg_indexes WHERE indexname = 'tenant_keys_one_active'`); !strings.Contains(got, "UNIQUE") || !strings.Contains(got, "WHERE (state = 'active'") {
			t.Errorf("partial unique index = %s", got)
		}
		if got := q(`SELECT count(*)::text FROM pg_trigger WHERE tgrelid = 'public.tenant_keys'::regclass AND tgname = 'tenant_keys_guard' AND tgenabled = 'A'`); got != "1" {
			t.Errorf("transition trigger always-enabled count = %s", got)
		}
		for _, p := range []string{"DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			if got := q(`SELECT has_table_privilege('activediq_app', 'public.tenant_keys', '` + p + `')::text`); got != "false" {
				t.Errorf("runtime role holds %s", p)
			}
		}
		for _, c := range []string{"tenant_id", "version", "created_at", "kek_provider", "kek_key_id"} {
			if got := q(`SELECT has_column_privilege('activediq_app', 'public.tenant_keys', '` + c + `', 'UPDATE')::text`); got != "false" {
				t.Errorf("runtime role may UPDATE %s", c)
			}
		}
		for _, c := range []string{"state", "retired_at", "shredded_at", "wrapped_dek"} {
			if got := q(`SELECT has_column_privilege('activediq_app', 'public.tenant_keys', '` + c + `', 'UPDATE')::text`); got != "true" {
				t.Errorf("runtime role may not UPDATE %s", c)
			}
		}
		// This migration adds no SECURITY DEFINER function, and no role has BYPASSRLS (AC6).
		if got := q(`SELECT count(*)::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.prosecdef AND p.proname LIKE 'tenant_keys%'`); got != "0" {
			t.Errorf("SECURITY DEFINER functions: %s", got)
		}
		if got := q(`SELECT count(*)::text FROM pg_roles WHERE rolbypassrls AND rolname LIKE 'activediq%'`); got != "0" {
			t.Errorf("BYPASSRLS roles: %s", got)
		}
	})
}

func TestTransitionTriggerAndRuntimeGrants(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		if err := r.provision(r.a); err != nil {
			t.Fatal(err)
		}
		app := func(sql string) error {
			return r.in(r.a, func(ctx context.Context, tx store.Tx) error { _, err := tx.Exec(ctx, sql); return err })
		}
		// A second active row for the tenant violates DM-02.I1.
		if err := app(`INSERT INTO public.tenant_keys (tenant_id, version, state, wrapped_dek, kek_provider, kek_key_id)
			SELECT tenant_id, 2, 'active', '\x01', 'p', 'k' FROM public.tenant_keys`); store.SQLState(err) != "23505" {
			t.Errorf("second active row: %v", err)
		}
		if err := app(`DELETE FROM public.tenant_keys`); store.SQLState(err) != "42501" {
			t.Errorf("runtime DELETE: %v", err)
		}
		if err := app(`UPDATE public.tenant_keys SET kek_key_id = 'other'`); store.SQLState(err) != "42501" {
			t.Errorf("runtime UPDATE kek_key_id: %v", err)
		}
		if err := app(`UPDATE public.tenant_keys SET version = 9`); store.SQLState(err) != "42501" {
			t.Errorf("runtime UPDATE version: %v", err)
		}
		// Re-wrap (same state, wrapped_dek changed) is refused for the runtime role by the trigger.
		if err := app(`UPDATE public.tenant_keys SET wrapped_dek = '\x00'`); store.SQLState(err) != "AD403" {
			t.Errorf("runtime re-wrap: %v", err)
		}
		// ... and allowed for the owner (maintenance).
		if err := r.ownerSQL(`UPDATE public.tenant_keys SET wrapped_dek = wrapped_dek, kek_key_id = 'kek-2' WHERE true`); err != nil {
			t.Errorf("owner re-wrap: %v", err)
		}
		// active -> retired
		if err := app(`UPDATE public.tenant_keys SET state = 'retired'`); store.SQLState(err) == "" {
			t.Errorf("retired without retired_at must violate the check")
		}
		if err := app(`UPDATE public.tenant_keys SET state = 'retired', retired_at = now()`); err != nil {
			t.Fatalf("active -> retired: %v", err)
		}
		// retired -> active never.
		if err := app(`UPDATE public.tenant_keys SET state = 'active', retired_at = NULL`); store.SQLState(err) != "AD403" {
			t.Errorf("retired -> active: %v", err)
		}
		// Shredding must empty wrapped_dek.
		if err := app(`UPDATE public.tenant_keys SET state = 'shredded', shredded_at = now()`); store.SQLState(err) == "" {
			t.Errorf("shred with non-empty wrapped_dek must fail")
		}
		if err := app(`UPDATE public.tenant_keys SET state = 'shredded', shredded_at = now(), wrapped_dek = ''`); err != nil {
			t.Fatalf("retired -> shredded: %v", err)
		}
		for _, sql := range []string{
			`UPDATE public.tenant_keys SET state = 'active', shredded_at = NULL, wrapped_dek = '\x01'`,
			`UPDATE public.tenant_keys SET state = 'retired', shredded_at = NULL, wrapped_dek = '\x01', retired_at = now()`,
		} {
			if err := app(sql); store.SQLState(err) != "AD403" {
				t.Errorf("out of shredded: %s: %v", sql, err)
			}
		}
		if err := r.ownerSQL(`UPDATE public.tenant_keys SET kek_key_id = 'x' WHERE true`); store.SQLState(err) != "AD403" {
			t.Errorf("owner edit of a shredded row: %v", err)
		}
	})
}

// Acceptance 2.
func TestProvisionInsertsOnceAndDestroysPlaintext(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		if err := r.provision(r.a); err != nil {
			t.Fatal(err)
		}
		if n := r.count(r.a, `version = 1 AND state = 'active' AND octet_length(wrapped_dek) > 0 AND kek_provider = 'fakekms' AND kek_key_id = 'kek-1'`); n != 1 {
			t.Fatalf("active version 1 rows = %d", n)
		}
		if err := r.provision(r.a); err != nil {
			t.Fatalf("second Provision: %v", err)
		}
		if n := r.count(r.a, `true`); n != 1 {
			t.Fatalf("rows after second Provision = %d", n)
		}
		// Another tenant's rows are not visible and not touched.
		if n := r.count(r.b, `true`); n != 0 {
			t.Fatalf("tenant B sees %d rows", n)
		}
		// A tenant whose only rows are shredded is never re-keyed.
		if err := r.ownerSQL(`UPDATE public.tenant_keys SET state = 'shredded', shredded_at = now(), wrapped_dek = '' WHERE true`); err != nil {
			t.Fatal(err)
		}
		if err := r.provision(r.a); err != nil {
			t.Fatal(err)
		}
		if n := r.count(r.a, `state = 'active'`); n != 0 {
			t.Fatalf("a shredded tenant was re-keyed")
		}
	})
}

func TestProvisionFailsClosedWhenProviderDown(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		r.kms.SetDown(true)
		wantCode(t, r.provision(r.a), keys.ProviderUnavailable)
		if n := r.count(r.a, `true`); n != 0 {
			t.Fatalf("rows after failed Provision = %d", n)
		}
		if _, err := r.dek(r.a, 0); keys.Code(err) != keys.NoActiveKey {
			t.Fatalf("keyless tenant: %v", err)
		}
		r.kms.SetDown(false)
		if err := r.provision(r.a); err != nil {
			t.Fatalf("retry: %v", err)
		}
		d, err := r.dek(r.a, 0)
		if err != nil {
			t.Fatal(err)
		}
		d.Destroy()
	})
}

// Acceptance 3.
func TestKeySourceResolution(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		_, err := r.dek(r.a, 0)
		wantCode(t, err, keys.NoActiveKey)

		if err := r.provision(r.a); err != nil {
			t.Fatal(err)
		}
		if err := r.provision(r.b); err != nil {
			t.Fatal(err)
		}
		active, err := r.dek(r.a, 0)
		if err != nil || active.Version != 1 {
			t.Fatalf("active: %v %v", active.Version, err)
		}
		byVersion, err := r.dek(r.a, 1)
		if err != nil || byVersion.Version != 1 {
			t.Fatalf("version 1: %v", err)
		}
		// Same key either way: sealing under one opens under the other.
		c := keys.Context{Tenant: r.a, Table: "t", Row: "r", Column: "c", Version: 1}
		blob, err := keys.Seal(active, c, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		if pt, err := keys.Open(byVersion, c, blob); err != nil || !bytes.Equal(pt, []byte("x")) {
			t.Fatalf("open: %v", err)
		}
		active.Destroy()
		byVersion.Destroy()

		// Unknown version and another tenant's version are the same error. Tenant A's version 1 asked
		// for through tenant B's tx: B's own version 1 would answer, so use a version only A has.
		if err := r.ownerSQL(`INSERT INTO public.tenant_keys (tenant_id, version, state, wrapped_dek, kek_provider, kek_key_id)
			SELECT tenant_id, 2, 'retired', wrapped_dek, kek_provider, kek_key_id FROM public.tenant_keys WHERE tenant_id = '` + r.a.String() + `'`); err == nil {
			// retired requires retired_at; the check must have refused it.
			t.Fatal("retired row without retired_at was accepted")
		}
		if err := r.ownerSQL(`INSERT INTO public.tenant_keys (tenant_id, version, state, wrapped_dek, kek_provider, kek_key_id, retired_at)
			SELECT tenant_id, 2, 'retired', wrapped_dek, kek_provider, kek_key_id, now() FROM public.tenant_keys WHERE tenant_id = '` + r.a.String() + `'`); err != nil {
			t.Fatal(err)
		}
		_, errOther := r.dek(r.b, 2)
		_, errUnknown := r.dek(r.b, 77)
		wantCode(t, errOther, keys.KeyNotFound)
		wantCode(t, errUnknown, keys.KeyNotFound)
		if errOther.Error() != errUnknown.Error() {
			t.Fatalf("not identical: %q vs %q", errOther, errUnknown)
		}
		// Version 2's row is a copy of version 1's wrapped DEK: wrap binding rejects it.
		_, err = r.dek(r.a, 2)
		wantCode(t, err, keys.UnwrapFailed)

		// Shredded.
		if err := r.ownerSQL(`UPDATE public.tenant_keys SET state = 'shredded', shredded_at = now(), wrapped_dek = '' WHERE tenant_id = '` + r.a.String() + `' AND version = 2`); err != nil {
			t.Fatal(err)
		}
		_, err = r.dek(r.a, 2)
		wantCode(t, err, keys.KeyShredded)
	})
}

// Acceptance 4.
func TestKeySourceProviderOutageAndTampering(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		if err := r.provision(r.a); err != nil {
			t.Fatal(err)
		}
		r.kms.SetDown(true)
		_, err := r.dek(r.a, 0)
		wantCode(t, err, keys.ProviderUnavailable)
		r.kms.SetDown(false)

		// Tampered kek_ref: the KEK is not held.
		if err := r.ownerSQL(`UPDATE public.tenant_keys SET kek_key_id = 'kek-evil' WHERE true`); err != nil {
			t.Fatal(err)
		}
		_, err = r.dek(r.a, 0)
		wantCode(t, err, keys.UnwrapFailed)
		for _, leak := range []string{r.a.String(), "kek-evil", "kek-1", "fakekms", "tenant_keys", "SELECT"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("error text leaks %q", leak)
			}
		}
		// Tampered wrapped_dek.
		if err := r.ownerSQL(`UPDATE public.tenant_keys SET kek_key_id = 'kek-1', wrapped_dek = '\xdeadbeef' WHERE true`); err != nil {
			t.Fatal(err)
		}
		_, err = r.dek(r.a, 0)
		wantCode(t, err, keys.UnwrapFailed)
	})
}

// With a real local KEK the same wrap-binding holds: a wrapped DEK moved to another tenant's row fails.
func TestKeySourceLocalProviderBindsTenant(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := setup(t, s)
		kek := secret.FromBytes(bytes.Repeat([]byte{7}, keys.DEKSize))
		lp, err := keys.NewLocalProvider("local-1", kek)
		if err != nil {
			t.Fatal(err)
		}
		r.st = keys.NewStore(lp)
		if err := r.provision(r.a); err != nil {
			t.Fatal(err)
		}
		if err := r.provision(r.b); err != nil {
			t.Fatal(err)
		}
		if err := r.ownerSQL(`UPDATE public.tenant_keys SET wrapped_dek = (SELECT wrapped_dek FROM public.tenant_keys WHERE tenant_id = '` + r.a.String() +
			`') WHERE tenant_id = '` + r.b.String() + `'`); err != nil {
			t.Fatal(err)
		}
		d, err := r.dek(r.a, 0)
		if err != nil {
			t.Fatal(err)
		}
		d.Destroy()
		_, err = r.dek(r.b, 0)
		wantCode(t, err, keys.UnwrapFailed)
	})
}

// Acceptance 5: the only INSERT INTO tenant_keys statements in the package are in Provision (and Rotate
// when it lands), never in the KeySource.
func TestOnlyProvisionAndRotateInsert(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"Provision": true, "Rotate": true}
	found := 0
	for _, p := range pkgs {
		for fname, f := range p.Files {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				ast.Inspect(fd, func(n ast.Node) bool {
					lit, ok := n.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					if up := strings.ToUpper(lit.Value); strings.Contains(up, "INSERT") && strings.Contains(strings.ToLower(lit.Value), "tenant_keys") {
						found++
						if !allowed[fd.Name.Name] {
							t.Errorf("%s: INSERT INTO tenant_keys in %s", fname, fd.Name.Name)
						}
					}
					return true
				})
			}
		}
	}
	if found == 0 {
		t.Fatal("found no INSERT INTO tenant_keys at all: the scan is broken")
	}
}
