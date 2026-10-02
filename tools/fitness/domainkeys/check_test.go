package main

// Tests for fitness-domain-keys: every rule has a fixture that breaks only that rule and must be
// reported naming the table, the object and the rule (T-0050 acceptance 1 to 3), and a good schema that
// must pass. The database rules run against real PostgreSQL containers; without Docker they are skipped
// locally and fail under CI. The source rules (declarations) need no database.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

var (
	serverMu sync.Mutex
	servers  = map[string]*pgharness.Server{}
)

func testServer(t *testing.T, version string) *pgharness.Server {
	t.Helper()
	serverMu.Lock()
	defer serverMu.Unlock()
	if s := servers[version]; s != nil {
		return s
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := pgharness.DockerAvailable(ctx); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("Docker is required in CI: %v", err)
		}
		t.Skipf("SKIPPED, NOT PROVEN: %v (the fitness-domain-keys database tests need Docker; CI refuses to skip)", err)
	}
	s, err := pgharness.StartServer(ctx, version, nil)
	if err != nil {
		t.Fatalf("start PostgreSQL %s: %v", version, err)
	}
	// Cluster-level roles the fixtures grant to: the retention role, and a role that must never hold anything.
	c, err := s.ConnectAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	for _, r := range []string{DefaultRetentionRole, "fx_reader"} {
		var stmt string
		if err := c.QueryRow(ctx, `SELECT format('CREATE ROLE %I NOLOGIN', $1::text)`, r).Scan(&stmt); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	servers[version] = s
	return s
}

func TestMain(m *testing.M) {
	code := m.Run()
	for _, s := range servers {
		s.Stop()
	}
	os.Exit(code)
}

// The mini domain model the fixtures run against: the headings are all the job reads.
const fxModel = "# model\n" +
	"### DM-01 Tenant · P · owner `platform/tenant`\n" +
	"### DM-06 Lease · P (platform work) and T (tenant work) · owner `platform/jobs`\n" +
	"### DM-11 DirectoryCredential · T · owner `connector/credential`\n" +
	"### DM-16 DirectoryObject · D · owner `directory/inventory`\n" +
	"### DM-18 ChangeRecord · D · append-only · owner `directory/inventory`\n" +
	"### DM-25 Tier0Override · T · insert-only · owner `directory/connection`\n" +
	"### DM-30 Account · T · owner `platform/authn`\n" +
	"### DM-33 Permission · R · declared by each module (EP-6)\n" +
	"### DM-80 AuditEvent · T · append-only · owner `platform/audit`\n"

const fxRegistry = `{"globalTables": [{"table": "public.tenants", "reason": "the tenant directory", "owner": "internal/platform/tenant"}]}`

const fxBase = `CREATE TABLE tenants (id uuid PRIMARY KEY, parent_tenant_id uuid);`

// decl renders one tablekind.Declare call; extra is more fields (", AppendOnly: true").
func decl(name, entity, kind, extra string) string {
	return fmt.Sprintf("var _ = tablekind.Declare(tablekind.Table{Name: %q, Entity: %q, Kind: tablekind.%s%s})\n", name, entity, kind, extra)
}

const declHeader = "package x\n\nimport \"fx.test/internal/platform/tablekind\"\n\n"

var tenantsDecl = decl("public.tenants", "DM-01", "Platform", "")

// tree is one fixture repository.
type tree struct {
	migrations map[string]string // file name → SQL; 0001 is the tenants table unless set
	decls      string            // body of internal/x/tables.go after the header
	files      map[string]string // other files, by repo-relative path
	model      string
	registry   string
	bootstrap  []string
}

func (f tree) write(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	put := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("go.mod", "module fx.test\n\ngo 1.27.0\n")
	ms := map[string]string{"0001_tenant_tenants.sql": fxBase}
	for n, s := range f.migrations {
		ms[n] = s
	}
	for n, s := range ms {
		put("migrations/"+n, s)
	}
	put("internal/x/tables.go", declHeader+f.decls)
	for p, b := range f.files {
		put(p, b)
	}
	model := f.model
	if model == "" {
		model = fxModel
	}
	put("model.md", model)
	reg := f.registry
	if reg == "" {
		reg = fxRegistry
	}
	put("registry.json", reg)
	return root
}

func (f tree) run(t *testing.T, version string) ([]Violation, string) {
	t.Helper()
	s := testServer(t, version)
	root := f.write(t)
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	vs, err := Run(ctx, Options{
		Root: root, MigrationsDir: "migrations", RegistryPath: "registry.json", DomainModelPath: "model.md",
		RetentionRole: DefaultRetentionRole, Versions: []string{version}, Out: &out,
		Servers: map[string]*pgharness.Server{version: s}, ExtraBootstrap: f.bootstrap,
	})
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, out.String())
	}
	return vs, out.String()
}

func format(vs []Violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString("  " + v.String() + "\n")
	}
	return b.String()
}

// want requires a violation of check/rule whose Where or message contains every string of named.
func want(t *testing.T, vs []Violation, check, rule string, named ...string) {
	t.Helper()
	for _, v := range vs {
		ok := v.Check == check && v.Rule == rule
		for _, n := range named {
			ok = ok && (strings.Contains(v.Where, n) || strings.Contains(v.Msg, n))
		}
		if ok {
			return
		}
	}
	t.Errorf("no %s [%s] violation naming %q; got:\n%s", check, rule, named, format(vs))
}

func wantNone(t *testing.T, vs []Violation) {
	t.Helper()
	if len(vs) > 0 {
		t.Fatalf("expected no violations; got:\n%s", format(vs))
	}
}

// goodSQL is a schema every rule accepts: a directory table keyed by GUID with the DN beside it as a
// snapshot, an append-only record whose UPDATE and DELETE were revoked and whose DELETE the retention role
// holds, and a sealed credential column named like a secret attribute.
const goodSQL = `
CREATE TABLE directory_object (
  tenant_id uuid NOT NULL, connection_id uuid NOT NULL, object_guid uuid NOT NULL,
  dn text NOT NULL, sam_account_name text, display_name text,
  PRIMARY KEY (tenant_id, connection_id, object_guid));
CREATE INDEX directory_object_dn ON directory_object (dn);
CREATE TABLE change_record (
  tenant_id uuid NOT NULL, connection_id uuid NOT NULL, object_guid uuid NOT NULL, seq bigint NOT NULL,
  old_dn text, new_dn text, at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, connection_id, object_guid, seq),
  FOREIGN KEY (tenant_id, connection_id, object_guid) REFERENCES directory_object);
REVOKE UPDATE, DELETE ON change_record FROM activediq_app;
GRANT DELETE ON change_record TO activediq_retention;
CREATE TABLE credential (
  tenant_id uuid NOT NULL, id uuid NOT NULL, sealed_secret bytea NOT NULL, ms_mcs_admpwd_sealed bytea,
  PRIMARY KEY (tenant_id, id));
`

var goodDecls = tenantsDecl +
	decl("public.directory_object", "DM-16", "Directory", "") +
	decl("public.change_record", "DM-18", "Directory", ", AppendOnly: true") +
	decl("public.credential", "DM-11", "Tenant", `, Sealed: []string{"sealed_secret", "ms_mcs_admpwd_sealed"}`)

func good() tree {
	return tree{migrations: map[string]string{"0002_directory_inventory.sql": goodSQL}, decls: goodDecls}
}

func TestGoodSchemaPasses(t *testing.T) {
	for _, ver := range []string{"18", "16"} {
		t.Run("pg"+ver, func(t *testing.T) {
			vs, out := good().run(t, ver)
			wantNone(t, vs)
			if !strings.Contains(out, "X3/X4/X5 over 4 table(s) ok") {
				t.Errorf("output lacks the per-version summary:\n%s", out)
			}
		})
	}
}

// with returns the good schema plus extra SQL and declarations.
func with(sql, decls string) tree {
	g := good()
	g.migrations = map[string]string{"0002_directory_inventory.sql": goodSQL, "0003_directory_extra.sql": sql}
	g.decls += decls
	return g
}

func TestX3KeyedOnIdentityString(t *testing.T) {
	cases := []struct {
		name, sql, rule, index, holds string
	}{
		{"unique index on dn (acceptance 1)", `CREATE UNIQUE INDEX uq_dn ON directory_object (tenant_id, dn);`, "key-identity-column", "uq_dn", "DN"},
		{"unique index on a name", `CREATE UNIQUE INDEX uq_name ON directory_object (display_name);`, "key-identity-column", "uq_name", "name or display name"},
		{"unique expression index on lower(dn)", `CREATE UNIQUE INDEX uq_ldn ON directory_object (lower(dn));`, "key-identity-column", "uq_ldn", "DN"},
		{"unique index on sAMAccountName", `CREATE UNIQUE INDEX uq_sam ON directory_object (sam_account_name);`, "key-identity-column", "uq_sam", "sAMAccountName"},
		{"exclusion constraint on dn", `CREATE EXTENSION IF NOT EXISTS btree_gist; ALTER TABLE directory_object ADD CONSTRAINT ex_dn EXCLUDE USING gist (dn WITH =);`, "key-identity-column", "ex_dn", "DN"},
		{"primary key on an object SID", `CREATE TABLE d2 (tenant_id uuid NOT NULL, object_sid text NOT NULL, PRIMARY KEY (tenant_id, object_sid));`, "key-identity-column", "d2_pkey", "SID"},
		{"primary key on a UPN", `CREATE TABLE d2 (tenant_id uuid NOT NULL, user_principal_name text NOT NULL, PRIMARY KEY (tenant_id, user_principal_name));`, "key-identity-column", "d2_pkey", "UPN"},
		{"a column annotated as a DN under another name", `CREATE TABLE d2 (tenant_id uuid NOT NULL, ref text NOT NULL, PRIMARY KEY (tenant_id, ref)); COMMENT ON COLUMN d2.ref IS 'diq:holds=dn';`, "key-identity-column", "d2_pkey", "DN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			decls := ""
			if strings.Contains(c.sql, "d2") {
				decls = decl("public.d2", "DM-16", "Directory", "")
			}
			vs, _ := with(c.sql, decls).run(t, "18")
			want(t, vs, "X3", c.rule, c.index, c.holds, "X3")
			if len(vs) != 1 {
				t.Errorf("exactly the one X3 finding expected, got:\n%s", format(vs))
			}
		})
	}
}

func TestX3ForeignKeyOnIdentityString(t *testing.T) {
	// A tenant table joining a directory table on its DN, and a directory table with a foreign key on a name.
	sql := `
ALTER TABLE directory_object ADD CONSTRAINT uq_ref UNIQUE (tenant_id, connection_id, object_guid, sam_account_name);
CREATE TABLE ref_by_name (tenant_id uuid NOT NULL, id uuid NOT NULL, connection_id uuid NOT NULL, object_guid uuid NOT NULL, sam text,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id, object_guid, sam) REFERENCES directory_object (tenant_id, connection_id, object_guid, sam_account_name));`
	vs, _ := with(sql, decl("public.ref_by_name", "DM-30", "Tenant", "")).run(t, "18")
	want(t, vs, "X3", "fk-identity-column", "ref_by_name_tenant_id_connection_id_object_guid_sam_fkey", "sam_account_name", "joins on")
	want(t, vs, "X3", "key-identity-column", "uq_ref") // the unique constraint it needs is itself a key on a name
}

func TestX3NameOKSuppressesAndGoesStale(t *testing.T) {
	sql := `CREATE TABLE settings (tenant_id uuid NOT NULL, name text NOT NULL, v text, PRIMARY KEY (tenant_id, name));`
	vs, _ := with(sql, decl("public.settings", "DM-16", "Directory", "")).run(t, "18")
	want(t, vs, "X3", "key-identity-column", "settings_pkey", "name")

	vs, _ = with(sql, decl("public.settings", "DM-16", "Directory", `, NameOK: []string{"name"}`)).run(t, "18")
	wantNone(t, vs)

	// Listed, but no rule trips: the exemption is stale. A missing column is a stale declaration.
	vs, _ = with(`CREATE TABLE settings (tenant_id uuid NOT NULL, k text NOT NULL, PRIMARY KEY (tenant_id, k));`,
		decl("public.settings", "DM-16", "Directory", `, NameOK: []string{"k", "gone"}`)).run(t, "18")
	want(t, vs, "REG", "exemption-stale", "public.settings.k")
	want(t, vs, "REG", "declaration-stale", "public.settings.gone")
}

func TestX3AppliesOnlyToDirectoryTables(t *testing.T) {
	// The same unique index on a tenant (T) table is fine: X3 is about directory identity.
	vs, _ := with(`CREATE TABLE account (tenant_id uuid NOT NULL, id uuid NOT NULL, upn text NOT NULL, PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, upn));`,
		decl("public.account", "DM-30", "Tenant", "")).run(t, "18")
	wantNone(t, vs)
}

func TestX5RuntimeRoleMayNotUpdateAppendOnly(t *testing.T) {
	audit := `CREATE TABLE audit_event (tenant_id uuid NOT NULL, seq bigint NOT NULL, kind text NOT NULL, PRIMARY KEY (tenant_id, seq));`
	auditDecl := decl("public.audit_event", "DM-80", "Tenant", ", AppendOnly: true")
	cases := []struct {
		name, sql, rule, named string
	}{
		// The default privileges grant the runtime role UPDATE and DELETE; a migration that forgets the REVOKE fails.
		{"audit event with the default grants (acceptance 2)", audit, "runtime-update", "public.audit_event"},
		{"audit event, UPDATE granted back", audit + `REVOKE UPDATE, DELETE ON audit_event FROM activediq_app; GRANT UPDATE ON audit_event TO activediq_app;`, "runtime-update", "public.audit_event"},
		{"audit event, DELETE kept", audit + `REVOKE UPDATE ON audit_event FROM activediq_app;`, "runtime-delete", "retention role"},
		{"audit event, TRUNCATE granted", audit + `REVOKE UPDATE, DELETE ON audit_event FROM activediq_app; GRANT TRUNCATE ON audit_event TO activediq_app;`, "runtime-truncate", "public.audit_event"},
		{"audit event, UPDATE on one column", audit + `REVOKE UPDATE, DELETE ON audit_event FROM activediq_app; GRANT UPDATE (kind) ON audit_event TO activediq_app;`, "runtime-update-column", "public.audit_event"},
		{"audit event, UPDATE granted to PUBLIC", audit + `REVOKE UPDATE, DELETE ON audit_event FROM activediq_app; GRANT UPDATE ON audit_event TO PUBLIC;`, "runtime-update", "public.audit_event"},
		{"audit event, UPDATE granted to another role", audit + `REVOKE UPDATE, DELETE ON audit_event FROM activediq_app; GRANT UPDATE ON audit_event TO fx_reader;`, "grant-update", "fx_reader"},
		{"audit event, DELETE granted to another role", audit + `REVOKE UPDATE, DELETE ON audit_event FROM activediq_app; GRANT DELETE ON audit_event TO fx_reader;`, "grant-delete", "fx_reader"},
		{"audit event, retention role granted UPDATE", audit + `REVOKE UPDATE, DELETE ON audit_event FROM activediq_app; GRANT UPDATE ON audit_event TO activediq_retention;`, "grant-update", DefaultRetentionRole},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs, _ := with(c.sql, auditDecl).run(t, "18")
			want(t, vs, "X5", c.rule, c.named, "X5")
		})
	}
	t.Run("change record with the default grants", func(t *testing.T) {
		g := good()
		g.migrations["0002_directory_inventory.sql"] = strings.Replace(goodSQL, "REVOKE UPDATE, DELETE ON change_record FROM activediq_app;", "", 1)
		vs, _ := g.run(t, "18")
		want(t, vs, "X5", "runtime-update", "public.change_record", "X5")
	})
	t.Run("the revoked table with the retention role's DELETE passes", func(t *testing.T) {
		vs, _ := with(audit+`REVOKE UPDATE, DELETE ON audit_event FROM activediq_app; GRANT DELETE ON audit_event TO activediq_retention;`, auditDecl).run(t, "18")
		wantNone(t, vs)
	})
}

func TestX5PartitionsFollowTheirRoot(t *testing.T) {
	sql := `
CREATE TABLE audit_event (tenant_id uuid NOT NULL, seq bigint NOT NULL, PRIMARY KEY (tenant_id, seq)) PARTITION BY RANGE (seq);
CREATE TABLE audit_event_p1 PARTITION OF audit_event FOR VALUES FROM (0) TO (1000);
REVOKE UPDATE, DELETE ON audit_event FROM activediq_app;`
	d := decl("public.audit_event", "DM-80", "Tenant", ", AppendOnly: true")
	vs, _ := with(sql, d).run(t, "18")
	want(t, vs, "X5", "runtime-update", "public.audit_event_p1") // the partition kept the default grants
	if len(vs) != 2 {                                            // UPDATE and DELETE on the partition
		t.Errorf("expected the partition's UPDATE and DELETE only, got:\n%s", format(vs))
	}
	vs, _ = with(sql+`REVOKE UPDATE, DELETE ON audit_event_p1 FROM activediq_app;`, d).run(t, "18")
	wantNone(t, vs)
}

func TestX5NoStateColumn(t *testing.T) {
	revoke := `REVOKE UPDATE, DELETE ON %s FROM activediq_app;`
	d := decl("public.approval", "DM-80", "Tenant", ", AppendOnly: true")
	for _, col := range []string{"state", "status", "lifecycle_state", "phase", "archived_status"} {
		t.Run(col, func(t *testing.T) {
			sql := fmt.Sprintf(`CREATE TABLE approval (tenant_id uuid NOT NULL, id uuid NOT NULL, %s text NOT NULL DEFAULT 'x', PRIMARY KEY (tenant_id, id));`+revoke, col, "approval")
			vs, _ := with(sql, d).run(t, "18")
			want(t, vs, "X5", "state-column", "public.approval."+col, "derived")
		})
	}
	t.Run("an enum type named like a state", func(t *testing.T) {
		sql := `CREATE TYPE approval_state AS ENUM ('open', 'closed');
CREATE TABLE approval (tenant_id uuid NOT NULL, id uuid NOT NULL, s approval_state, PRIMARY KEY (tenant_id, id));` + fmt.Sprintf(revoke, "approval")
		vs, _ := with(sql, d).run(t, "18")
		want(t, vs, "X5", "state-column", "public.approval.s")
	})
	t.Run("a fact column listed in NameOK", func(t *testing.T) {
		sql := `CREATE TABLE approval (tenant_id uuid NOT NULL, id uuid NOT NULL, http_status int NOT NULL, PRIMARY KEY (tenant_id, id));` + fmt.Sprintf(revoke, "approval")
		vs, _ := with(sql, d).run(t, "18")
		want(t, vs, "X5", "state-column", "http_status")
		vs, _ = with(sql, decl("public.approval", "DM-80", "Tenant", `, AppendOnly: true, NameOK: []string{"http_status"}`)).run(t, "18")
		wantNone(t, vs)
	})
	t.Run("a mutable table may have a state", func(t *testing.T) {
		vs, _ := with(`CREATE TABLE account (tenant_id uuid NOT NULL, id uuid NOT NULL, state text, PRIMARY KEY (tenant_id, id));`,
			decl("public.account", "DM-30", "Tenant", "")).run(t, "18")
		wantNone(t, vs)
	})
}

func TestX4SecretAttributeColumns(t *testing.T) {
	cases := []struct{ name, col, comment, attr string }{
		{"unicodePwd as a column (acceptance 3)", "unicode_pwd", "", "unicodePwd"},
		{"LAPS legacy password", "ms_mcs_admpwd", "", "ms-Mcs-AdmPwd"},
		{"LAPS password, camel case in quotes", `"msLAPS-Password"`, "", "msLAPS-Password"},
		{"BitLocker recovery password inside a longer name", "old_msfve_recovery_password", "", "msFVE-RecoveryPassword"},
		{"annotated under an innocent name", "blob", "diq:attr=msTPM-OwnerInformation", "msTPM-OwnerInformation"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sql := fmt.Sprintf(`CREATE TABLE host_secret (tenant_id uuid NOT NULL, id uuid NOT NULL, %s text, PRIMARY KEY (tenant_id, id));`, c.col)
			if c.comment != "" {
				sql += fmt.Sprintf(`COMMENT ON COLUMN host_secret.%s IS '%s';`, c.col, c.comment)
			}
			vs, _ := with(sql, decl("public.host_secret", "DM-30", "Tenant", "")).run(t, "18")
			want(t, vs, "X4", "secret-attr-column", "public.host_secret", c.attr, "X4", "LF-38")
		})
	}
	t.Run("a sealed column named for an attribute is allowed only when declared Sealed", func(t *testing.T) {
		sql := `CREATE TABLE host_secret (tenant_id uuid NOT NULL, id uuid NOT NULL, unicode_pwd_sealed bytea, PRIMARY KEY (tenant_id, id));`
		vs, _ := with(sql, decl("public.host_secret", "DM-30", "Tenant", "")).run(t, "18")
		want(t, vs, "X4", "secret-attr-column", "unicode_pwd_sealed")
		vs, _ = with(sql, decl("public.host_secret", "DM-30", "Tenant", `, Sealed: []string{"unicode_pwd_sealed"}`)).run(t, "18")
		wantNone(t, vs)
	})
	t.Run("a Sealed column must be bytea and must exist", func(t *testing.T) {
		sql := `CREATE TABLE host_secret (tenant_id uuid NOT NULL, id uuid NOT NULL, sealed_secret text, PRIMARY KEY (tenant_id, id));`
		vs, _ := with(sql, decl("public.host_secret", "DM-30", "Tenant", `, Sealed: []string{"sealed_secret", "absent"}`)).run(t, "18")
		want(t, vs, "X4", "sealed-type", "public.host_secret.sealed_secret", "bytea")
		want(t, vs, "REG", "declaration-stale", "public.host_secret.absent")
	})
}

func TestDeclarationsCoverEveryTable(t *testing.T) {
	t.Run("an undeclared table", func(t *testing.T) {
		vs, _ := with(`CREATE TABLE sneaky (tenant_id uuid NOT NULL, id uuid NOT NULL, PRIMARY KEY (tenant_id, id));`, "").run(t, "18")
		want(t, vs, "REG", "table-undeclared", "public.sneaky", "tablekind.Declare")
	})
	t.Run("a declaration no migration backs", func(t *testing.T) {
		vs, _ := with("", decl("public.ghost", "DM-30", "Tenant", "")).run(t, "18")
		want(t, vs, "REG", "declaration-stale", "public.ghost")
	})
	t.Run("a platform table that is not registered global, and the reverse", func(t *testing.T) {
		g := with(`CREATE TABLE lease (id uuid PRIMARY KEY);`, decl("public.lease", "DM-06", "Platform", ""))
		vs, _ := g.run(t, "18")
		want(t, vs, "REG", "kind-global-mismatch", "public.lease", "global table")
		g = with(`CREATE TABLE lease (tenant_id uuid NOT NULL, id uuid NOT NULL, PRIMARY KEY (tenant_id, id));`, decl("public.lease", "DM-06", "Tenant", ""))
		g.registry = `{"globalTables": [{"table": "public.tenants", "reason": "r", "owner": "o"}, {"table": "public.lease", "reason": "r", "owner": "o"}]}`
		vs, _ = g.run(t, "18")
		want(t, vs, "REG", "kind-global-mismatch", "public.lease", "only a P table is global")
	})
	t.Run("a migration that does not apply", func(t *testing.T) {
		vs, _ := with(`CREATE TABLE broken (`, "").run(t, "18")
		want(t, vs, "REG", "migrations-apply", "0003_directory_extra.sql")
	})
}

// --- source rules: no database needed ---------------------------------------------------------------

func scan(t *testing.T, decls string, files map[string]string) (*Source, []Violation) {
	t.Helper()
	root := tree{decls: decls, files: files}.write(t)
	src, vs, err := ScanSource(root, "fx.test")
	if err != nil {
		t.Fatal(err)
	}
	return src, vs
}

func TestScanReadsDeclarations(t *testing.T) {
	src, vs := scan(t, goodDecls, nil)
	wantNone(t, vs)
	if len(src.Decls) != 4 {
		t.Fatalf("want 4 declarations, got %d", len(src.Decls))
	}
	var co *Declaration
	for i := range src.Decls {
		if src.Decls[i].Name == "public.credential" {
			co = &src.Decls[i]
		}
	}
	if co == nil || co.Entity != "DM-11" || co.Kind != "T" || len(co.Sealed) != 2 || co.Pos != "internal/x/tables.go:8" {
		t.Fatalf("declaration misread: %+v", co)
	}
}

func TestScanRefusesWhatItCannotRead(t *testing.T) {
	cases := []struct{ name, decls, rule string }{
		{"a variable", "var n = \"public.t\"\nvar _ = tablekind.Declare(tablekind.Table{Name: n, Entity: \"DM-30\", Kind: tablekind.Tenant})\n", "declaration-literal"},
		{"a computed kind", "var k = tablekind.Tenant\nvar _ = tablekind.Declare(tablekind.Table{Name: \"public.t\", Entity: \"DM-30\", Kind: k})\n", "declaration-literal"},
		{"a positional literal", "var _ = tablekind.Declare(tablekind.Table{\"public.t\", \"DM-30\", tablekind.Tenant, false, nil, nil})\n", "declaration-literal"},
		{"a missing field", "var _ = tablekind.Declare(tablekind.Table{Name: \"public.t\", Kind: tablekind.Tenant})\n", "declaration-literal"},
		{"an unknown field", "var _ = tablekind.Declare(tablekind.Table{Name: \"public.t\", Entity: \"DM-30\", Kind: tablekind.Tenant, Owner: \"x\"})\n", "declaration-literal"},
		{"a malformed name", "var _ = tablekind.Declare(tablekind.Table{Name: \"t\", Entity: \"DM-30\", Kind: tablekind.Tenant})\n", "declaration-literal"},
		{"Declare on a variable", "var t0 = tablekind.Table{Name: \"public.t\", Entity: \"DM-30\", Kind: tablekind.Tenant}\nvar _ = tablekind.Declare(t0)\n", "declaration-site"},
		{"a literal that is never declared", "var t0 = tablekind.Table{Name: \"public.t\", Entity: \"DM-30\", Kind: tablekind.Tenant}\n", "declaration-site"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, vs := scan(t, c.decls, nil)
			want(t, vs, "REG", c.rule, "internal/x/tables.go:")
			if len(src.Decls) != 0 {
				t.Errorf("an unreadable declaration was accepted: %+v", src.Decls)
			}
		})
	}
}

func TestScanFollowsImportAliasAndIgnoresTests(t *testing.T) {
	aliased := "package y\n\nimport tk \"fx.test/internal/platform/tablekind\"\n\nvar _ = tk.Declare(tk.Table{Name: \"public.a\", Entity: \"DM-30\", Kind: tk.Tenant})\n"
	inTest := "package y\n\nimport \"fx.test/internal/platform/tablekind\"\n\nvar _ = tablekind.Declare(tablekind.Table{Name: \"public.fixture\", Entity: \"DM-30\", Kind: tablekind.Tenant})\n"
	src, vs := scan(t, "", map[string]string{"internal/y/a.go": aliased, "internal/y/a_test.go": inTest})
	wantNone(t, vs)
	if len(src.Decls) != 1 || src.Decls[0].Name != "public.a" {
		t.Fatalf("want the aliased declaration only, got %+v", src.Decls)
	}
}

func decls(t *testing.T, body string) *Source {
	t.Helper()
	src, vs := scan(t, body, nil)
	wantNone(t, vs)
	return src
}

func entities(t *testing.T) map[string]Entity {
	t.Helper()
	p := filepath.Join(t.TempDir(), "m.md")
	if err := os.WriteFile(p, []byte(fxModel), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := LoadEntities(p)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDeclarationsAgreeWithTheDomainModel(t *testing.T) {
	es := entities(t)
	if e := es["DM-06"]; e.Kind != "" || es["DM-18"].Kind != "D" || !es["DM-18"].AppendOnly || !es["DM-25"].AppendOnly || es["DM-80"].Kind != "T" {
		t.Fatalf("headings misread: %+v", es)
	}
	cases := []struct{ name, body, rule string }{
		{"kind differs from the model", decl("public.a", "DM-16", "Tenant", ""), "kind-mismatch"},
		{"a registry entity has no table", decl("public.a", "DM-33", "Tenant", ""), "kind-mismatch"},
		{"an append-only entity declared mutable", decl("public.a", "DM-18", "Directory", ""), "append-only-missing"},
		{"insert-only counts the same", decl("public.a", "DM-25", "Tenant", ""), "append-only-missing"},
		{"append-only claimed for a mutable entity", decl("public.a", "DM-30", "Tenant", ", AppendOnly: true"), "append-only-unfounded"},
		{"an entity the model lacks", decl("public.a", "DM-99", "Tenant", ""), "entity-unknown"},
		{"the same table twice", decl("public.a", "DM-30", "Tenant", "") + decl("public.a", "DM-30", "Tenant", ""), "declaration-duplicate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs := checkDeclarations(decls(t, c.body), es)
			want(t, vs, "REG", c.rule, "public.a")
		})
	}
	// A heading that names two kinds ("P and T") is not cross-checked, either kind is declarable.
	wantNone(t, checkDeclarations(decls(t, decl("public.lease", "DM-06", "Platform", "")+decl("public.lease_t", "DM-06", "Tenant", "")), es))
}

func TestDM25RetentionPropertyMustExist(t *testing.T) {
	es := entities(t)
	override := decl("public.override", "DM-25", "Tenant", ", AppendOnly: true")
	src, _ := scan(t, override, nil)
	vs := checkDeclarations(src, es)
	want(t, vs, "X5", "property-missing", "DM-25.I6", "TestProperty_DM25_I6")

	test := "package y\n\nimport \"testing\"\n\nfunc TestProperty_DM25_I6_RetentionKeepsDerivedState(t *testing.T) {}\n"
	src, _ = scan(t, override, map[string]string{"internal/y/override_test.go": test})
	wantNone(t, checkDeclarations(src, es))

	// A method, or a name that only resembles the test, does not count.
	wrong := "package y\n\nimport \"testing\"\n\nfunc TestProperty_DM25_I60(t *testing.T) {}\nfunc (s S) TestProperty_DM25_I6(t *testing.T) {}\ntype S struct{}\n"
	src, _ = scan(t, override, map[string]string{"internal/y/override_test.go": wrong})
	want(t, checkDeclarations(src, es), "X5", "property-missing", "DM-25.I6")

	// No DM-25 table, nothing to demand yet.
	src, _ = scan(t, tenantsDecl, nil)
	wantNone(t, checkDeclarations(src, es))
}

func TestMissingDomainModelIsAnError(t *testing.T) {
	if _, err := LoadEntities(filepath.Join(t.TempDir(), "absent.md")); err == nil {
		t.Fatal("a missing domain model must stop the job, not switch the cross-check off")
	}
	p := filepath.Join(t.TempDir(), "empty.md")
	_ = os.WriteFile(p, []byte("# nothing\n"), 0o644)
	if _, err := LoadEntities(p); err == nil {
		t.Fatal("a document without entity headings must stop the job")
	}
}

func TestIdentityAndStateNames(t *testing.T) {
	for col, want := range map[string]string{
		"dn": "dn", "old_dn": "dn", "distinguished_name": "dn", "distinguishedName": "dn", "dn_hash": "dn",
		"sid": "sid", "object_sid": "sid", "sid_history": "sid", "samaccountname": "sam", "sam_account_name": "sam",
		"upn": "upn", "user_principal_name": "upn", "display_name": "name", "name": "name", "cn": "name", "common_name": "name",
		"object_guid": "", "connection_id": "", "tenant_id": "", "dns_zone": "", "did": "", "side": "", "ends_at": "",
	} {
		if got := identityHolds(col); got != want {
			t.Errorf("identityHolds(%q) = %q, want %q", col, got, want)
		}
	}
	for s, want := range map[string]bool{
		"state": true, "status": true, "lifecycle_state": true, "retention_phase": true, "state_changed_at": true,
		"statement": false, "estate": false, "outcome": false, "kind": false, "at": false, "verdict": false,
	} {
		if got := stateName(s); got != want {
			t.Errorf("stateName(%q) = %v, want %v", s, got, want)
		}
	}
	attrs := []string{"unicodePwd", "ms-Mcs-AdmPwd", "dBCSPwd", "msLAPS-Password"}
	for col, want := range map[string]string{
		"unicode_pwd": "unicodePwd", "UnicodePwd": "unicodePwd", "ms_mcs_admpwd": "ms-Mcs-AdmPwd", "x_mslaps_password_x": "msLAPS-Password",
		"dbcspwd": "dBCSPwd", "password": "", "pwd_last_set": "", "tenant_id": "", "sealed_secret": "",
	} {
		if got := secretAttrFor(col, "", attrs); got != want {
			t.Errorf("secretAttrFor(%q) = %q, want %q", col, got, want)
		}
	}
	// seven letters or fewer match exactly only
	if got := secretAttrFor("my_dbcspwd_copy", "", attrs); got != "" {
		t.Errorf("a short attribute name matched inside a longer column: %q", got)
	}
}
