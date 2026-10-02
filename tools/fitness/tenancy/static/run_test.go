package static

// T5 tests (ADR-0002 acceptance 4 and 5): each rule runs on a throw-away Go module that holds the
// platform packages in the layout of blueprint §1.1, stub pgx and River modules, and one offending
// file. The module is type-checked for real, so what is proven is what the CI job does.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/tools/fitness/tenancy/registry"
)

const module = "fx.test"

// baseFiles is a clean product: every platform package, using its powers where it may.
var baseFiles = map[string]string{
	"internal/platform/tenant/tenant.go": `package tenant

// ID is a tenant identifier. It has no decoder: only the owner packages can mint one.
type ID [16]byte

func (i ID) String() string { return "" }

// FromBytes mints an ID.
func FromBytes(b [16]byte) ID { return ID(b) }
`,
	"internal/platform/store/store.go": `package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"fx.test/internal/platform/tenant"
)

type Tx struct{ c *pgx.Conn }

func WithTenantTx(ctx context.Context, id tenant.ID, fn func(Tx) error) error {
	_ = "SELECT set_config('app.tenant_id', $1, true)"
	return fn(Tx{})
}

func WithPlatform(ctx context.Context, fn func(Tx) error) error { return fn(Tx{}) }
`,
	"internal/platform/authn/authn.go": `package authn

import "fx.test/internal/platform/tenant"

func Principal() tenant.ID { return tenant.ID{1} }
`,
	"internal/platform/jobs/jobs.go": `package jobs

import (
	"github.com/riverqueue/river"

	"fx.test/internal/platform/tenant"
)

var _ = river.Client{}

func Decode(b [16]byte) tenant.ID { return tenant.ID(b) }
`,
}

const stubPgx = "package pgx\n\ntype Conn struct{}\n"
const stubRiver = "package river\n\ntype Client struct{}\n"

// build writes baseFiles plus extra into a temp module and returns its root.
func build(t *testing.T, extra map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, s string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module "+module+"\n\ngo 1.22\n\nrequire (\n\tgithub.com/jackc/pgx/v5 v5.0.0\n\tgithub.com/riverqueue/river v0.0.0\n)\n\n"+
		"replace github.com/jackc/pgx/v5 => ./stubs/pgx\nreplace github.com/riverqueue/river => ./stubs/river\n")
	write("stubs/pgx/go.mod", "module github.com/jackc/pgx/v5\n\ngo 1.22\n")
	write("stubs/pgx/pgx.go", stubPgx)
	write("stubs/river/go.mod", "module github.com/riverqueue/river\n\ngo 1.22\n")
	write("stubs/river/river.go", stubRiver)
	for k, v := range baseFiles {
		write(k, v)
	}
	for k, v := range extra {
		write(k, v)
	}
	return root
}

func runStatic(t *testing.T, root string, reg *registry.Registry) []Finding {
	t.Helper()
	if reg == nil {
		reg = &registry.Registry{}
	}
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the fixture module must compile: %v\n%s", err, out)
	}
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOPROXY", "off")
	fs, err := Run(root, DefaultConfig(module, reg))
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func dump(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString("  " + f.String() + "\n")
	}
	return b.String()
}

// wantAt requires a finding of the rule at file:line.
func wantAt(t *testing.T, fs []Finding, rule, file string, line int) {
	t.Helper()
	for _, f := range fs {
		if f.Rule == rule && f.File == file && (line == 0 || f.Line == line) {
			return
		}
	}
	t.Errorf("no [%s] finding at %s:%d; got:\n%s", rule, file, line, dump(fs))
}

func wantNone(t *testing.T, fs []Finding) {
	t.Helper()
	if len(fs) > 0 {
		t.Fatalf("expected no findings; got:\n%s", dump(fs))
	}
}

func TestCleanModulePasses(t *testing.T) {
	wantNone(t, runStatic(t, build(t, nil), nil))
}

// Acceptance 4: file and line are named.
func TestMintingOutsideAllowedPackages(t *testing.T) {
	root := build(t, map[string]string{
		"internal/modules/m/m.go": `package m

import "fx.test/internal/platform/tenant"

func Literal() tenant.ID { return tenant.ID{1, 2} } // line 5

func Convert(b [16]byte) tenant.ID { return tenant.ID(b) } // line 7

func Via(b [16]byte) tenant.ID { return tenant.FromBytes(b) } // line 9

func Index(i tenant.ID) byte { return i[0] } // line 11

func Slice(i tenant.ID) []byte { return i[:] } // line 13
`,
		"internal/modules/m/m_test.go": `package m

import "fx.test/internal/platform/tenant"

func fixture() tenant.ID { return tenant.ID{9} } // a test may mint
`,
	})
	fs := runStatic(t, root, nil)
	for _, line := range []int{5, 7, 9, 11, 13} {
		wantAt(t, fs, RuleMint, "internal/modules/m/m.go", line)
	}
	for _, f := range fs {
		if strings.HasSuffix(f.File, "_test.go") {
			t.Errorf("a test file may mint a tenant.ID, got %s", f)
		}
	}
	if len(fs) != 5 {
		t.Errorf("want exactly 5 findings, got:\n%s", dump(fs))
	}
}

func TestMintingByRegisteredFunction(t *testing.T) {
	root := build(t, map[string]string{
		"internal/modules/enroll/enroll.go": `package enroll

import "fx.test/internal/platform/tenant"

func Bootstrap() tenant.ID { return tenant.ID{7} }

func Other() tenant.ID { return tenant.ID{8} }
`,
	})
	reg := &registry.Registry{PlatformPaths: []registry.PlatformPath{
		{Package: "internal/modules/enroll", Function: "Bootstrap", Reason: "first-run bootstrap", MintsTenantID: true},
	}}
	fs := runStatic(t, root, reg)
	wantAt(t, fs, RuleMint, "internal/modules/enroll/enroll.go", 7)
	if len(fs) != 1 {
		t.Errorf("only Other may be reported; got:\n%s", dump(fs))
	}
}

func TestWithPlatformCallSites(t *testing.T) {
	src := `package m

import (
	"context"

	"fx.test/internal/platform/store"
)

type S struct{}

func (S) Enroll(ctx context.Context) error {
	return store.WithPlatform(ctx, func(store.Tx) error { return nil }) // line 12
}

func Sneaky(ctx context.Context) error {
	return store.WithPlatform(ctx, func(store.Tx) error { return nil }) // line 16
}
`
	root := build(t, map[string]string{"internal/modules/m/m.go": src})
	reg := &registry.Registry{PlatformPaths: []registry.PlatformPath{
		{Package: "internal/modules/m", Function: "S.Enroll", Reason: "device enrolment is tenantless", WithPlatform: true},
	}}
	fs := runStatic(t, root, reg)
	wantAt(t, fs, RuleWithPlat, "internal/modules/m/m.go", 16)
	if len(fs) != 1 {
		t.Errorf("only Sneaky may be reported; got:\n%s", dump(fs))
	}
}

func TestImportBoundaries(t *testing.T) {
	root := build(t, map[string]string{
		"internal/modules/m/m.go": `package m

import (
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

var _ pgx.Conn
var _ river.Client
`,
	})
	fs := runStatic(t, root, nil)
	wantAt(t, fs, RulePgx, "internal/modules/m/m.go", 4)
	wantAt(t, fs, RuleRiver, "internal/modules/m/m.go", 5)
}

func TestSetConfigAndSetText(t *testing.T) {
	root := build(t, map[string]string{
		"internal/modules/m/m.go": `package m

const a = "SELECT set_config('app.tenant_id', 'x', false)" // line 3

const b = "SET LOCAL app.tenant_id = 'x'" // line 5

const c = "SET ROLE postgres" // line 7

const fine = "SELECT 1 FROM settings"
`,
		"internal/modules/m/queries.sql": "SELECT 1;\nSELECT set_config('app.tenant_id', 'x', true);\n",
	})
	fs := runStatic(t, root, nil)
	for _, line := range []int{3, 5, 7} {
		wantAt(t, fs, RuleSetConfig, "internal/modules/m/m.go", line)
	}
	wantAt(t, fs, RuleSetConfig, "internal/modules/m/queries.sql", 2)
	if len(fs) != 4 {
		t.Errorf("want 4 findings; got:\n%s", dump(fs))
	}
}

var tenantsGlobal = registry.GlobalTable{Table: "public.tenants", Reason: "the tenant directory", Owner: "internal/platform/tenant"}

func TestGlobalTableSQL(t *testing.T) {
	root := build(t, map[string]string{
		"internal/modules/m/m.go": `package m

const q = "SELECT id FROM public.tenants" // line 3

const ok = "SELECT id FROM tenant_settings"
`,
		"internal/modules/m/queries.sql":                   "-- name: ListTenants :many\nSELECT id\nFROM tenants;\n",
		"internal/platform/tenant/queries.sql":             "SELECT id FROM tenants;\n",
		"internal/platform/store/reportsql/identifiers.go": "package reportsql\n\nvar Tables = []string{\"tenants\"} // line 3\n",
	})
	fs := runStatic(t, root, &registry.Registry{GlobalTables: []registry.GlobalTable{tenantsGlobal}})
	wantAt(t, fs, RuleGlobalSQL, "internal/modules/m/m.go", 3)
	wantAt(t, fs, RuleGlobalSQL, "internal/modules/m/queries.sql", 3)
	wantAt(t, fs, RuleGlobalSQL, "internal/platform/store/reportsql/identifiers.go", 3)
	if len(fs) != 3 {
		t.Errorf("the owning package may name its table; want 3 findings, got:\n%s", dump(fs))
	}
}

func TestJobTypesCarryATenant(t *testing.T) {
	root := build(t, map[string]string{
		"internal/modules/m/jobs.go": `package m

import "fx.test/internal/platform/tenant"

type NoTenant struct{ N int }

func (NoTenant) Kind() string { return "no_tenant" } // the type is on line 5

type WithTenant struct {
	Tenant tenant.ID
	N      int
}

func (WithTenant) Kind() string { return "with_tenant" }

type Platform struct{}

func (Platform) Kind() string { return "platform" }

type NotAJob struct{}
`,
	})
	reg := &registry.Registry{PlatformJobs: []registry.PlatformJob{{Type: "internal/modules/m.Platform", Reason: "sweeps every tenant"}}}
	fs := runStatic(t, root, reg)
	wantAt(t, fs, RuleJob, "internal/modules/m/jobs.go", 5)
	if len(fs) != 1 {
		t.Errorf("only NoTenant may be reported; got:\n%s", dump(fs))
	}
}

func TestTenantIDHasNoDecoder(t *testing.T) {
	root := build(t, map[string]string{
		"internal/platform/tenant/decode.go": `package tenant

func (i *ID) UnmarshalText(b []byte) error { return nil } // line 3
`,
	})
	fs := runStatic(t, root, nil)
	wantAt(t, fs, RuleIDDecoders, "internal/platform/tenant/decode.go", 3)
}

// Acceptance 5: a registry entry that names something that does not exist fails.
func TestStaleRegistryEntries(t *testing.T) {
	root := build(t, map[string]string{
		"internal/modules/m/m.go": "package m\n\nfunc Real() {}\n",
	})
	reg := &registry.Registry{
		PlatformPaths: []registry.PlatformPath{
			{Package: "internal/modules/gone", Function: "F", Reason: "r", WithPlatform: true},
			{Package: "internal/modules/m", Function: "Missing", Reason: "r", WithPlatform: true},
			{Package: "internal/modules/m", Function: "Real", Reason: "r", WithPlatform: true},
			{Package: "internal/modules/m", Function: "Real", Reason: "r", MintsTenantID: true},
		},
		PlatformJobs: []registry.PlatformJob{{Type: "internal/modules/m.Nope", Reason: "r"}},
		GlobalTables: []registry.GlobalTable{{Table: "public.x", Reason: "r", Owner: "internal/modules/nowhere"}},
	}
	fs := runStatic(t, root, reg)
	var msgs []string
	for _, f := range fs {
		if f.Rule == "registry-stale" {
			msgs = append(msgs, f.Msg)
		}
	}
	for _, sub := range []string{
		"platformPaths[internal/modules/gone.F]: names a package that does not exist",
		"platformPaths[internal/modules/m.Missing]: names a function that does not exist",
		"platformPaths[internal/modules/m.Real]: is listed with withPlatform but the function no longer calls WithPlatform",
		"platformPaths[internal/modules/m.Real]: is listed with mintsTenantID but the function no longer mints a tenant.ID",
		"platformJobs[internal/modules/m.Nope]",
		"globalTables[public.x]: owning package directory internal/modules/nowhere does not exist",
	} {
		found := false
		for _, m := range msgs {
			if strings.Contains(m, sub) {
				found = true
			}
		}
		if !found {
			t.Errorf("no stale-registry finding %q; got:\n%s", sub, dump(fs))
		}
	}
}

func TestOpenAPITenantParameters(t *testing.T) {
	const doc = `openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /users:
    get:
      parameters:
        - {name: tenant_id, in: query, schema: {type: string}}
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: "#/components/schemas/NewUser"}
  /groups:
    get:
      parameters:
        - $ref: "#/components/parameters/TenantHeader"
  /clean:
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer}}
  /tenants:
    x-activediq-scope: platform
    get:
      parameters:
        - {name: tenant_id, in: query, schema: {type: string}}
components:
  parameters:
    TenantHeader: {name: X-Tenant-ID, in: header, schema: {type: string}}
  schemas:
    NewUser:
      type: object
      properties:
        name: {type: string}
        owner: {$ref: "#/components/schemas/Owner"}
    Owner:
      type: object
      properties:
        tenantId: {type: string}
        tenant_id: {type: string}
`
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "api", "openapi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "api", "openapi", "openapi.yaml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, present, err := CheckOpenAPI(root)
	if err != nil || !present {
		t.Fatalf("present=%v err=%v", present, err)
	}
	var got []string
	for _, f := range fs {
		got = append(got, f.Msg)
	}
	all := strings.Join(got, "\n")
	for _, sub := range []string{
		`GET /users is a tenant-scope operation and declares the query parameter "tenant_id"`,
		`POST /users is a tenant-scope operation and declares the body field "tenant_id"`,
		`GET /groups is a tenant-scope operation and declares the header parameter "X-Tenant-ID"`,
	} {
		if !strings.Contains(all, sub) {
			t.Errorf("missing finding %q in:\n%s", sub, all)
		}
	}
	if strings.Contains(all, "/clean") || strings.Contains(all, "/tenants") {
		t.Errorf("clean and platform-scope operations must not be reported:\n%s", all)
	}
	if _, present, _ := CheckOpenAPI(t.TempDir()); present {
		t.Error("with no api/openapi directory the check must report not present")
	}
}
