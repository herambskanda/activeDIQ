package tenantref_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const importSuffix = "internal/platform/authn/tenantref"

// permitted lists every non-test FILE that may import tenantref (ADR-0002 rule 5). Each holds text that
// authentication or the runner already put on the principal, the authority context or the transaction.
// Adding a file here is a security review item: the text must never come from a request body, path or
// query (the unauthenticated attestation callback is a registry-listed mint instead).
var permitted = map[string]string{
	"internal/compose/server/console.go":             "p.Tenant (authenticated session)",
	"internal/compose/server/tier0.go":               "authority.TenantFrom (set by the runner)",
	"internal/directory/client/reads_tunnel.go":      "authority context set by the runner",
	"internal/modules/connections/attest_http.go":    "p.Tenant (session principal)",
	"internal/modules/compliance/hold.go":            "app.tenant_id of the runner transaction in Plan; payload tenant set in Plan",
	"internal/modules/connections/reconfirm.go":      "runner payload tenant, set in Plan from app.tenant_id",
	"internal/platform/fleet/fleetsql/enrollment.go": "p.Tenant (authenticated principal) compared to the tid argument",
	"internal/platform/fleet/fleetsql/reenrol.go":    "p.Tenant (authenticated principal) compared to the tid argument",
	"internal/platform/fleet/fleetsql/revoke.go":     "p.Tenant (authenticated principal) compared to the tid argument",
	"internal/platform/fleet/fleetsql/withdraw.go":   "p.Tenant (authenticated principal) compared to the tid argument",
	"internal/platform/notify/syslog/http.go":        "p.Tenant (session principal)",
	"internal/platform/rbac/grants.go":               "app.tenant_id set by store.WithTenant",
}

// scanRoots are the trees the T5 fitness check walks (tools/fitness/tenancy/static/run.go); cmd/ may
// import an internal package of the same module, so it must be scanned too.
var scanRoots = []string{"cmd", "internal"}

// allImporters scans every scanRoot that exists under root.
func allImporters(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	for _, top := range scanRoots {
		dir := filepath.Join(root, top)
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		out = append(out, importers(t, root, dir)...)
	}
	sort.Strings(out)
	return out
}

// importers returns the slash-separated, root-relative non-test .go files under dir that import tenantref
// under any name (aliased, dot or blank), matched on the import path rather than on source text.
func importers(t *testing.T, root, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			path, _ := strconv.Unquote(im.Path.Value)
			if path == importSuffix || strings.HasSuffix(path, "/"+importSuffix) {
				rel, _ := filepath.Rel(root, p)
				out = append(out, filepath.ToSlash(rel))
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func unpermitted(files []string) []string {
	var bad []string
	for _, f := range files {
		if strings.HasPrefix(f, "internal/platform/authn/tenantref/") {
			continue
		}
		if _, ok := permitted[f]; !ok {
			bad = append(bad, f)
		}
	}
	return bad
}

func TestOnlyPermittedFilesImportTenantref(t *testing.T) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	if bad := unpermitted(allImporters(t, root)); len(bad) > 0 {
		t.Fatalf("files import tenantref without being permitted (add with security review): %v", bad)
	}
}

func TestImporterScanCatchesBypasses(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	imp := `"example.com/m/internal/platform/authn/tenantref"`
	write("internal/zzbypass/x.go", "package x\nimport tr "+imp+"\nvar _ = tr.TenantFromText\n")
	write("internal/zzdot/x.go", "package x\nimport . "+imp+"\n")
	write("internal/zzblank/x.go", "package x\nimport _ "+imp+"\n")
	// A new file inside an already permitted package is caught because the pin is per file.
	write("internal/platform/rbac/newfile.go", "package rbac\nimport "+imp+"\nvar _ = tenantref.TenantFromText\n")
	write("internal/platform/rbac/grants.go", "package rbac\nimport "+imp+"\n")
	write("cmd/zzbypass/x.go", "package main\nimport tr "+imp+"\nvar _ = tr.TenantFromText\nfunc main() {}\n")
	write("internal/other/ok.go", "package other\nimport \"fmt\"\nvar _ = fmt.Sprint\n")

	got := unpermitted(allImporters(t, root))
	want := []string{
		"cmd/zzbypass/x.go",
		"internal/platform/rbac/newfile.go",
		"internal/zzblank/x.go",
		"internal/zzbypass/x.go",
		"internal/zzdot/x.go",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}
