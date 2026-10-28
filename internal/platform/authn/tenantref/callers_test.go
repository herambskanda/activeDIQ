package tenantref_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// permitted lists every non-test package that may call tenantref (ADR-0002 rule 5). Each holds text that
// authentication or the runner already put on the principal, the authority context or the transaction.
// Adding a caller here is a security review item: the text must never come from a request body, path or
// query (the unauthenticated attestation callback is a registry-listed mint instead).
var permitted = map[string]string{
	"internal/compose/server":           "console.go p.Tenant (authenticated session); tier0.go authority.TenantFrom",
	"internal/directory/client":         "reads_tunnel.go authority context set by the runner",
	"internal/modules/connections":      "attest_http.go p.Tenant (session); reconfirm.go runner payload tenant",
	"internal/platform/rbac":            "grants.go app.tenant_id set by store.WithTenant",
	"internal/platform/authn/tenantref": "the package itself",
}

func TestOnlyPermittedPackagesCallTenantref(t *testing.T) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	err = filepath.WalkDir(filepath.Join(root, "internal"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "tenantref.TenantFrom") {
			rel, _ := filepath.Rel(root, filepath.Dir(p))
			found[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for d := range found {
		if _, ok := permitted[d]; !ok {
			bad = append(bad, d)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("packages call tenantref without being permitted (add with security review): %v", bad)
	}
}
