package main

// Every rule has a fixture that breaks only that rule and must be reported (a check without a failing
// case is not a check), plus clean fixtures that must stay silent.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	sqlDir = "internal/platform/fleet/fleetsql/"
	okSign = "package fleetsql\n\nimport \"crypto/x509\"\n\nfunc (e *Enroller) SignServerLeaf(names []string) { s := e.serverSigner(); x509.CreateCertificate(nil, nil, nil, nil, s) }\n" +
		"func (e *Enroller) serverSigner() int { return 0 }\n"
	okMig = "CREATE TABLE public.fleet_server_ca (\n id uuid PRIMARY KEY,\n sealed_key bytea CHECK (octet_length(sealed_key) BETWEEN 32 AND 16384)\n);\n"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func run(t *testing.T, files map[string]string) (out, pending []string) {
	t.Helper()
	root := tree(t, files)
	g, err := loadGo(root)
	if err != nil {
		t.Fatal(err)
	}
	sv, sp, present, err := checkSchema(root)
	if err != nil {
		t.Fatal(err)
	}
	vs, p := checkAll(g, present)
	for _, v := range append(vs, sv...) {
		out = append(out, v.String())
	}
	return out, append(p, sp...)
}

func TestRules(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string // substring; "" = clean
	}{
		{"clean landed feature", map[string]string{sqlDir + "s.go": okSign, "migrations/0099_x.sql": okMig}, ""},
		{"clean tree, nothing landed", map[string]string{"internal/a/a.go": "package a\n"}, ""},

		{"FCS-1 signer called from another function", map[string]string{sqlDir + "s.go": okSign + "func (e *Enroller) Sneak() { e.serverSigner() }\n"}, "FCS-1 [signer-callers]"},
		{"FCS-1 signer called outside fleetsql", map[string]string{sqlDir + "s.go": okSign, "internal/x/x.go": "package x\n\nfunc f(e E) { e.serverSigner() }\n"}, "FCS-1 [signer-callers]"},
		{"FCS-1 new CreateCertificate site in fleetsql", map[string]string{sqlDir + "s.go": okSign + "func mint() { x509.CreateCertificate(nil, nil, nil, nil, nil) }\n"}, "FCS-1 [create-certificate]"},
		{"FCS-1 table named outside fleetsql", map[string]string{sqlDir + "s.go": okSign, "internal/x/x.go": "package x\n\nvar q = `SELECT sealed_key FROM public.fleet_server_ca`\n"}, "FCS-1 [table-owner]"},
		{"FCS-1 migration without signer", map[string]string{"migrations/0099_x.sql": okMig}, "FCS-1 [half-landed]"},
		{"FCS-1 signer without SignServerLeaf", map[string]string{sqlDir + "s.go": "package fleetsql\n\nfunc (e *Enroller) serverSigner() int { return 0 }\n"}, "FCS-1 [half-landed]"},

		{"FCS-2 takes a CSR", map[string]string{sqlDir + "s.go": strings.Replace(okSign, "names []string", "csr *x509.CertificateRequest", 1)}, "FCS-2 [caller-key]"},
		{"FCS-2 takes a public key", map[string]string{sqlDir + "s.go": strings.Replace(okSign, "names []string", "pub crypto.PublicKey", 1)}, "FCS-2 [caller-key]"},
		{"FCS-2 takes DER bytes", map[string]string{sqlDir + "s.go": strings.Replace(okSign, "names []string", "der []byte", 1)}, "FCS-2 [caller-key]"},
		{"FCS-2 ClientAuth EKU", map[string]string{sqlDir + "s.go": strings.Replace(okSign, "s := ", "_ = x509.ExtKeyUsageClientAuth; s := ", 1)}, "FCS-2 [eku]"},
		{"FCS-2 any EKU", map[string]string{sqlDir + "s.go": strings.Replace(okSign, "s := ", "_ = x509.ExtKeyUsageAny; s := ", 1)}, "FCS-2 [eku]"},
		{"FCS-2 URI SAN", map[string]string{sqlDir + "s.go": strings.Replace(okSign, "s := ", "_ = x509.Certificate{URIs: nil}; s := ", 1)}, "FCS-2 [uri-san]"},
		{"FCS-2 CA leaf", map[string]string{sqlDir + "s.go": strings.Replace(okSign, "s := ", "_ = x509.Certificate{IsCA: true}; s := ", 1)}, "FCS-2 [is-ca]"},

		{"FCS-3 gateway names the server CA", map[string]string{sqlDir + "s.go": okSign, "internal/platform/fleet/gateway/g.go": "package gateway\n\nfunc f() { pool.AddCert(serverCA) }\n"}, "FCS-3 [client-pool]"},
		{"FCS-3 gateway reads the table", map[string]string{"internal/platform/fleet/gateway/g.go": "package gateway\n\nvar q = \"fleet_server_ca\"\n"}, "FCS-3 [client-pool]"},
		{"FCS-3 TenantCAs includes the server CA", map[string]string{sqlDir + "c.go": "package fleetsql\n\nfunc (e *Enroller) TenantCAs() { out = append(out, e.serverCA) }\n"}, "FCS-3 [client-pool]"},
		{"FCS-3 gateway presenting a server cert is fine", map[string]string{"internal/platform/fleet/gateway/g.go": "package gateway\n\nfunc f(server tls.Certificate) {}\n"}, ""},

		{"FCS-4 dial roots on the whole bundle", map[string]string{"internal/platform/fleet/dial/d.go": "package dial\n\nfunc PinnedRoots() {}\nfunc f() { clientTLS(Pool(ca), h, nil) }\n"}, "FCS-4 [dial-roots]"},
		{"FCS-4 dial roots on pinned roots", map[string]string{"internal/platform/fleet/dial/d.go": "package dial\n\nfunc PinnedRoots() {}\nfunc f() { clientTLS(Pool(PinnedRoots(b, p)), h, nil); clientTLS(x509.NewCertPool(), h, nil) }\n"}, ""},
		{"FCS-4 dial rule inactive before PinnedRoots", map[string]string{"internal/platform/fleet/dial/d.go": "package dial\n\nfunc f() { clientTLS(Pool(ca), h, nil) }\n"}, ""},

		{"FCS-5 tenant_id column", map[string]string{"migrations/0099_x.sql": strings.Replace(okMig, "id uuid", "tenant_id uuid,\n id uuid", 1), sqlDir + "s.go": okSign}, "FCS-5 [tenant-id]"},
		{"FCS-5 tenant_id added later", map[string]string{"migrations/0099_x.sql": okMig, "migrations/0100_y.sql": "ALTER TABLE public.fleet_server_ca ADD COLUMN tenant_id uuid;\n", sqlDir + "s.go": okSign}, "FCS-5 [tenant-id]"},
		{"FCS-5 no sealed_key CHECK", map[string]string{"migrations/0099_x.sql": "CREATE TABLE public.fleet_server_ca (id uuid, sealed_key bytea);\n", sqlDir + "s.go": okSign}, "FCS-5 [sealed-key-check]"},
		{"FCS-5 tenant_id in a comment is fine", map[string]string{"migrations/0099_x.sql": "-- no tenant_id here\n" + okMig, sqlDir + "s.go": okSign}, ""},

		{"FCS-6 three certificates", map[string]string{"internal/compose/server/f.go": "package server\n\nvar c = tls.Certificate{Certificate: [][]byte{leaf, ca, tenantCA}}\n"}, "FCS-6 [chain-length]"},
		{"FCS-6 one certificate", map[string]string{"internal/compose/server/f.go": "package server\n\nvar c = tls.Certificate{Certificate: [][]byte{leaf}}\n"}, "FCS-6 [chain-length]"},
		{"FCS-6 appended chain", map[string]string{"internal/platform/fleet/gateway/f.go": "package gateway\n\nvar c = tls.Certificate{Certificate: append(chain, x)}\n"}, "FCS-6 [chain-append]"},
		{"FCS-6 two certificates", map[string]string{"internal/compose/server/f.go": "package server\n\nvar c = tls.Certificate{Certificate: [][]byte{leaf, ca}}\n"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := run(t, c.files)
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("expected clean, got %v", got)
				}
				return
			}
			for _, g := range got {
				if strings.Contains(g, c.want) {
					return
				}
			}
			t.Fatalf("want a violation containing %q, got %v", c.want, got)
		})
	}
}

func TestPendingListedUntilLanded(t *testing.T) {
	_, p := run(t, map[string]string{"internal/a/a.go": "package a\n"})
	joined := strings.Join(p, "\n")
	for _, want := range []string{"FCS-1/FCS-2", "FCS-4 dial roots", "FCS-5 fleet_server_ca schema"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing pending %q in %v", want, p)
		}
	}
	_, p = run(t, map[string]string{sqlDir + "s.go": okSign, "migrations/0099_x.sql": okMig})
	if strings.Contains(strings.Join(p, "\n"), "FCS-5 fleet_server_ca schema") || strings.Contains(strings.Join(p, "\n"), "FCS-1/FCS-2") {
		t.Fatalf("landed parts must not be pending: %v", p)
	}
}

func TestBindings(t *testing.T) {
	// not landed but the test exists: violation
	root := tree(t, map[string]string{"internal/platform/fleet/gateway/g_test.go": "package gateway\n\nimport \"testing\"\n\nfunc TestServerCAAbsentFromClientPool(t *testing.T) {}\n"})
	files, _ := loadGo(root)
	vs, pend, err := runBindings(context.Background(), root, files, defaultBindings, func(context.Context, string, string, []string) ([]byte, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].Rule != "binding-not-landed" || len(pend) != len(defaultBindings) {
		t.Fatalf("got %v pending %d", vs, len(pend))
	}
	// landed: missing, failed and skipped tests are each a violation, a pass is not
	b := []binding{{"FCS-3", "w", "./p", []string{"TestA", "TestB", "TestC", "TestD"}, true}}
	out := `{"Action":"pass","Test":"TestA"}
{"Action":"fail","Test":"TestB"}
{"Action":"skip","Test":"TestC"}
`
	vs, _, err = runBindings(context.Background(), ".", nil, b, func(context.Context, string, string, []string) ([]byte, error) { return []byte(out), nil })
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]string{}
	for _, v := range vs {
		rules[v.Where] = v.Rule
	}
	if len(vs) != 3 || rules["./p TestB"] != "test-failed" || rules["./p TestC"] != "test-skipped" || rules["./p TestD"] != "test-missing" {
		t.Fatalf("got %v", vs)
	}
}
