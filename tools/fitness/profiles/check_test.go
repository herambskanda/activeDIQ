package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests build a small repository in a temporary directory: a clean baseline that passes every
// check, then one deliberate violation per case (ADR-0002 fitness function, acceptance 2-5).

const adrRatified = "---\nstatus: ratified\n---\n# ADR\n"

var baseline = map[string]string{
	"go.mod": "module example.test/diq\n\ngo 1.27.0\n\nrequire github.com/jackc/pgx/v5 v5.9.2\n",
	"knowledge/development/decisions/0002-deployment-model.md": adrRatified,
	"knowledge/development/decisions/0009-draft.md":            "---\nstatus: proposed\n---\n",
	"tools/fitness/stack/manifest.json":                        `{"denylistExtends": ["tools/fitness/profiles/uem-denylist.json"]}`,
	"internal/platform/capability/capability.go": `package capability

type ID string

const (
	DirectoryAD    ID = "directory.ad"
	DirectoryEntra ID = "directory.entra"
	Provisioning   ID = "tenant-provisioning"
)
`,
	"internal/platform/tenant/tenant.go": "package tenant\n\nfunc New() int { return 1 }\n",
	"internal/compose/config/config.go": `package config

import "os"

func Load() string { return os.Getenv("ACTIVEDIQ_PROFILE") }
`,
	"internal/compose/profile/profile.go": `package profile

import "example.test/diq/internal/platform/capability"

type Role string

const (
	RoleServer    Role = "server"
	RoleConnector Role = "connector"
	RoleEdge      Role = "edge"
)

type Provider string

const (
	ProviderAD    Provider = "ad"
	ProviderEntra Provider = "entra"
)

type Process struct {
	Binary    string
	Roles     []Role
	Providers []Provider
}

type Exception struct{ What, ADR string }

type Manifest struct {
	Name         string
	Processes    []Process
	Capabilities []capability.ID
	Exceptions   []Exception
}
`,
	"internal/compose/profile/manifests.go": `package profile

import "example.test/diq/internal/platform/capability"

func Windows() Manifest {
	return Manifest{
		Name:         "windows",
		Processes:    []Process{{Binary: "server", Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderAD, ProviderEntra}}},
		Capabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra},
	}
}

func LinuxOCI() Manifest {
	return Manifest{
		Name:         "linux-oci",
		Processes:    []Process{{Binary: "server", Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderAD, ProviderEntra}}},
		Capabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra},
	}
}

func SaaS() Manifest {
	return Manifest{
		Name:         "saas",
		Processes:    []Process{{Binary: "server", Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderEntra}}},
		Capabilities: []capability.ID{capability.DirectoryEntra, capability.Provisioning},
	}
}
`,
	"cmd/server/main.go": `package main

import (
	"os"

	"example.test/diq/internal/compose/config"
	"example.test/diq/internal/compose/profile"
)

func main() { _ = os.Getenv; _ = config.Load; _ = profile.Windows }
`,
	"internal/directory/ldapfilter/f.go": "package ldapfilter\n\nimport \"example.test/diq/internal/platform/tenant\"\n\nvar _ = tenant.New\n",
}

// copyReal brings in the real manifest and denylist, so the tests exercise what `make ci` runs.
func copyReal(t *testing.T, files map[string]string) {
	t.Helper()
	for _, n := range []string{"manifest.json", "uem-denylist.json"} {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		files["tools/fitness/profiles/"+n] = string(b)
	}
}

// repo writes the baseline plus the given files (an empty string deletes a baseline file).
func repo(t *testing.T, extra map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{}
	for k, v := range baseline {
		files[k] = v
	}
	copyReal(t, files)
	for k, v := range extra {
		files[k] = v
	}
	for rel, body := range files {
		if body == "" {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

var onlyMain = Options{Branches: []string{"main", "factory/T-0038"}}

func run(t *testing.T, root string, checks ...string) []Violation {
	t.Helper()
	if len(checks) == 0 {
		checks = []string{"P1", "P7", "U1", "U2", "ACT"}
	}
	vs, _, err := Run(root, defaultManifest, checks, onlyMain)
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

// expect requires a violation of the check whose position starts with pos and whose message
// contains every fragment.
func expect(t *testing.T, vs []Violation, check, pos string, frags ...string) {
	t.Helper()
	for _, v := range vs {
		if v.Check == check && strings.HasPrefix(v.Pos, pos) {
			ok := true
			for _, f := range frags {
				ok = ok && strings.Contains(v.Msg, f)
			}
			if ok {
				return
			}
		}
	}
	t.Errorf("want %s at %s containing %q; got:\n%s", check, pos, frags, dump(vs))
}

func dump(vs []Violation) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString("  " + v.String() + "\n")
	}
	return b.String()
}

func TestBaselinePasses(t *testing.T) {
	if vs := run(t, repo(t, nil)); len(vs) != 0 {
		t.Fatalf("baseline should pass:\n%s", dump(vs))
	}
}

// --- P1 -----------------------------------------------------------------------------------

func TestP1DomainImportsCompose(t *testing.T) {
	root := repo(t, map[string]string{"internal/directory/dn/dn.go": "package dn\n\nimport \"example.test/diq/internal/compose/profile\"\n\nvar _ = profile.Windows\n"})
	expect(t, run(t, root, "P1"), "P1", "internal/directory/dn/dn.go:3", "imports internal/compose/profile")
}

func TestP1DomainReadsProfileEnv(t *testing.T) {
	for name, src := range map[string]string{
		"literal":  "package dn\n\nimport \"os\"\n\nfunc F() string { return os.Getenv(\"ACTIVEDIQ_PROFILE\") }\n",
		"lookup":   "package dn\n\nimport \"os\"\n\nfunc F() bool { _, ok := os.LookupEnv(\"DIQ_SAAS\"); return ok }\n",
		"constant": "package dn\n\nimport \"os\"\n\nconst envName = \"ACTIVEDIQ_DEPLOYMENT_MODE\"\n\nfunc F() string { return os.Getenv(envName) }\n",
		"prefix":   "package dn\n\nimport \"os\"\n\nfunc F(s string) string { return os.Getenv(\"ACTIVEDIQ_PROFILE_\" + s) }\n",
		"alias":    "package dn\n\nimport o \"os\"\n\nfunc F() string { return o.Getenv(\"ACTIVEDIQ_PROFILE\") }\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := repo(t, map[string]string{"internal/directory/dn/dn.go": src})
			expect(t, run(t, root, "P1"), "P1", "internal/directory/dn/dn.go:", "profile-selecting environment variable")
		})
	}
}

func TestP1DomainEnvNotConstant(t *testing.T) {
	root := repo(t, map[string]string{"internal/directory/dn/dn.go": "package dn\n\nimport \"os\"\n\nfunc F(n string) string { return os.Getenv(n) }\n"})
	expect(t, run(t, root, "P1"), "P1", "internal/directory/dn/dn.go:5", "not a constant")
	root = repo(t, map[string]string{"internal/directory/dn/dn.go": "package dn\n\nimport \"os\"\n\nvar get = os.Getenv\n"})
	expect(t, run(t, root, "P1"), "P1", "internal/directory/dn/dn.go:5", "hides which variable")
}

func TestP1UnrelatedEnvInDomainIsNotProfileSelecting(t *testing.T) {
	root := repo(t, map[string]string{"internal/directory/dn/dn.go": "package dn\n\nimport \"os\"\n\nfunc F() string { return os.Getenv(\"ACTIVEDIQ_TEST_PG_IMAGE\") }\n"})
	if vs := run(t, root, "P1"); len(vs) != 0 {
		t.Fatalf("a constant, non-profile variable is not P1's concern:\n%s", dump(vs))
	}
}

func TestP1RoleOtherThanLoaderReadsEnv(t *testing.T) {
	root := repo(t, map[string]string{"internal/compose/server/server.go": "package server\n\nimport \"os\"\n\nfunc F() string { return os.Getenv(\"ACTIVEDIQ_PROFILE\") }\n"})
	expect(t, run(t, root, "P1"), "P1", "internal/compose/server/server.go:5", "outside the config loader")
}

func TestP1ProfileNamedIdentifier(t *testing.T) {
	for name, src := range map[string]string{
		"var":        "package dn\n\nvar isSaaS = false\n",
		"func":       "package dn\n\nfunc IsSelfHosted() bool { return true }\n",
		"field":      "package dn\n\ntype T struct{ OnPrem bool }\n",
		"underscore": "package dn\n\nvar is_saas = false\n",
		"linuxoci":   "package dn\n\nconst linuxOCIOnly = 1\n",
		"literal":    "package dn\n\nfunc F(p string) bool { return p == \"saas\" }\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := repo(t, map[string]string{"internal/directory/dn/dn.go": src})
			expect(t, run(t, root, "P1"), "P1", "internal/directory/dn/dn.go:", "profile")
		})
	}
}

func TestP1ProfileNamesAllowedInCompositionRootAndTools(t *testing.T) {
	root := repo(t, map[string]string{
		"internal/compose/server/server.go": "package server\n\nvar isSaaS = false\n",
		"tools/fitness/x/x.go":              "package x\n\nvar isSaaS = false\n",
	})
	if vs := run(t, root, "P1"); len(vs) != 0 {
		t.Fatalf("the composition root and tools may name profiles:\n%s", dump(vs))
	}
}

func TestP1ProfileNamedCapability(t *testing.T) {
	root := repo(t, map[string]string{"internal/platform/capability/capability.go": "package capability\n\ntype ID string\n\nconst (\n\tDirectoryAD ID = \"directory.ad\"\n\tDirectoryEntra ID = \"directory.entra\"\n\tProvisioning ID = \"tenant-provisioning\"\n\tHosted ID = \"saas-mode\"\n)\n"})
	vs := run(t, root, "P1")
	expect(t, vs, "P1", "internal/platform/capability/capability.go:9", "saas-mode", "named after a profile")
}

func TestP1CapabilityAsymmetry(t *testing.T) {
	m := strings.Replace(baseline["internal/compose/profile/manifests.go"], "func LinuxOCI() Manifest {\n\treturn Manifest{\n\t\tName:         \"linux-oci\",\n\t\tProcesses:    []Process{{Binary: \"server\", Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderAD, ProviderEntra}}},\n\t\tCapabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra},",
		"func LinuxOCI() Manifest {\n\treturn Manifest{\n\t\tName:         \"linux-oci\",\n\t\tProcesses:    []Process{{Binary: \"server\", Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderAD, ProviderEntra}}},\n\t\tCapabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra, capability.Provisioning},", 1)
	if m == baseline["internal/compose/profile/manifests.go"] {
		t.Fatal("fixture edit did not apply")
	}
	root := repo(t, map[string]string{"internal/compose/profile/manifests.go": m})
	expect(t, run(t, root, "P1"), "P1", "internal/compose/profile/manifests.go:", "differ in capability \"tenant-provisioning\"", "linux-oci")

	// An exception citing a ratified ADR covers it ...
	withExc := strings.Replace(m, "Provisioning},\n\t}\n}\n\nfunc SaaS", "Provisioning},\n\t\tExceptions:   []Exception{{What: \"tenant-provisioning\", ADR: \"0002-deployment-model.md\"}},\n\t}\n}\n\nfunc SaaS", 1)
	if withExc == m {
		t.Fatal("exception edit did not apply")
	}
	root = repo(t, map[string]string{"internal/compose/profile/manifests.go": withExc})
	if vs := run(t, root, "P1"); len(vs) != 0 {
		t.Fatalf("exception citing a ratified ADR should cover the difference:\n%s", dump(vs))
	}
	// ... one citing a proposed ADR, a missing ADR, or nothing does not.
	for _, adr := range []string{"0009-draft.md", "0042-missing.md", ""} {
		bad := strings.Replace(withExc, "0002-deployment-model.md", adr, 1)
		root = repo(t, map[string]string{"internal/compose/profile/manifests.go": bad})
		vs := run(t, root, "P1")
		expect(t, vs, "P1", "internal/compose/profile/manifests.go:", "differ in capability")
		expect(t, vs, "P1", "internal/compose/profile/manifests.go:", "exception \"tenant-provisioning\" is not valid")
	}
}

func TestP1Planes(t *testing.T) {
	edge := strings.Replace(baseline["internal/compose/profile/manifests.go"], "Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderAD, ProviderEntra}}},\n\t\tCapabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra},\n\t}\n}\n\nfunc LinuxOCI", "Roles: []Role{RoleServer, RoleConnector, RoleEdge}, Providers: []Provider{ProviderAD, ProviderEntra}}},\n\t\tCapabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra},\n\t}\n}\n\nfunc LinuxOCI", 1)
	if edge == baseline["internal/compose/profile/manifests.go"] {
		t.Fatal("fixture edit did not apply")
	}
	expect(t, run(t, repo(t, map[string]string{"internal/compose/profile/manifests.go": edge}), "P1"), "P1", "internal/compose/profile/manifests.go:", "composes role \"edge\"")

	t0 := strings.Replace(baseline["internal/compose/profile/manifests.go"], "Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderEntra}}}", "Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderEntra}}, {Binary: \"t0\", Roles: []Role{Role(\"t0-connector\")}}}", 1)
	if t0 == baseline["internal/compose/profile/manifests.go"] {
		t.Fatal("fixture edit did not apply")
	}
	expect(t, run(t, repo(t, map[string]string{"internal/compose/profile/manifests.go": t0}), "P1"), "P1", "internal/compose/profile/manifests.go:", "t0-connector in the SaaS cell")

	t0mix := strings.Replace(baseline["internal/compose/profile/manifests.go"], "Roles: []Role{RoleServer, RoleConnector}, Providers: []Provider{ProviderAD, ProviderEntra}}},\n\t\tCapabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra},\n\t}\n}\n\nfunc LinuxOCI", "Roles: []Role{RoleServer, Role(\"t0-connector\")}, Providers: []Provider{ProviderAD, ProviderEntra}}},\n\t\tCapabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra},\n\t}\n}\n\nfunc LinuxOCI", 1)
	expect(t, run(t, repo(t, map[string]string{"internal/compose/profile/manifests.go": t0mix}), "P1"), "P1", "internal/compose/profile/manifests.go:", "composes role \"t0-connector\"")
}

func TestP1SaaSCellCarriesNoAD(t *testing.T) {
	m := strings.Replace(baseline["internal/compose/profile/manifests.go"], "Providers: []Provider{ProviderEntra}}},\n\t\tCapabilities: []capability.ID{capability.DirectoryEntra, capability.Provisioning}", "Providers: []Provider{ProviderAD, ProviderEntra}}},\n\t\tCapabilities: []capability.ID{capability.DirectoryAD, capability.DirectoryEntra, capability.Provisioning}", 1)
	if m == baseline["internal/compose/profile/manifests.go"] {
		t.Fatal("fixture edit did not apply")
	}
	vs := run(t, repo(t, map[string]string{"internal/compose/profile/manifests.go": m}), "P1")
	expect(t, vs, "P1", "internal/compose/profile/manifests.go:", "carries the \"ad\" directory provider")
	expect(t, vs, "P1", "internal/compose/profile/manifests.go:", "enables capability \"directory.ad\"")
}

func TestP1MissingManifest(t *testing.T) {
	m := baseline["internal/compose/profile/manifests.go"]
	m = m[:strings.Index(m, "func SaaS")]
	expect(t, run(t, repo(t, map[string]string{"internal/compose/profile/manifests.go": m}), "P1"), "P1", "internal/compose/profile", "manifest \"saas\" not found")
}

// --- P7 -----------------------------------------------------------------------------------

func TestP7(t *testing.T) {
	root := repo(t, nil)
	for _, b := range []string{"release/1.0", "customer-acme", "factory/T-12", "main2", "feature/x", "factory/T-0038-rework"} {
		vs, _, err := Run(root, defaultManifest, []string{"P7"}, Options{Branches: []string{"main", "factory/T-0038", b}})
		if err != nil {
			t.Fatal(err)
		}
		expect(t, vs, "P7", "branch "+b, "not main or factory/T-NNNN")
	}
	if vs := run(t, root, "P7"); len(vs) != 0 {
		t.Fatalf("main and factory/T-NNNN are allowed:\n%s", dump(vs))
	}
}

func TestBranchesFromGit(t *testing.T) {
	root := repo(t, nil)
	git := func(args ...string) {
		t.Helper()
		out, err := runGit(root, args...)
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	git("-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-q", "--allow-empty", "-m", "x")
	git("branch", "factory/T-0001")
	git("branch", "release/customer-a")
	bs, err := Branches(root)
	if err != nil {
		t.Fatal(err)
	}
	vs, _, err := Run(root, defaultManifest, []string{"P7"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(bs, ",") != "factory/T-0001,main,release/customer-a" {
		t.Errorf("branches = %v", bs)
	}
	expect(t, vs, "P7", "branch release/customer-a", "not main")
	if len(vs) != 1 {
		t.Errorf("only the variant branch should fail:\n%s", dump(vs))
	}
}

// --- U1 -----------------------------------------------------------------------------------

func TestU1RequireDenylisted(t *testing.T) {
	for _, mod := range []string{"github.com/herambskanda/patchiq", "github.com/herambskanda/patchiq/pkg/x", "github.com/skenzeriq/uem"} {
		root := repo(t, map[string]string{"go.mod": "module example.test/diq\n\ngo 1.27.0\n\nrequire (\n\tgithub.com/jackc/pgx/v5 v5.9.2\n\t" + mod + " v0.0.0 // indirect\n)\n"})
		expect(t, run(t, root, "U1"), "U1", "go.mod:7", mod, "denylist")
	}
	// A nested module is found too.
	root := repo(t, map[string]string{"sidecars/x/go.mod": "module example.test/x\n\nrequire github.com/herambskanda/patchiq v1.0.0\n"})
	expect(t, run(t, root, "U1"), "U1", "sidecars/x/go.mod:3", "patchiq")
}

func TestU1ImportOfDenylisted(t *testing.T) {
	root := repo(t, map[string]string{"internal/directory/dn/dn.go": "package dn\n\nimport _ \"github.com/herambskanda/patchiq/internal/x\"\n"})
	expect(t, run(t, root, "U1"), "U1", "internal/directory/dn/dn.go:3", "imports github.com/herambskanda/patchiq/internal/x")
}

func TestU1Replace(t *testing.T) {
	for name, line := range map[string]string{
		"parent dir": "replace github.com/jackc/pgx/v5 => ../pgx",
		"absolute":   "replace github.com/jackc/pgx/v5 => /opt/pgx",
		"fork":       "replace github.com/jackc/pgx/v5 => github.com/someone/pgx v1.0.0",
		"escape":     "replace github.com/jackc/pgx/v5 => ./../../pgx",
		"block":      "replace (\n\tgithub.com/jackc/pgx/v5 => ../pgx\n)",
	} {
		t.Run(name, func(t *testing.T) {
			root := repo(t, map[string]string{"go.mod": baseline["go.mod"] + "\n" + line + "\n"})
			expect(t, run(t, root, "U1"), "U1", "go.mod:", "points outside the repository")
		})
	}
	// Inside the repository is fine.
	root := repo(t, map[string]string{"go.mod": baseline["go.mod"] + "\nreplace github.com/jackc/pgx/v5 => ./third_party/pgx\n"})
	if vs := run(t, root, "U1"); len(vs) != 0 {
		t.Fatalf("a replace inside the repository is allowed:\n%s", dump(vs))
	}
	// A replace that names a UEM module fails whatever it points at.
	root = repo(t, map[string]string{"go.mod": baseline["go.mod"] + "\nreplace github.com/jackc/pgx/v5 => ./third_party/pgx\nreplace github.com/herambskanda/patchiq => ./third_party/p\n"})
	expect(t, run(t, root, "U1"), "U1", "go.mod:", "names a UEM/PatchIQ module")
}

func TestU1ReplaceExceptionCitesRatifiedADR(t *testing.T) {
	m, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	with := func(adr string) map[string]string {
		return map[string]string{
			"go.mod":                               baseline["go.mod"] + "\nreplace github.com/jackc/pgx/v5 => ../pgx\n",
			"tools/fitness/profiles/manifest.json": strings.Replace(string(m), `"replaceExceptions": []`, `"replaceExceptions": [{"path": "go.mod:github.com/jackc/pgx/v5", "adr": "`+adr+`", "reason": "test"}]`, 1),
		}
	}
	if vs := run(t, repo(t, with("0002-deployment-model.md")), "U1"); len(vs) != 0 {
		t.Fatalf("exception citing a ratified ADR should pass:\n%s", dump(vs))
	}
	vs := run(t, repo(t, with("0009-draft.md")), "U1")
	expect(t, vs, "U1", "go.mod:", "points outside the repository")
	expect(t, vs, "U1", "manifest replaceExceptions[0]", "proposed")
}

func TestU1StackMustExtendDenylist(t *testing.T) {
	root := repo(t, map[string]string{"tools/fitness/stack/manifest.json": `{"denylistExtends": []}`})
	expect(t, run(t, root, "U1"), "U1", "tools/fitness/stack/manifest.json", "denylistExtends")
}

// --- U2 -----------------------------------------------------------------------------------

func TestU2(t *testing.T) {
	for _, imp := range []string{"internal/directory/ldapfilter", "internal/connector/ldap", "internal/modules/ou", "internal/agentmodules/addc", "internal/compose/profile", "internal/proto/activediq/connector/v1"} {
		root := repo(t, map[string]string{"internal/platform/tenant/leak.go": "package tenant\n\nimport _ \"example.test/diq/" + imp + "\"\n"})
		expect(t, run(t, root, "U2"), "U2", "internal/platform/tenant/leak.go:3", imp, "extractable")
	}
	// Tests count: a platform test may not reach up either.
	root := repo(t, map[string]string{"internal/platform/tenant/leak_test.go": "package tenant\n\nimport _ \"example.test/diq/internal/directory/ldapfilter\"\n"})
	expect(t, run(t, root, "U2"), "U2", "internal/platform/tenant/leak_test.go:3", "extractable")
}

// --- Activation table -----------------------------------------------------------------------

func TestActivationPendingIsPrinted(t *testing.T) {
	root := repo(t, nil)
	vs, rows, err := Run(root, defaultManifest, []string{"ACT"}, onlyMain)
	if err != nil || len(vs) != 0 {
		t.Fatalf("err=%v\n%s", err, dump(vs))
	}
	var b strings.Builder
	PrintTable(&b, rows)
	for _, id := range requiredActivation {
		if !strings.Contains(b.String(), "  "+id+" ") || !strings.Contains(b.String(), "pending") {
			t.Errorf("table lacks pending row for %s:\n%s", id, b.String())
		}
	}
	for _, p := range []string{"packaging/windows/", "internal/connector/*/", "proto/skenzeriq/"} {
		if !strings.Contains(b.String(), p) {
			t.Errorf("table does not show activating path %s:\n%s", p, b.String())
		}
	}
}

func TestActivationSubjectWithoutCheckFails(t *testing.T) {
	for check, path := range map[string]string{
		"P2": "packaging/windows/installer.wxs",
		"P6": "packaging/oci/Dockerfile",
		"P3": "internal/connector/ldap/ldap.go",
		"P4": "internal/connector/ldap/ldap.go",
		"P5": "internal/platform/updater/updater.go",
		"U3": "proto/skenzeriq/agent/v1/agent.proto",
		"U4": "proto/skenzeriq/agent/v1/agent.proto",
	} {
		t.Run(check, func(t *testing.T) {
			vs := run(t, repo(t, map[string]string{path: "package x\n"}), "ACT")
			expect(t, vs, "ACT", "activation table "+check, "exists", "not implemented")
		})
	}
}

// Files directly under internal/connector (the doc.go that exists today) do not activate P3.
func TestActivationDirectoryOnlyPattern(t *testing.T) {
	vs := run(t, repo(t, map[string]string{"internal/connector/doc.go": "package connector\n"}), "ACT")
	if len(vs) != 0 {
		t.Fatalf("doc.go must not activate P3:\n%s", dump(vs))
	}
}

func withCommand(t *testing.T, check string, command string) map[string]string {
	t.Helper()
	b, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, `"check": "`+check+`"`)
	j := strings.Index(s[i:], `"command": []`)
	if i < 0 || j < 0 {
		t.Fatalf("no row for %s", check)
	}
	s = s[:i+j] + `"command": ` + command + s[i+j+len(`"command": []`):]
	return map[string]string{"tools/fitness/profiles/manifest.json": s}
}

func TestActivationImplementedCheckMustPass(t *testing.T) {
	extra := withCommand(t, "U3", `["go", "version"]`)
	extra["proto/skenzeriq/agent/v1/agent.proto"] = "syntax = \"proto3\";\n"
	extra["proto/skenzeriq/agent/v1/x.txt"] = "x"
	// U3 passes now; U4 (same subject) is still unimplemented.
	vs := run(t, repo(t, extra), "ACT")
	expect(t, vs, "ACT", "activation table U4", "not implemented")
	for _, v := range vs {
		if strings.Contains(v.Pos, "U3") {
			t.Errorf("U3 has an implemented, passing check: %s", v)
		}
	}

	extra = withCommand(t, "U3", `["go", "tool", "no-such-tool-xyz"]`)
	extra["proto/skenzeriq/agent/v1/agent.proto"] = "syntax = \"proto3\";\n"
	vs = run(t, repo(t, extra), "ACT")
	expect(t, vs, "ACT", "activation table U3", "fails")

	extra = withCommand(t, "U3", `["go", "run", "./tools/fitness/u3"]`)
	extra["proto/skenzeriq/agent/v1/agent.proto"] = "syntax = \"proto3\";\n"
	vs = run(t, repo(t, extra), "ACT")
	expect(t, vs, "ACT", "activation table U3", "./tools/fitness/u3 does not exist")
}

func TestActivationRowCannotBeDeleted(t *testing.T) {
	b, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, `    {
      "check": "U4"`)
	j := strings.Index(s[i:], "    }\n")
	s = s[:i] + s[i+j+len("    }\n"):]
	s = strings.Replace(s, "    },\n  ]", "    }\n  ]", 1)
	vs := run(t, repo(t, map[string]string{"tools/fitness/profiles/manifest.json": s}), "ACT")
	expect(t, vs, "ACT", "activation table U4", "no row")
}

func TestUnknownCheck(t *testing.T) {
	if _, _, err := Run(repo(t, nil), defaultManifest, []string{"P9"}, onlyMain); err == nil {
		t.Fatal("unknown check should be an error")
	}
}
