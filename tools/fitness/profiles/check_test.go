package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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
	"internal/platform/tenant/tenant.go": "package tenant\n\ntype ID struct{ b [16]byte }\n\nfunc New() ID { return ID{} }\n\nfunc (ID) String() string { return \"t\" }\n",
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
	"internal/directory/graphnames/names.go": `package graphnames

// Microsoft's own names, registered in manifest.json externalVocabulary (ADR-0002 E-1).
const (
	OnPremisesSyncEnabled     = "onPremisesSyncEnabled"
	AttrOnPremisesSyncEnabled = "onPremisesSyncEnabled"
	OnPremisesDomainName      = "onPremisesDomainName"
	OnPremisesImmutableID     = "onPremisesImmutableId"
	OnPremisesSecurityIdentifier = "onPremisesSecurityIdentifier"
	SegOnPremisesSynchronization = "onPremisesSynchronization"
	AnchorOnpremSID           = "onprem_sid"
)
`,
	"internal/directory/ldapfilter/f.go": "package ldapfilter\n\nimport \"example.test/diq/internal/platform/tenant\"\n\nvar _ = tenant.New\n",
}

// deferralLine matches one `"deferral": {...},` line of the real manifest.
var deferralLine = regexp.MustCompile(`\n[ \t]*"deferral": \{[^}]*\},`)

// shippedWithoutDeferrals is the manifest `make ci` runs with every deferral removed, so a row whose subject
// exists and whose check is missing shows as "not implemented" in the cases below. The deferral
// cases add exactly the deferral they exercise (withDeferral).
func shippedWithoutDeferrals(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	return deferralLine.ReplaceAllString(string(b), "")
}

// copyReal brings in the real manifest and denylist, so the tests exercise what `make ci` runs.
func copyReal(t *testing.T, files map[string]string) {
	t.Helper()
	files["tools/fitness/profiles/manifest.json"] = shippedWithoutDeferrals(t)
	b, err := os.ReadFile("uem-denylist.json")
	if err != nil {
		t.Fatal(err)
	}
	files["tools/fitness/profiles/uem-denylist.json"] = string(b)
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

// testToday is the date the deferral cases run on, so none of them depends on the wall clock.
var testToday = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

var onlyMain = Options{Branches: []string{"main", "factory/T-0038"}, Now: testToday}

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
		"P2-msi": "packaging/windows/installer.wxs",
		"P2-oci": "packaging/linux-oci/Dockerfile.server",
		"P6":     "packaging/linux-oci/Dockerfile.server",
		"P3":     "internal/connector/ldap/ldap.go",
		"P4":     "internal/connector/ldap/ldap.go",
		"P5":     "internal/platform/updater/updater.go",
		"U3":     "proto/skenzeriq/agent/v1/agent.proto",
		"U4":     "proto/skenzeriq/agent/v1/agent.proto",
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
	s := shippedWithoutDeferrals(t)
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
	s := shippedWithoutDeferrals(t)
	i := strings.Index(s, `    {
      "check": "U4"`)
	j := strings.Index(s[i:], "    }\n")
	s = s[:i] + s[i+j+len("    }\n"):]
	s = strings.Replace(s, "    },\n  ]", "    }\n  ]", 1)
	vs := run(t, repo(t, map[string]string{"tools/fitness/profiles/manifest.json": s}), "ACT")
	expect(t, vs, "ACT", "activation table U4", "no row")
}

// --- Activation deferrals (ADR-0002 erratum E-3) ----------------------------------------------

// adrDeferrals is an ADR whose "Activation deferrals" table approves two deferrals.
const adrDeferrals = `---
status: ratified
---
# ADR

**Activation deferrals** (parsed by fitness-profiles; columns 1 to 3 are machine-read):

| Check | Ticket | Expires | Evidence the check needs | Producer |
| --- | --- | --- | --- | --- |
| P2-oci | T-0927 | 2026-12-15 | images | devops-engineer |
| P3 | T-0929 | 2026-11-30 | conformance | directory-engineer |

Text after the table.

| Check | Ticket | Expires |
| --- | --- | --- |
| U3 | T-0933 | 2026-11-30 |
`

// only keeps the violations of one activation row, so a case about P2-oci is not about P6, which
// the same packaging/linux-oci/ path also activates.
func only(vs []Violation, check string) []Violation {
	var out []Violation
	for _, v := range vs {
		if v.Pos == "activation table "+check {
			out = append(out, v)
		}
	}
	return out
}

// deferralRepo is a repository where the subject of check exists and the real manifest carries the
// given deferral on that check's row. The ADR is the one with the table above.
func deferralRepo(t *testing.T, check, path, deferral string, mutate func(string) string) string {
	t.Helper()
	s := shippedWithoutDeferrals(t)
	i := strings.Index(s, `"check": "`+check+`"`)
	j := strings.Index(s[i:], `"command": [],`)
	if i < 0 || j < 0 {
		t.Fatalf("no row for %s", check)
	}
	j += i + len(`"command": [],`)
	s = s[:j] + "\n      \"deferral\": " + deferral + "," + s[j:]
	if mutate != nil {
		s = mutate(s)
	}
	return repo(t, map[string]string{
		"tools/fitness/profiles/manifest.json":                     s,
		"knowledge/development/decisions/0002-deployment-model.md": adrDeferrals,
		path: "x",
	})
}

const d2oci = `{"ticket": "T-0927", "expires": "2026-12-15", "adr": "0002-deployment-model.md"}`

// A deferral listed in the ADR table and not yet expired prints ACTIVE, DEFERRED and is no violation.
func TestActivationDeferralApprovedByADRPasses(t *testing.T) {
	root := deferralRepo(t, "P2-oci", "packaging/linux-oci/Dockerfile.server", d2oci, nil)
	vs, rows, err := Run(root, defaultManifest, []string{"ACT"}, onlyMain)
	if err != nil || len(only(vs, "P2-oci")) != 0 {
		t.Fatalf("err=%v\n%s", err, dump(vs))
	}
	var b strings.Builder
	PrintTable(&b, rows)
	if !strings.Contains(b.String(), "P2-oci ACTIVE, DEFERRED (T-0927 until 2026-12-15)") {
		t.Errorf("table lacks the deferred row:\n%s", b.String())
	}
	// The last day is still inside the deferral; a table row after prose and a second table is found.
	onDay := Options{Branches: onlyMain.Branches, Now: time.Date(2026, 12, 15, 23, 59, 0, 0, time.UTC)}
	if vs, _, _ := Run(root, defaultManifest, []string{"ACT"}, onDay); len(only(vs, "P2-oci")) != 0 {
		t.Fatalf("a deferral is valid on its expiry date:\n%s", dump(vs))
	}
}

func TestActivationDeferralExpiredFails(t *testing.T) {
	root := deferralRepo(t, "P2-oci", "packaging/linux-oci/Dockerfile.server", d2oci, nil)
	late := Options{Branches: onlyMain.Branches, Now: time.Date(2026, 12, 16, 0, 0, 1, 0, time.UTC)}
	vs, _, err := Run(root, defaultManifest, []string{"ACT"}, late)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, vs, "ACT", "activation table P2-oci", "deferral", "expired on 2026-12-15")
	// An expiry that is not an ISO date cannot be compared and fails too.
	root = deferralRepo(t, "P2-oci", "packaging/linux-oci/Dockerfile.server", d2oci, func(s string) string { return strings.Replace(s, "2026-12-15", "15/12/2026", 1) })
	expect(t, run(t, root, "ACT"), "ACT", "activation table P2-oci", "deferral", "not a YYYY-MM-DD date")
}

func TestActivationDeferralMalformedTicketFails(t *testing.T) {
	for _, tk := range []string{"T-927", "927", "t-0927", "T-0927x", "T-"} {
		t.Run(tk, func(t *testing.T) {
			root := deferralRepo(t, "P2-oci", "packaging/linux-oci/Dockerfile.server", d2oci, func(s string) string { return strings.Replace(s, "T-0927", tk, 1) })
			expect(t, run(t, root, "ACT"), "ACT", "activation table P2-oci", "deferral", "ticket", "malformed")
		})
	}
	// Five digits are well formed; the ADR table has no such row, so it fails there instead.
	root := deferralRepo(t, "P2-oci", "packaging/linux-oci/Dockerfile.server", d2oci, func(s string) string { return strings.Replace(s, "T-0927", "T-10927", 1) })
	vs := run(t, root, "ACT")
	for _, v := range vs {
		if strings.Contains(v.Msg, "malformed") {
			t.Errorf("T-10927 is well formed: %s", v)
		}
	}
	expect(t, vs, "ACT", "activation table P2-oci", "no row")
}

func TestActivationDeferralOnRowWithCommandIsStale(t *testing.T) {
	root := deferralRepo(t, "P2-oci", "packaging/linux-oci/Dockerfile.server", d2oci, func(s string) string {
		i := strings.Index(s, `"check": "P2-oci"`)
		j := strings.Index(s[i:], `"command": []`)
		return s[:i+j] + `"command": ["go", "version"]` + s[i+j+len(`"command": []`):]
	})
	vs := run(t, root, "ACT")
	expect(t, vs, "ACT", "activation table P2-oci", "deferral", "stale", "remove the deferral")
	// The command still runs: the stale deferral does not hide a failing check.
	root = deferralRepo(t, "P2-oci", "packaging/linux-oci/Dockerfile.server", d2oci, func(s string) string {
		i := strings.Index(s, `"check": "P2-oci"`)
		j := strings.Index(s[i:], `"command": []`)
		return s[:i+j] + `"command": ["go", "tool", "no-such-tool-xyz"]` + s[i+j+len(`"command": []`):]
	})
	expect(t, run(t, root, "ACT"), "ACT", "activation table P2-oci", "fails")
}

func TestActivationDeferralNotInADRTableFails(t *testing.T) {
	// The manifest alone cannot approve: P6 has a deferral here, and the ADR table has no P6 row.
	root := deferralRepo(t, "P6", "packaging/linux-oci/Dockerfile.server", `{"ticket": "T-0932", "expires": "2026-12-15", "adr": "0002-deployment-model.md"}`, nil)
	expect(t, run(t, root, "ACT"), "ACT", "activation table P6", "deferral", "no row", "Activation deferrals")
	// A row for the check with a different ticket, or a later expiry, is not the approved deferral.
	for name, mut := range map[string]func(string) string{
		"ticket":  func(s string) string { return strings.Replace(s, "T-0927", "T-0999", 1) },
		"expires": func(s string) string { return strings.Replace(s, "2026-12-15", "2027-03-01", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			root := deferralRepo(t, "P2-oci", "packaging/linux-oci/Dockerfile.server", d2oci, mut)
			expect(t, run(t, root, "ACT"), "ACT", "activation table P2-oci", "deferral", "no row")
		})
	}
	// A different check with the same ticket and expiry does not count either.
	root = deferralRepo(t, "P2-msi", "packaging/windows/installer.wxs", `{"ticket": "T-0927", "expires": "2026-12-15", "adr": "0002-deployment-model.md"}`, nil)
	expect(t, run(t, root, "ACT"), "ACT", "activation table P2-msi", "deferral", "no row")
}

func TestActivationDeferralADRMustGrant(t *testing.T) {
	root := deferralRepo(t, "P2-oci", "packaging/linux-oci/Dockerfile.server", d2oci, nil)
	for name, tc := range map[string]struct{ file, content, frag string }{
		"proposed": {"knowledge/development/decisions/0002-deployment-model.md", strings.Replace(adrDeferrals, "ratified", "proposed", 1), "ratified or accepted"},
		"no table": {"knowledge/development/decisions/0002-deployment-model.md", adrRatified, "no **Activation deferrals** heading"},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(root, filepath.FromSlash(tc.file))
			if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			expect(t, run(t, root, "ACT"), "ACT", "activation table P2-oci", "deferral", tc.frag)
		})
	}
	// An adr that is a path, not a file name in decisionsDir, is refused.
	root = deferralRepo(t, "P2-oci", "packaging/linux-oci/Dockerfile.server", d2oci, func(s string) string {
		return strings.Replace(s, `"expires": "2026-12-15", "adr": "0002-deployment-model.md"`, `"expires": "2026-12-15", "adr": "../0002-deployment-model.md"`, 1)
	})
	expect(t, run(t, root, "ACT"), "ACT", "activation table P2-oci", "deferral", "must be the file name")
}

// A deferral changes nothing for a row whose subject does not exist yet: it stays pending.
func TestActivationDeferralOnPendingRowStaysPending(t *testing.T) {
	root := deferralRepo(t, "P5", "unrelated.txt", `{"ticket": "T-0999", "expires": "2026-12-15", "adr": "0002-deployment-model.md"}`, nil)
	vs, rows, err := Run(root, defaultManifest, []string{"ACT"}, onlyMain)
	if err != nil {
		t.Fatal(err)
	}
	expect(t, vs, "ACT", "activation table P5", "deferral", "no row") // the deferral is still judged
	for _, r := range rows {
		if r.Check == "P5" && r.State() != "pending" {
			t.Errorf("P5 state = %q, want pending", r.State())
		}
	}
}

// The manifest as shipped: P2 split by artefact, every path under packaging/linux-oci/, no row on
// the wrong packaging/oci/ path (acceptance 3).
func TestShippedManifestActivationPaths(t *testing.T) {
	b, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "packaging/oci") {
		t.Error("manifest.json names packaging/oci/, which is not in the tree; the OCI artefacts are in packaging/linux-oci/")
	}
	cfg, err := LoadConfig("../../..", defaultManifest)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, a := range cfg.Activation {
		paths[a.Check] = strings.Join(a.Paths, ",")
	}
	for check, want := range map[string]string{"P2-oci": "packaging/linux-oci/", "P2-msi": "packaging/windows/", "P6": "packaging/linux-oci/"} {
		if paths[check] != want {
			t.Errorf("%s paths = %q, want %q", check, paths[check], want)
		}
	}
	if _, ok := paths["P2"]; ok {
		t.Error("the unsplit P2 row is back")
	}
}

// Every deferral in the shipped manifest is approved by the ADR table as it is today, so the real
// table and the real manifest agree. It judges them on the date the ADR was written: the wall
// clock is the job's business (`make fitness-profiles`), not this test's.
func TestShippedDeferralsMatchADRTable(t *testing.T) {
	cfg, err := LoadConfig("../../..", defaultManifest)
	if err != nil {
		t.Fatal(err)
	}
	c := &Ctx{Root: "../../..", Cfg: cfg, Now: testToday}
	n := 0
	for _, a := range cfg.Activation {
		if a.Deferral == nil {
			continue
		}
		n++
		if ps := c.deferralProblems(a); len(ps) != 0 {
			t.Errorf("%s: %s", a.Check, strings.Join(ps, "; "))
		}
	}
	if n != 7 {
		t.Errorf("manifest carries %d deferrals, ADR-0002 lists seven", n)
	}
}

func TestUnknownCheck(t *testing.T) {
	if _, _, err := Run(repo(t, nil), defaultManifest, []string{"P9"}, onlyMain); err == nil {
		t.Fatal("unknown check should be an error")
	}
}

// --- P1 erratum E-1: registered external vocabulary ------------------------------------------

// withVocab returns the real manifest with its externalVocabulary replaced.
func withVocab(t *testing.T, entries string) map[string]string {
	t.Helper()
	b, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["externalVocabulary"] = json.RawMessage(entries)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"tools/fitness/profiles/manifest.json": string(out)}
}

func TestP1ExternalVocabularyIdentifiers(t *testing.T) {
	for _, id := range []string{"IsOnPremDeployment", "OnPremisesProfile", "OnPremisesSyncEnabledForSaaS", "onPremMode", "SaaSOnPremisesDomainName"} {
		t.Run("fails/"+id, func(t *testing.T) {
			root := repo(t, map[string]string{"internal/directory/dn/dn.go": "package dn\n\nvar " + id + " = 1\n"})
			expect(t, run(t, root, "P1"), "P1", "internal/directory/dn/dn.go:3", id, "names a deployment profile")
		})
	}
	// The registered names pass: graphnames/names.go in the baseline holds four of them, and a
	// domain package may use them as well.
	src := "package dn\n\nvar (\n\tOnPremisesSyncEnabled = 1\n\tAttrOnPremisesSyncEnabled = 1\n\tOnPremisesDomainName = 1\n\tAnchorOnpremSID = 1\n\tonPremisesImmutableId = 1\n)\n"
	root := repo(t, map[string]string{"internal/directory/dn/dn.go": src})
	if vs := run(t, root, "P1"); len(vs) != 0 {
		t.Fatalf("registered Graph and token-claim names pass:\n%s", dump(vs))
	}
}

func TestP1ExternalVocabularyDoesNotLoosenCapabilityValues(t *testing.T) {
	root := repo(t, map[string]string{"internal/platform/capability/capability.go": "package capability\n\ntype ID string\n\nconst (\n\tDirectoryAD ID = \"directory.ad\"\n\tDirectoryEntra ID = \"directory.entra\"\n\tProvisioning ID = \"tenant-provisioning\"\n\tHosted ID = \"onprem-mode\"\n)\n"})
	expect(t, run(t, root, "P1"), "P1", "internal/platform/capability/capability.go:9", "onprem-mode", "named after a profile")
}

func TestP1ExternalVocabularyEntryRefused(t *testing.T) {
	const src = "https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0"
	for name, c := range map[string]struct{ entry, id, why string }{
		"no source":        {`{"term":"onPremisesSyncEnabled","kind":"graph-property","source":""}`, "OnPremisesSyncEnabled", "no https source"},
		"http source":      {`{"term":"onPremisesSyncEnabled","kind":"graph-property","source":"http://learn.microsoft.com/x"}`, "OnPremisesSyncEnabled", "no https source"},
		"unknown kind":     {`{"term":"onPremisesSyncEnabled","kind":"invented","source":"` + src + `"}`, "OnPremisesSyncEnabled", "kind"},
		"no denylist word": {`{"term":"displayName","kind":"graph-property","source":"` + src + `"}`, "DisplayName", "needs no registration"},
		"token onprem":     {`{"term":"onprem","kind":"graph-property","source":"` + src + `"}`, "OnPremMode", "a denylist token"},
		"token on_prem":    {`{"term":"on_prem","kind":"graph-property","source":"` + src + `"}`, "OnPremMode", "a denylist token"},
		"token saas":       {`{"term":"SaaS","kind":"graph-property","source":"` + src + `"}`, "IsSaaS", "a denylist token"},
		"stem onPremises":  {`{"term":"onPremises","kind":"graph-property","source":"` + src + `"}`, "OnPremisesProfile", "refused stem"},
		"stem onPremise":   {`{"term":"onPremise","kind":"graph-property","source":"` + src + `"}`, "OnPremiseProfile", "refused stem"},
		"stale":            {`{"term":"onPremisesLastSyncDateTime","kind":"graph-property","source":"` + src + `"}`, "Unrelated", "stale"},
	} {
		t.Run(name, func(t *testing.T) {
			files := withVocab(t, "["+c.entry+"]")
			files["internal/directory/dn/dn.go"] = "package dn\n\nvar " + c.id + " = 1\n"
			vs := run(t, repo(t, files), "P1")
			expect(t, vs, "P1", "tools/fitness/profiles/manifest.json", "externalVocabulary entry", c.why)
		})
	}
}

// A refused entry cuts nothing: registering the stem must not exempt the identifier that holds it.
func TestP1RefusedEntryDoesNotExempt(t *testing.T) {
	files := withVocab(t, `[{"term":"onPremises","kind":"graph-segment","source":"https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0"}]`)
	files["internal/directory/dn/dn.go"] = "package dn\n\nvar OnPremisesProfile = 1\n"
	expect(t, run(t, repo(t, files), "P1"), "P1", "internal/directory/dn/dn.go:3", "names a deployment profile")
}

func TestP1ExternalVocabularyAcceptsOnpremSID(t *testing.T) {
	files := withVocab(t, `[{"term":"onprem_sid","kind":"token-claim","source":"https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference"}]`)
	files["internal/directory/dn/dn.go"] = "package dn\n\nvar AnchorOnpremSID = 1\n"
	files["internal/directory/graphnames/names.go"] = "package graphnames\n"
	if vs := run(t, repo(t, files), "P1"); len(vs) != 0 {
		t.Fatalf("onprem_sid with AnchorOnpremSID in the tree validates:\n%s", dump(vs))
	}
}

func TestP1RealRegistryIsSourced(t *testing.T) {
	cfg, err := LoadConfig("../../..", defaultManifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ExternalVocabulary) == 0 {
		t.Fatal("the registry registers the terms the tree uses")
	}
	for _, e := range cfg.ExternalVocabulary {
		if !strings.HasPrefix(e.Source, "https://learn.microsoft.com/") {
			t.Errorf("%s: source %q is not a Microsoft Learn page", e.Term, e.Source)
		}
	}
}

// --- P1 erratum E-2: forwarding the environment ------------------------------------------------

func TestP1EnvironForwarding(t *testing.T) {
	const head = "package dn\n\nimport (\n\t\"os\"\n\t\"os/exec\"\n)\n\nconst envA = \"X=1\"\n\nvar _ = exec.Command\nvar _ = os.Args\n\n"
	for name, body := range map[string]string{
		"plain":            "func F(cmd *exec.Cmd) { cmd.Env = os.Environ() }\n",
		"append":           "func F(cmd *exec.Cmd) { cmd.Env = append(os.Environ(), \"X=1\") }\n",
		"append several":   "func F(cmd *exec.Cmd) { cmd.Env = append(os.Environ(), \"X=1\", \"CGO_ENABLED=0\") }\n",
		"constant concat":  "func F(cmd *exec.Cmd) { cmd.Env = append(os.Environ(), \"GOTRACEBACK=\"+\"crash\") }\n",
		"package constant": "func F(cmd *exec.Cmd) { cmd.Env = append(os.Environ(), envA) }\n",
		"method":           "func F(cmd *exec.Cmd) { cmd.Env = append(cmd.Environ(), \"GOOS=linux\") }\n",
	} {
		t.Run("allowed/"+name, func(t *testing.T) {
			root := repo(t, map[string]string{"internal/directory/dn/dn.go": head + body})
			if vs := run(t, root, "P1"); len(vs) != 0 {
				t.Fatalf("no finding:\n%s", dump(vs))
			}
		})
	}
	for name, c := range map[string]struct{ body, why string }{
		"range":             {"func F() { for range os.Environ() {} }\n", "other than as the right side"},
		"index":             {"func F() string { return os.Environ()[0] }\n", "other than as the right side"},
		"argument":          {"func F(f func([]string)) { f(os.Environ()) }\n", "passed on or consumed"},
		"range method":      {"func F(cmd *exec.Cmd) { for range cmd.Environ() {} }\n", "other than as the right side"},
		"profile name":      {"func F(cmd *exec.Cmd) { cmd.Env = append(os.Environ(), \"ACTIVEDIQ_PROFILE=saas\") }\n", "profile-selecting"},
		"profile method":    {"func F(cmd *exec.Cmd) { cmd.Env = append(cmd.Environ(), \"DIQ_SAAS=1\") }\n", "profile-selecting"},
		"variable arg":      {"func F(cmd *exec.Cmd, v string) { cmd.Env = append(os.Environ(), v) }\n", "not a constant string"},
		"function call arg": {"func mk(s string) string { return \"ACTIVEDIQ_PROFILE=saas\" }\nfunc F(cmd *exec.Cmd) { cmd.Env = append(os.Environ(), mk(\"A=1\")) }\n", "not a constant string"},
		"conversion arg":    {"func F(cmd *exec.Cmd) { cmd.Env = append(os.Environ(), string(\"A=1\")) }\n", "not a constant string"},
		"prefix arg":        {"func F(cmd *exec.Cmd, v string) { cmd.Env = append(os.Environ(), \"X=\"+v) }\n", "not a constant string"},
		"spread":            {"func F(cmd *exec.Cmd, v []string) { cmd.Env = append(os.Environ(), v...) }\n", "passed on or consumed"},
		"not Env field":     {"func F(cmd *exec.Cmd) { x := os.Environ(); _ = x }\n", "other than as the right side"},
		"other field":       {"type T struct{ Vars []string }\n\nfunc F(t *T) { t.Vars = os.Environ() }\n", "other than a child's Env"},
		"append first":      {"func F(cmd *exec.Cmd) { cmd.Env = append([]string{\"X=1\"}, os.Environ()...) }\n", "passed on or consumed"},
	} {
		t.Run("fails/"+name, func(t *testing.T) {
			root := repo(t, map[string]string{"internal/directory/dn/dn.go": head + c.body})
			expect(t, run(t, root, "P1"), "P1", "internal/directory/dn/dn.go:", "Environ", c.why)
		})
	}
}

func TestP1EnvironInConfigLoaderAndToolsIsExempt(t *testing.T) {
	root := repo(t, map[string]string{
		"internal/compose/config/env.go": "package config\n\nimport \"os\"\n\nfunc All() []string { return os.Environ() }\n",
		"tools/x/x.go":                   "package x\n\nimport \"os\"\n\nfunc All() []string { return os.Environ() }\n",
	})
	if vs := run(t, root, "P1"); len(vs) != 0 {
		t.Fatalf("the config loader and tools may read the environment:\n%s", dump(vs))
	}
}
