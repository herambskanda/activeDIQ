package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/tools/gen/modules/modlist"
)

const mod = "example.test/m"

// tree writes files (path -> content) under a temp repository root with a go.mod.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files["go.mod"] = "module " + mod + "\n\ngo 1.27.0\n"
	if _, ok := files[blueprintPath]; !ok {
		files[blueprintPath] = catalogueFor(files)
	}
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

// blueprintDoc renders a blueprint with the three §5 tables, one body per section.
func blueprintDoc(s51, s52, s53 string) string {
	tbl := func(h, rows string) string {
		return "### " + h + "\n\n| Package | Owner | Interface | EPs |\n| --- | --- | --- | --- |\n" + rows + "\n"
	}
	return "## 5. Component catalogue\n\n" + tbl("5.1 Platform kernel (`internal/platform/`)", s51) +
		tbl("5.2 Directory domain (`internal/directory`)", s52) + tbl("5.3 Connector root (`internal/connector/`)", s53) +
		"### 5.4 Server feature modules\n\n| Package | Owner |\n| --- | --- |\n| `objects` | x |\n"
}

func row(first string) string { return "| " + first + " | owner | interface | — |\n" }

// catalogueFor writes one correct row for every package directory under the three roots.
func catalogueFor(files map[string]string) string {
	var rows [3]string
	seen := map[string]bool{}
	for p := range files {
		for i, r := range catalogueRoots {
			if rest, ok := strings.CutPrefix(p, r.dir+"/"); ok && strings.Contains(rest, "/") && strings.HasSuffix(p, ".go") {
				name, _, _ := strings.Cut(rest, "/")
				if !seen[r.dir+name] {
					seen[r.dir+name] = true
					rows[i] += row("`" + name + "`")
				}
			}
		}
	}
	return blueprintDoc(rows[0], rows[1], rows[2])
}

// goPkg renders a Go file importing the given repository-relative packages.
func goPkg(name string, imports ...string) string {
	var b strings.Builder
	b.WriteString("package " + name + "\n\nimport (\n")
	for _, i := range imports {
		b.WriteString("\t_ \"" + mod + "/" + i + "\"\n")
	}
	b.WriteString(")\n")
	return b.String()
}

func leaf(name string) string { return "package " + name + "\n" }

// expect runs Check and requires at least one violation of rule whose message contains want.
// One mistake can legitimately break several rules, so other violations are allowed.
func expect(t *testing.T, files map[string]string, rule, want string) {
	t.Helper()
	vs, err := Check(tree(t, files))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.Rule == rule && strings.Contains(v.Msg, want) {
			return
		}
	}
	t.Fatalf("want a violation of §%s containing %q, got %v", rule, want, vs)
}

func expectClean(t *testing.T, files map[string]string) {
	t.Helper()
	vs, err := Check(tree(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 0 {
		t.Fatalf("want no violations, got %v", vs)
	}
}

// The two generated lists of the clean tree, rendered by the same code the generator uses.
var baseServerList, baseAgentList = modlist.Render(mod, modlist.Lists{
	Server: []string{"helpdesk", "objects"},
	Agent:  []modlist.AgentModule{{ID: "addc"}},
})

// base is a clean layered tree every failing case is derived from.
func base() map[string]string {
	return map[string]string{
		"internal/platform/capability/c.go":  leaf("capability"),
		"internal/platform/module/m.go":      goPkg("module", "internal/platform/capability"),
		"internal/directory/d.go":            goPkg("directory", "internal/platform/module"),
		"internal/connector/c.go":            goPkg("connector", "internal/directory"),
		"internal/modules/objects/o.go":      goPkg("objects", "internal/platform/module", "internal/directory"),
		"internal/modules/objects/id.go":     "package objects\n\nconst ModuleID = \"objects\"\n",
		"internal/modules/helpdesk/h.go":     goPkg("helpdesk", "internal/platform/module"),
		"internal/modules/helpdesk/id.go":    "package helpdesk\n\nconst ModuleID = \"helpdesk\"\n",
		"internal/agentmodules/addc/a.go":    goPkg("addc", "internal/platform/module"),
		"internal/agentmodules/addc/kind.go": "package addc\n\nconst Kind = \"addc\"\n",
		pagesDir + "/README.md":              "# index\n",
		pagesDir + "/objects.md":             "# objects\n",
		pagesDir + "/helpdesk.md":            "# helpdesk\n",
		pagesDir + "/addc.md":                "# addc\n",
		"internal/compose/config/c.go":       leaf("config"),
		"internal/compose/profile/p.go":      goPkg("profile", "internal/platform/capability"),
		"internal/compose/server/s.go":       goPkg("server", "internal/compose/config", "internal/connector"),
		modlist.ServerFile:                   string(baseServerList),
		modlist.AgentFile:                    string(baseAgentList),
		"internal/compose/agent/a.go":        goPkg("agent", "internal/compose/config"),
		"internal/compose/edge/e.go":         goPkg("edge", "internal/compose/config"),
		"internal/compose/connector/c.go":    goPkg("connector", "internal/compose/config", "internal/connector"),
		"cmd/server/main.go":                 goPkg("main", "internal/compose/server"),
		"cmd/agent/main.go":                  goPkg("main", "internal/compose/agent"),
		"cmd/edge/main.go":                   goPkg("main", "internal/compose/edge"),
		"cmd/connector/main.go":              goPkg("main", "internal/compose/connector"),
	}
}

func with(extra map[string]string) map[string]string {
	m := base()
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestCleanTreePasses(t *testing.T) { expectClean(t, base()) }

func TestRule1PlatformImportsNothingAbove(t *testing.T) {
	for _, above := range []string{"internal/directory", "internal/connector", "internal/modules/objects", "internal/agentmodules/addc", "internal/compose/config"} {
		expect(t, with(map[string]string{"internal/platform/module/m.go": goPkg("module", above)}), "2.1", above)
	}
}

func TestRule2DirectoryImportsNoConnectorModuleOrCompose(t *testing.T) {
	expect(t, with(map[string]string{"internal/directory/d.go": goPkg("directory", "internal/connector")}), "2.2", "internal/connector")
	expect(t, with(map[string]string{"internal/directory/d.go": goPkg("directory", "internal/modules/objects")}), "2.2", "internal/modules/objects")
}

func TestRule3ConnectorImportersAreFixed(t *testing.T) {
	// A module, the directory domain and a cmd must not import the connector root.
	expect(t, with(map[string]string{"internal/modules/objects/o.go": goPkg("objects", "internal/connector")}), "2.3", "internal/connector")
	expect(t, with(map[string]string{"internal/compose/edge/e.go": goPkg("edge", "internal/connector")}), "2.3", "compose/edge")
	// ... and the connector may not reach up into modules.
	expect(t, with(map[string]string{"internal/connector/c.go": goPkg("connector", "internal/modules/objects")}), "2.3", "connector package")
}

func TestRule4ModulesNeverImportEachOther(t *testing.T) {
	expect(t, with(map[string]string{"internal/modules/objects/o.go": goPkg("objects", "internal/modules/helpdesk")}), "2.4", "helpdesk")
	// Importing one's own subpackage is fine.
	expectClean(t, with(map[string]string{
		"internal/modules/objects/sub/s.go": leaf("sub"),
		"internal/modules/objects/o.go":     goPkg("objects", "internal/modules/objects/sub"),
	}))
}

func TestRule5OnlyGeneratedListsNameAModule(t *testing.T) {
	// Handwritten file in compose/server naming a module.
	expect(t, with(map[string]string{"internal/compose/server/s.go": goPkg("server", "internal/modules/objects")}), "M3a", "modules.gen.go")
	// The generated filename in the wrong package.
	expect(t, with(map[string]string{"internal/compose/edge/modules.gen.go": goPkg("edge", "internal/modules/objects")}), "M3a", "internal/compose/edge")
	// cmd naming a module.
	expect(t, with(map[string]string{"cmd/edge/main.go": goPkg("main", "internal/compose/edge", "internal/modules/objects")}), "M3a", "cmd/edge")
}

func TestComposeRootIsPrivate(t *testing.T) {
	expect(t, with(map[string]string{"internal/modules/objects/o.go": goPkg("objects", "internal/compose/config")}), "2.4", "internal/compose")
	expect(t, with(map[string]string{"internal/directory/d.go": goPkg("directory", "internal/compose/config")}), "2.2", "internal/compose")
	expect(t, with(map[string]string{"internal/other/o.go": goPkg("other", "internal/compose/config")}), "1", "internal/other")
}

func TestRolePackagesNeverImportEachOther(t *testing.T) {
	expect(t, with(map[string]string{"internal/compose/edge/e.go": goPkg("edge", "internal/compose/server")}), "1", "never import each other")
	expect(t, with(map[string]string{"cmd/edge/main.go": goPkg("main", "internal/compose/server")}), "1", "own role package")
}

func TestProfileIsDataOnly(t *testing.T) {
	expect(t, with(map[string]string{"internal/compose/profile/p.go": goPkg("profile", "internal/platform/capability", "internal/platform/module")}), "3.2", "data only")
}

func TestRule7BinaryHygiene(t *testing.T) {
	// edge linking the database package through a helper: every single import is legal on its own,
	// only the link graph shows it.
	expect(t, with(map[string]string{
		"internal/platform/store/s.go":  leaf("store"),
		"internal/platform/helper/h.go": goPkg("helper", "internal/platform/store"),
		"internal/compose/edge/e.go":    goPkg("edge", "internal/compose/config", "internal/platform/helper"),
	}), "2.7", "binary edge links internal/platform/store (via internal/platform/helper)")
	// A test-only import is not part of the link graph.
	expectClean(t, with(map[string]string{
		"internal/platform/store/s.go":    leaf("store"),
		"internal/compose/edge/e_test.go": goPkg("edge_test", "internal/platform/store"),
	}))
	// The server binary must not contain agent modules.
	expect(t, with(map[string]string{"internal/compose/server/s.go": goPkg("server", "internal/agentmodules/addc")}), "2.7", "binary server links internal/agentmodules/addc")
}

func TestRule8WebAppAndDsNeverImportModules(t *testing.T) {
	web := func(p, c string) map[string]string { return with(map[string]string{p: c}) }
	expect(t, web("web/src/app/shell.tsx", "import { X } from '../modules/objects/screen';\n"), "2.8", "web/src/app")
	expect(t, web("web/src/ds/button.tsx", "import x from \"../modules/objects/x\"\n"), "2.8", "web/src/ds")
	expect(t, web("web/src/ds/button.tsx", "const m = await import('../modules/objects/x')\n"), "2.8", "web/src/ds")
	// app may import the generated list, ds may not.
	expectClean(t, web("web/src/app/routes.tsx", "import { modules } from './modules.gen';\n"))
	expect(t, web("web/src/ds/button.tsx", "import { modules } from '../modules/modules.gen';\n"), "2.8", "web/src/ds")
	// modules may import app and ds.
	expectClean(t, web("web/src/modules/objects/screen.tsx", "import { Button } from '../../ds/button';\n"))
}

// M7 (ADR-0003 closed catalogue). Each case starts from a tree whose catalogue is correct and breaks
// one thing.
func TestM7CatalogueRows(t *testing.T) {
	pkgs := map[string]string{
		"internal/platform/store/s.go":     leaf("store"),
		"internal/platform/store/sub/x.go": leaf("sub"),
		"internal/platform/deps.go":        leaf("platform"),
		"internal/directory/dn/d.go":       leaf("dn"),
		"internal/directory/doc.go":        leaf("directory"),
		"internal/connector/read/r.go":     leaf("read"),
		"internal/connector/empty/.keep":   "",
	}
	fixture := func(s51, s52, s53 string) map[string]string {
		m := map[string]string{blueprintPath: blueprintDoc(s51, s52, s53)}
		for k, v := range pkgs {
			m[k] = v
		}
		return m
	}
	good := func() (string, string, string) {
		return row("`store` (+`store/reportsql`)") + row("`store/reportsql`") + row("`planned`"), row("`dn`"), row("`read`")
	}

	t.Run("complete catalogue passes; planned names, subpackage rows and non-packages are fine", func(t *testing.T) {
		a, b, c := good()
		expectClean(t, fixture(a, b, c))
	})
	t.Run("missing row", func(t *testing.T) {
		_, b, c := good()
		expect(t, fixture(row("`planned`"), b, c), "M7", "package internal/platform/store has no row in blueprint §5.1")
	})
	t.Run("duplicated row", func(t *testing.T) {
		a, b, c := good()
		expect(t, fixture(a+row("`store`"), b, c), "M7", "internal/platform/store has 2 rows in blueprint §5.1")
	})
	t.Run("row in the wrong section", func(t *testing.T) {
		a, _, c := good()
		expect(t, fixture(a, "", c+row("`dn`")), "M7", "internal/directory/dn is named only in blueprint §5.3, not in its own §5.2")
	})
	t.Run("a (+sub) mention does not count", func(t *testing.T) {
		_, b, c := good()
		expect(t, fixture(row("`other` (+`store`)"), b, c), "M7", "internal/platform/store has no row")
	})
	t.Run("a subpackage-only row does not count", func(t *testing.T) {
		_, b, c := good()
		expect(t, fixture(row("`store/reportsql`"), b, c), "M7", "internal/platform/store has no row")
	})
	t.Run("one row naming two packages counts for each", func(t *testing.T) {
		a, _, c := good()
		expectClean(t, fixture(a, row("`dn`, `ldapfilter`"), c))
	})
	t.Run("the failure names the package, section and rule", func(t *testing.T) {
		_, b, c := good()
		vs, err := Check(tree(t, fixture(row("`planned`"), b, c)))
		if err != nil || len(vs) != 1 {
			t.Fatalf("want one violation, got %v, %v", vs, err)
		}
		for _, want := range []string{"ADR-0003 M7", "internal/platform/store", "§5.1", "closed catalogue"} {
			if !strings.Contains(vs[0].String(), want) {
				t.Fatalf("%q missing from %q", want, vs[0])
			}
		}
	})
	t.Run("a missing blueprint or section is an error, not a pass", func(t *testing.T) {
		m := fixture("", "", "")
		m[blueprintPath] = "## 5. Component catalogue\n"
		if _, err := Check(tree(t, m)); err == nil {
			t.Fatal("want an error for a blueprint without §5.1")
		}
	})
}

// ---- M3a, TG2, TG3, OW1 (ADR-0015): each rule has a failing fixture and the clean tree passes. ----

func without(m map[string]string, keys ...string) map[string]string {
	for _, k := range keys {
		delete(m, k)
	}
	return m
}

func TestM3aListMustCarryTheGeneratedHeader(t *testing.T) {
	hand := strings.TrimPrefix(string(baseServerList), modlist.Header+"\n\n")
	expect(t, with(map[string]string{modlist.ServerFile: hand}), "M3a", "generated header")
	expect(t, with(map[string]string{modlist.AgentFile: "package agent\n"}), "M3a", "generated header")
}

func TestM3aListMustRegenerateToTheSameBytes(t *testing.T) {
	// Stale: a module exists that the list does not name.
	expect(t, with(map[string]string{"internal/modules/inventory/m.go": "package inventory\n\nconst ModuleID = \"inventory\"\n", pagesDir + "/inventory.md": "x"}), "M3a", "stale or hand-edited")
	// Hand-edited: same header, one byte different.
	expect(t, with(map[string]string{modlist.ServerFile: string(baseServerList) + "// edited\n"}), "M3a", "stale or hand-edited")
	// Missing list while modules exist.
	expect(t, without(base(), modlist.ServerFile), "M3a", "list is missing")
}

func TestM3aModuleNeedsAPageAndPageNeedsAModule(t *testing.T) {
	expect(t, without(base(), pagesDir+"/helpdesk.md"), "M3a-page", "no architecture page")
	expect(t, without(base(), pagesDir+"/addc.md"), "M3a-page", "internal/agentmodules/addc")
	expect(t, with(map[string]string{pagesDir + "/ghost.md": "x"}), "M3a-orphan", "no module")
	// README and non-ID names (platform pages) are not module pages.
	expectClean(t, with(map[string]string{pagesDir + "/operation-persistence.md": "x"}))
}

func TestM3aBaselineIsHonouredAndCannotGoStale(t *testing.T) {
	m := with(map[string]string{pagesDir + "/ghost.md": "x", baselinePath: "no-module ghost # T-9999\n"})
	expectClean(t, m)
	// The debt is paid but the line stays: the build fails so the baseline shrinks.
	expect(t, with(map[string]string{baselinePath: "no-module ghost\n"}), "M3a", "matches no violation")
}

const tplPlan = `package ad

import (
	"fmt"
	"context"

	"example.test/m/internal/modules/objects"
	"example.test/m/internal/platform/operation"
)

type TemplateRef struct{ ID string }

func load(ctx context.Context, pc operation.PlanContext, ref TemplateRef) (objects.Template, error) {
	return objects.Template{}, nil
}

func planCreate(ctx context.Context, pc operation.PlanContext, ref TemplateRef) error {
%s}
`

func tg2Tree(body string) map[string]string {
	return with(map[string]string{
		"internal/modules/ad/p.go":      fmt.Sprintf(tplPlan, body),
		"internal/modules/ad/id.go":     "package ad\n\nconst ModuleID = \"ad\"\n",
		pagesDir + "/ad.md":             "x",
		modlist.ServerFile:              string(serverListWith("ad", "helpdesk", "objects")),
		"internal/modules/objects/t.go": "package objects\n\ntype Template struct{}\n",
	})
}

func serverListWith(ids ...string) []byte {
	s, _ := modlist.Render(mod, modlist.Lists{Server: ids, Agent: []modlist.AgentModule{{ID: "addc"}}})
	return s
}

func TestTG2PlanMustCheckTheTemplateGateFirst(t *testing.T) {
	// The ad fixtures import objects, so TG2 aside they trip rule 2.4; only TG2 is asserted here.
	expect(t, tg2Tree("\t_, err := load(ctx, pc, ref)\n\treturn err\n"), "TG2", "never calls pc.Templates.CheckTemplate")
	expect(t, tg2Tree("\tpc.Facts.Facts(ctx, nil)\n\tif err := pc.Templates.CheckTemplate(ctx, \"p\", ref.ID); err != nil {\n\t\treturn err\n\t}\n\t_, err := load(ctx, pc, ref)\n\treturn err\n"), "TG2", "after a CheckInput, Facts")
	// The helper that reads counts at its call site: gate after `load` is too late.
	expect(t, tg2Tree("\t_, _ = load(ctx, pc, ref)\n\treturn pc.Templates.CheckTemplate(ctx, \"p\", ref.ID)\n"), "TG2", "after a CheckInput, Facts")
}

func TestTG2PassesWhenGateComesFirst(t *testing.T) {
	vs, err := Check(tree(t, tg2Tree("\tif err := pc.Templates.CheckTemplate(ctx, \"p\", ref.ID); err != nil {\n\t\treturn err\n\t}\n\t_, err := load(ctx, pc, ref)\n\treturn err\n")))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.Rule == "TG2" {
			t.Fatalf("unexpected %v", v)
		}
	}
}

func TestTG3TemplateConsumersMustNotImportRbac(t *testing.T) {
	rbac := goPkg("x", "internal/platform/rbac")
	// ad, objects, and a module that imports objects.
	expect(t, with(map[string]string{"internal/modules/objects/r.go": rbac}), "TG3", "internal/platform/rbac")
	expect(t, with(map[string]string{"internal/modules/helpdesk/r.go": goPkg("helpdesk", "internal/modules/objects", "internal/platform/rbac")}), "TG3", "imports internal/modules/objects")
	// A module that does not touch objects may import rbac; a test file may too.
	vs, err := Check(tree(t, with(map[string]string{"internal/modules/helpdesk/r.go": rbac})))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.Rule == "TG3" {
			t.Fatalf("unexpected %v", v)
		}
	}
	// The allowlist exempts a wiring module that imports objects, but never ad or objects.
	m := with(map[string]string{"internal/modules/helpdesk/r.go": goPkg("helpdesk", "internal/modules/objects", "internal/platform/rbac"), tg3AllowPath: "helpdesk # wires rbac\n"})
	vs, _ = Check(tree(t, m))
	for _, v := range vs {
		if v.Rule == "TG3" {
			t.Fatalf("allowlisted module reported: %v", v)
		}
	}
	expect(t, with(map[string]string{tg3AllowPath: "objects\n"}), "TG3", "cannot be on the TG3 allowlist")
}

func TestOW1ObjectsActionsTargetTheStore(t *testing.T) {
	desc := func(pkg, id, target string) string {
		return "package " + pkg + "\n\nvar d = operation.Descriptor{ID: " + id + ", Target: " + target + "}\n"
	}
	expect(t, with(map[string]string{"internal/modules/objects/a.go": desc("objects", `"objects.template.create"`, "operation.TargetAD")}), "OW1", "TargetStore")
	// An objects.* ID is caught in any module, through a const.
	expect(t, with(map[string]string{"internal/modules/helpdesk/a.go": "package helpdesk\n\nconst id = \"objects.template.apply\"\n\nvar d = operation.Descriptor{ID: operation.ActionID(id), Target: operation.TargetAD}\n"}), "OW1", "TargetStore")
	// Store Actions of objects, and other modules' AD Actions, are fine.
	vs, _ := Check(tree(t, with(map[string]string{
		"internal/modules/objects/a.go":  desc("objects", `"objects.template.create"`, "operation.TargetStore"),
		"internal/modules/helpdesk/a.go": desc("helpdesk", `"helpdesk.grant"`, "operation.TargetAD"),
	})))
	for _, v := range vs {
		if v.Rule == "OW1" {
			t.Fatalf("unexpected %v", v)
		}
	}
}
