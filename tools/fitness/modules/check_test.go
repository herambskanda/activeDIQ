package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// base is a clean layered tree every failing case is derived from.
func base() map[string]string {
	return map[string]string{
		"internal/platform/capability/c.go":      leaf("capability"),
		"internal/platform/module/m.go":          goPkg("module", "internal/platform/capability"),
		"internal/directory/d.go":                goPkg("directory", "internal/platform/module"),
		"internal/connector/c.go":                goPkg("connector", "internal/directory"),
		"internal/modules/objects/o.go":          goPkg("objects", "internal/platform/module", "internal/directory"),
		"internal/modules/helpdesk/h.go":         goPkg("helpdesk", "internal/platform/module"),
		"internal/agentmodules/addc/a.go":        goPkg("addc", "internal/platform/module"),
		"internal/compose/config/c.go":           leaf("config"),
		"internal/compose/profile/p.go":          goPkg("profile", "internal/platform/capability"),
		"internal/compose/server/s.go":           goPkg("server", "internal/compose/config", "internal/connector"),
		"internal/compose/server/modules.gen.go": goPkg("server", "internal/modules/objects", "internal/modules/helpdesk"),
		"internal/compose/agent/a.go":            goPkg("agent", "internal/compose/config"),
		"internal/compose/agent/modules.gen.go":  goPkg("agent", "internal/agentmodules/addc"),
		"internal/compose/edge/e.go":             goPkg("edge", "internal/compose/config"),
		"internal/compose/connector/c.go":        goPkg("connector", "internal/compose/config", "internal/connector"),
		"cmd/server/main.go":                     goPkg("main", "internal/compose/server"),
		"cmd/agent/main.go":                      goPkg("main", "internal/compose/agent"),
		"cmd/edge/main.go":                       goPkg("main", "internal/compose/edge"),
		"cmd/connector/main.go":                  goPkg("main", "internal/compose/connector"),
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
	expect(t, with(map[string]string{"internal/compose/server/s.go": goPkg("server", "internal/modules/objects")}), "2.5", "modules.gen.go")
	// The generated filename in the wrong package.
	expect(t, with(map[string]string{"internal/compose/edge/modules.gen.go": goPkg("edge", "internal/modules/objects")}), "2.5", "internal/compose/edge")
	// cmd naming a module.
	expect(t, with(map[string]string{"cmd/edge/main.go": goPkg("main", "internal/compose/edge", "internal/modules/objects")}), "2.5", "cmd/edge")
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
