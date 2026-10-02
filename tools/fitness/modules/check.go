// Package main is the fitness-modules job: it enforces the layering and import rules of
// blueprint §2 (rules 1 to 5, 7 and 8) by reading import statements. It needs no network and no
// build, so it runs the same everywhere `make ci` runs. It is deliberately conservative: build
// constraints are ignored, so a file that no target compiles is still checked.
//
// ADR-0001 gives `tools/fitness/stack` to T-0022 and the module-system ADR (T-0045) will own the
// full rule set. This job carries the rules that are already binding on the skeleton, and each rule
// has a failing fixture in check_test.go.
package main

import (
	"bufio"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Violation is one broken rule at one place.
type Violation struct {
	Rule string // for example "2.1"
	Pos  string // file:line, relative to the repository root
	Msg  string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: [blueprint §%s] %s", v.Pos, v.Rule, v.Msg)
}

// pkgImports is one package directory: its repository-relative import path and its imports.
type pkgImports struct {
	dir     string   // slash-separated, relative to the root; "." for the root
	imports []imp    // from all .go files, including tests
	nonTest []string // import paths from non-test files only (the link graph)
}

type imp struct {
	path string // import path, as written
	pos  string // file:line
	file string // base name of the file
	test bool
}

// Check loads the repository at root and returns every violation, sorted.
func Check(root string) ([]Violation, error) {
	modPath, err := modulePath(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	pkgs, err := loadPackages(root, modPath)
	if err != nil {
		return nil, err
	}
	var vs []Violation
	vs = append(vs, checkImportRules(pkgs, modPath)...)
	vs = append(vs, checkBinaryHygiene(pkgs, modPath)...)
	web, err := checkWeb(root)
	if err != nil {
		return nil, err
	}
	vs = append(vs, web...)
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Pos != vs[j].Pos {
			return vs[i].Pos < vs[j].Pos
		}
		return vs[i].Msg < vs[j].Msg
	})
	return vs, nil
}

func modulePath(gomod string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(s.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", fmt.Errorf("%s: no module directive", gomod)
}

// skipDir reports directories that hold no product Go code.
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "testdata", "vendor", "factory", "knowledge", "garage", ".claude":
		return true
	}
	return false
}

func loadPackages(root, modPath string) (map[string]*pkgImports, error) {
	pkgs := map[string]*pkgImports{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		dir := path.Dir(rel)
		pk := pkgs[dir]
		if pk == nil {
			pk = &pkgImports{dir: dir}
			pkgs[dir] = pk
		}
		isTest := strings.HasSuffix(rel, "_test.go")
		for _, is := range f.Imports {
			ip, err := strconv.Unquote(is.Path.Value)
			if err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
			pos := fset.Position(is.Pos())
			pk.imports = append(pk.imports, imp{path: ip, pos: fmt.Sprintf("%s:%d", rel, pos.Line), file: path.Base(rel), test: isTest})
			if !isTest {
				pk.nonTest = append(pk.nonTest, ip)
			}
		}
		return nil
	})
	return pkgs, err
}

// local converts an import path to a repository-relative directory, or "" if it is not ours.
func local(importPath, modPath string) string {
	if importPath == modPath {
		return "."
	}
	if rest, ok := strings.CutPrefix(importPath, modPath+"/"); ok {
		return rest
	}
	return ""
}

// under reports whether dir is prefix or a descendant of prefix.
func under(dir, prefix string) bool { return dir == prefix || strings.HasPrefix(dir, prefix+"/") }

// composeRoles are the role packages under internal/compose.
var composeRoles = []string{"server", "connector", "edge", "agent"}

func isRolePkg(dir string) (string, bool) {
	for _, r := range composeRoles {
		if under(dir, "internal/compose/"+r) {
			return r, true
		}
	}
	return "", false
}

func checkImportRules(pkgs map[string]*pkgImports, modPath string) []Violation {
	var vs []Violation
	add := func(rule string, i imp, format string, args ...any) {
		vs = append(vs, Violation{Rule: rule, Pos: i.pos, Msg: fmt.Sprintf(format, args...)})
	}
	for _, pk := range pkgs {
		for _, i := range pk.imports {
			to := local(i.path, modPath)
			if to == "" {
				continue
			}
			from := pk.dir
			switch {
			case under(from, "internal/platform"):
				// Rule 1: platform imports only platform, internal/proto/skenzeriq and registered dependencies.
				for _, banned := range []string{"internal/directory", "internal/connector", "internal/modules", "internal/agentmodules", "internal/compose", "internal/proto/activediq"} {
					if under(to, banned) {
						add("2.1", i, "platform package %s imports %s; the kernel imports nothing above it", from, to)
					}
				}
			case under(from, "internal/directory"):
				// Rule 2.
				for _, banned := range []string{"internal/connector", "internal/modules", "internal/agentmodules", "internal/compose"} {
					if under(to, banned) {
						add("2.2", i, "directory package %s imports %s", from, to)
					}
				}
			case under(from, "internal/connector"):
				// Rule 3, outbound side.
				for _, banned := range []string{"internal/modules", "internal/agentmodules", "internal/compose"} {
					if under(to, banned) {
						add("2.3", i, "connector package %s imports %s", from, to)
					}
				}
			case under(from, "internal/modules"):
				// Rule 4: modules never import other modules (or agent modules, or the composition root).
				if own := moduleOf(from, "internal/modules"); under(to, "internal/modules") && moduleOf(to, "internal/modules") != own {
					add("2.4", i, "module %s imports module %s; modules cooperate through kernel registries", own, moduleOf(to, "internal/modules"))
				}
				for _, banned := range []string{"internal/agentmodules", "internal/compose"} {
					if under(to, banned) {
						add("2.4", i, "module package %s imports %s", from, to)
					}
				}
			case under(from, "internal/agentmodules"):
				if own := moduleOf(from, "internal/agentmodules"); under(to, "internal/agentmodules") && moduleOf(to, "internal/agentmodules") != own {
					add("2.4", i, "agent module %s imports agent module %s", own, moduleOf(to, "internal/agentmodules"))
				}
				for _, banned := range []string{"internal/modules", "internal/connector", "internal/compose"} {
					if under(to, banned) {
						add("2.7", i, "agent module package %s imports %s", from, to)
					}
				}
			}

			// Rule 3, inbound side: who may import the connector root.
			if under(to, "internal/connector") && !under(from, "internal/connector") &&
				!(under(from, "internal/compose/server") || under(from, "internal/compose/connector") || under(from, "internal/compose/t0connector") || under(from, "tools/fitness")) {
				add("2.3", i, "%s may not import %s; only compose/server, compose/connector, compose/t0connector and tools/fitness do", from, to)
			}
			// Rule 5: only the generated lists name a module.
			if (under(to, "internal/modules") && to != "internal/modules") || (under(to, "internal/agentmodules") && to != "internal/agentmodules") {
				own := under(from, "internal/modules") || under(from, "internal/agentmodules")
				generated := i.file == "modules.gen.go" && (from == "internal/compose/server" || from == "internal/compose/agent")
				if !own && !generated {
					add("2.5", i, "%s imports %s; only the generated modules.gen.go of compose/server and compose/agent may name a module", from, to)
				}
			}
			// Composition root: nothing outside it (and cmd/) imports it; role packages never import each other.
			if under(to, "internal/compose") && !under(from, "internal/compose") && !under(from, "cmd") && !under(from, "tools/fitness") {
				add("1", i, "%s imports %s; nothing outside cmd/ and the composition root imports internal/compose", from, to)
			}
			if r, ok := isRolePkg(from); ok {
				if r2, ok2 := isRolePkg(to); ok2 && r != r2 {
					add("1", i, "role package %s imports role package %s; role packages never import each other", r, r2)
				}
			}
			if under(from, "internal/compose/profile") && !under(to, "internal/platform/capability") && !under(to, "internal/compose/profile") {
				add("3.2", i, "profile is data only: it may import only platform/capability, not %s", to)
			}
			// cmd/<role> calls only its own role package.
			if under(from, "cmd") {
				role := strings.TrimPrefix(from, "cmd/")
				if r2, ok := isRolePkg(to); ok && r2 != role {
					add("1", i, "cmd/%s imports role package %s; a binary calls only its own role package", role, r2)
				}
			}
		}
	}
	return vs
}

// moduleOf returns the first path element below root, i.e. the module's ID.
func moduleOf(dir, root string) string {
	rest := strings.TrimPrefix(strings.TrimPrefix(dir, root), "/")
	first, _, _ := strings.Cut(rest, "/")
	return first
}

// forbidden is the blueprint §2 rule 7 table: what each binary's link graph must not contain.
var forbidden = map[string][]string{
	"server":    {"internal/agentmodules"},
	"connector": {"internal/modules", "internal/platform/apihost", "internal/webui", "internal/platform/store"},
	"edge":      {"internal/modules", "internal/connector", "internal/platform/store", "internal/platform/keys"},
	"agent":     {"internal/modules", "internal/connector", "internal/platform/apihost", "internal/platform/store", "internal/webui"},
}

func checkBinaryHygiene(pkgs map[string]*pkgImports, modPath string) []Violation {
	var vs []Violation
	for role, banned := range forbidden {
		start := "cmd/" + role
		if pkgs[start] == nil {
			continue
		}
		// Breadth-first over the link graph (non-test files), remembering the first importer.
		via := map[string]string{start: ""}
		queue := []string{start}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			pk := pkgs[cur]
			if pk == nil {
				continue
			}
			for _, ip := range pk.nonTest {
				to := local(ip, modPath)
				if to == "" {
					continue
				}
				if _, seen := via[to]; !seen {
					via[to] = cur
					queue = append(queue, to)
				}
			}
		}
		for dep, from := range via {
			for _, b := range banned {
				if under(dep, b) && dep != start {
					vs = append(vs, Violation{Rule: "2.7", Pos: "cmd/" + role, Msg: fmt.Sprintf("binary %s links %s (via %s); it must not contain %s", role, dep, from, b)})
				}
			}
		}
	}
	return vs
}

var tsImport = regexp.MustCompile(`(?:from\s+|import\s*\(\s*|import\s+|require\(\s*)['"]([^'"]+)['"]`)

// checkWeb enforces blueprint §2 rule 8: web/src/app and web/src/ds never import web/src/modules/*,
// except that app may import the generated modules.gen.ts.
func checkWeb(root string) ([]Violation, error) {
	var vs []Violation
	src := filepath.Join(root, "web", "src")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return nil, nil
	}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(p)
		if ext != ".ts" && ext != ".tsx" {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		layer := ""
		switch {
		case under(rel, "web/src/app"):
			layer = "app"
		case under(rel, "web/src/ds"):
			layer = "ds"
		default:
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for n, line := range strings.Split(string(data), "\n") {
			for _, m := range tsImport.FindAllStringSubmatch(line, -1) {
				spec := m[1]
				target := spec
				if strings.HasPrefix(spec, ".") {
					target = path.Clean(path.Join(path.Dir(rel), spec))
				}
				toModules := under(target, "web/src/modules") || strings.HasPrefix(target, "src/modules") || strings.HasPrefix(target, "@/modules")
				if toModules && !(layer == "app" && path.Base(target) == "modules.gen") {
					vs = append(vs, Violation{Rule: "2.8", Pos: fmt.Sprintf("%s:%d", rel, n+1), Msg: fmt.Sprintf("web/src/%s imports %q; app and ds never import web/src/modules (only app may import the generated modules.gen)", layer, spec)})
				}
			}
		}
		return nil
	})
	return vs, err
}
