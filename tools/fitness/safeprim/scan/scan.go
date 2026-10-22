// Package scan implements the static safe-primitives fitness functions FF-SP1 to FF-SP3 of
// knowledge/development/architecture/safe-primitives.md §8 (T-0033):
//
//	FF-SP1  import boundaries: the LDAP library, SQL drivers, process APIs, output-encoder libraries
//	        and the PowerShell SDK each have one home.
//	FF-SP2  banned APIs: the per-primitive lists, by name and literal, plus the type-aware go/analysis
//	        passes in tools/analyzers (dnstring, sqlconst, secretjson, tmplconst).
//	FF-SP3  literal-shape scanner: filter-, DN-, PowerShell-, SQL-, HTML- and mail-shaped literals
//	        combined with concatenation or formatting outside their primitive package. Go, C# and Rust
//	        are scanned here; TypeScript under web/ is scanned by the ESLint rules in web/eslint/.
//
// Everything here is plain go/parser and text scanning, with no network and no external tool, so it
// runs the same everywhere `make ci` runs. Build constraints are ignored on purpose. Where each
// primitive lives is tools/analyzers/policy; the rule tables are rules.go.
package scan

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Finding is one broken rule at one place.
type Finding struct {
	FF   string // FF-SP1, FF-SP2 or FF-SP3
	Rule string
	File string // repository-relative, slash-separated
	Line int
	Msg  string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s [%s] %s", f.File, f.Line, f.FF, f.Rule, f.Msg)
}

// Checks selects which fitness functions run.
type Checks map[string]bool

// AllChecks is FF-SP1 to FF-SP3.
func AllChecks() Checks { return Checks{"FF-SP1": true, "FF-SP2": true, "FF-SP3": true} }

// skipDir reports directories that hold no product code (a root-level one is still entered when a
// package product code imports lives in it, T-0082). Only names that can never be a product
// package are skipped at any depth (.git, and testdata fixtures under tools/). node_modules is not
// one of them: Go does not ignore it, so internal/node_modules/p, or web/node_modules/dep, is an
// importable product package (T-0083). Beside a package.json it is handled by npmDir instead:
// non-Go content is skipped, Go files of our module are still scanned. Every other skip is tied to
// where that directory really is: repository-level working trees at the root, and build output
// only beside the project file that produces it (bin and obj beside a .csproj, target beside
// Cargo.toml, dist beside package.json). A product package that happens to be called target, bin
// or obj, such as internal/modules/target, is therefore scanned.
func skipDir(root, rel, name string) bool {
	return skipDirUnless(root, rel, name, nil)
}

// rootSkipped are the root-level directories that normally hold no product code. They stay
// skipped unless a package that product code reaches lives in them (T-0082).
var rootSkipped = map[string]bool{"vendor": true, "factory": true, "knowledge": true, "garage": true, ".claude": true, "dist": true, "third_party": true}

// skipDirUnless is skipDir, except that a root-level directory in rootSkipped is entered when it
// overlaps a directory in entered (see enteredDirs): it is one, holds one, or lies inside one.
func skipDirUnless(root, rel, name string, entered map[string]bool) bool {
	switch name {
	case ".git":
		return true
	case "testdata":
		// Go lets product code import a testdata (or _x, .x) package, and it then ships. Only the
		// analyzer fixtures under tools/ are exempt: they are deliberate violations.
		return strings.HasPrefix(rel, "tools/")
	}
	if !strings.Contains(rel, "/") {
		if rootSkipped[name] {
			return !overlapsEntered(rel, entered)
		}
	}
	parent := filepath.Join(root, filepath.FromSlash(filepath.ToSlash(filepath.Dir(rel))))
	switch name {
	case "bin", "obj":
		return dirHasSuffix(parent, ".csproj", ".fsproj", ".vbproj")
	case "target":
		return dirHasName(parent, "Cargo.toml")
	case "dist":
		return dirHasName(parent, "package.json")
	}
	return false
}

// npmDir reports a node_modules directory directly beside a package.json.
func npmDir(root, rel, name string) bool {
	if name != "node_modules" {
		return false
	}
	return dirHasName(filepath.Join(root, filepath.FromSlash(filepath.Dir(rel))), "package.json")
}

// scanNPM walks an npm node_modules tree. npm's own content is not product code, but Go builds any
// .go file there that belongs to our module, and a nested go.mod can be pulled in with a replace
// directive, so every .go file and go.mod is scanned like any other (T-0083). There is no
// structural skip: fail closed, and use a reviewed allowlist if an npm package ever ships Go.
func scanNPM(root, rel, module string, checks Checks, out *[]Finding) error {
	return filepath.WalkDir(filepath.Join(root, filepath.FromSlash(rel)), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		r, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		r = filepath.ToSlash(r)
		if d.IsDir() {
			if d.Name() == ".git" || (d.Name() == "testdata" && strings.HasPrefix(r, "tools/")) {
				return fs.SkipDir
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(r), ".go") || d.Name() == "go.mod" {
			return scanFile(root, r, module, checks, out)
		}
		return nil
	})
}

// dirHasName reports whether dir directly contains a file called exactly one of names.
func dirHasName(dir string, names ...string) bool {
	for _, n := range names {
		if st, err := os.Stat(filepath.Join(dir, n)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

// dirHasSuffix reports whether dir directly contains a file whose name ends in one of suffixes.
func dirHasSuffix(dir string, suffixes ...string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		for _, sfx := range suffixes {
			if strings.HasSuffix(e.Name(), sfx) {
				return true
			}
		}
	}
	return false
}

// Scan walks the repository at root and returns every finding of the selected checks, sorted. It
// covers the syntactic half of FF-SP1 to FF-SP3; the go/analysis passes run through Analyze.
func Scan(root string, checks Checks) ([]Finding, error) {
	module, _ := modulePath(filepath.Join(root, "go.mod"))
	var out []Finding
	entered, err := enteredDirs(root, module)
	if err != nil {
		return nil, err
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && skipDirUnless(root, rel, d.Name(), entered) {
				return fs.SkipDir
			}
			if rel != "." && npmDir(root, rel, d.Name()) {
				if err := scanNPM(root, rel, module, checks, &out); err != nil {
					return err
				}
				return fs.SkipDir
			}
			return nil
		}
		if inRootSkipped(rel) && !underEntered(rel, entered) {
			return nil // a file of a skipped root directory that no shipped package reaches
		}
		return scanFile(root, rel, module, checks, &out)
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
	return out, nil
}

func inRootSkipped(rel string) bool {
	top, _, nested := strings.Cut(rel, "/")
	return nested && rootSkipped[top]
}

func scanFile(root, rel, module string, checks Checks, out *[]Finding) error {
	ext := strings.ToLower(filepath.Ext(rel))
	base := filepath.Base(rel)
	switch {
	case ext == ".go":
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return err
		}
		if err := scanGo(rel, src, module, checks, out); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
	case base == "go.mod":
		return scanGoMod(root, rel, checks, out)
	case ext == ".cs" || ext == ".csproj" || base == "Directory.Build.props":
		return scanText(root, rel, csRules, checks, out)
	case ext == ".rs":
		return scanText(root, rel, rustRules, checks, out)
	case base == "package.json" && strings.HasPrefix(rel, "web/"):
		return scanWebPackage(root, rel, checks, out)
	case ext == ".sql":
		return scanText(root, rel, sqlRules, checks, out)
	}
	return scanServiceDefinition(root, rel, ext, base, checks, out)
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
