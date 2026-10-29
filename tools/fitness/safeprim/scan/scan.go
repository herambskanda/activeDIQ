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

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
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
// only beside the project file that produces it (buildOutDir), and even then Go files are scanned. A product package that happens to be
// called target, bin or obj, such as internal/modules/target, is therefore scanned.
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
	return false
}

// buildOutDir reports a directory that, beside the project file producing it, normally holds build
// output: bin and obj beside a .csproj, target beside Cargo.toml, dist beside package.json. Its
// non-Go content is skipped, but Go ignores none of these names, so a main-module .go file inside
// is an importable product package: scanGoOnly still scans those (T-0084).
func buildOutDir(root, rel, name string) bool {
	parent := filepath.Join(root, filepath.FromSlash(filepath.Dir(rel)))
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

// scanGoOnly walks a directory whose non-Go content is not product code (an npm node_modules tree, or
// build output, T-0084). That content is not product code, but Go builds any
// .go file there that belongs to our module, and a nested go.mod can be pulled in with a replace
// directive, so every .go file and go.mod is scanned like any other (T-0083). There is no
// structural skip: fail closed, and use a reviewed allowlist if an npm package ever ships Go.
func scanGoOnly(root, rel, module string, checks Checks, out *[]Finding) error {
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
		if strings.EqualFold(filepath.Ext(r), ".go") || d.Name() == "go.mod" || isNativeSource(r) {
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
			if rel != "." && (npmDir(root, rel, d.Name()) || buildOutDir(root, rel, d.Name())) {
				if err := scanGoOnly(root, rel, module, checks, &out); err != nil {
					return err
				}
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// Checked before the skipped-path filter: the link entry of an entered directory
			// (garage/link) is not "under" it, yet Go compiles through it (T-0085).
			if isSkippedPath(rel) && !underEntered(rel, entered) && !overlapsEntered(rel, entered) {
				return nil
			}
			st, serr := os.Stat(p)
			switch {
			case serr != nil:
				out = append(out, Finding{FF: "FF-SP1", Rule: "dangling-symlink", File: rel, Line: 1,
					Msg: "symlink cannot be resolved (" + serr.Error() + "); failing closed because the scan cannot see its target (T-0085)"})
				return nil
			case st.IsDir():
				out = append(out, Finding{FF: "FF-SP1", Rule: "dir-symlink", File: rel, Line: 1,
					Msg: "directory symlinks are rejected: Go compiles the target under this path when imported, while the scan walks by name (T-0085); move the code into the tree"})
				return nil
			}
			// A symlinked file is scanned through the link, as Go compiles it.
			return scanFile(root, rel, module, checks, &out)
		}
		if isSkippedPath(rel) && !underEntered(rel, entered) {
			return nil // a file of a skipped directory that no shipped package reaches
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

// isSkippedPath: rel lies in a directory the walk skips unless shipped code reaches it.
func isSkippedPath(rel string) bool { return inRootSkipped(rel) }

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
		scanGoCheckLinkname(rel, src, checks, out)
	case isNativeSource(rel):
		scanNative(rel, checks, out)
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

// nativeExts are the non-Go source files the go tool compiles into a package: assembly, C, C++,
// Objective-C, Fortran, SWIG and prebuilt objects (.syso). Matching is case-insensitive, so .s, .S and
// .sx (cgo assembly, as go/build treats it) are covered.
var nativeExts = map[string]bool{".s": true, ".sx": true, ".c": true, ".h": true, ".syso": true, ".cc": true, ".cpp": true,
	".cxx": true, ".hh": true, ".hpp": true, ".hxx": true, ".m": true, ".mm": true, ".f": true, ".f90": true,
	".for": true, ".swig": true, ".swigcxx": true}

// nativeHomes are the directories allowed to hold native source. Empty on purpose: adding one is a
// reviewed change with an ADR (T-0215).
var nativeHomes = []string{}

func isNativeSource(rel string) bool { return nativeExts[strings.ToLower(filepath.Ext(rel))] }

// scanNative flags assembly, C and objects in product code: assembly can reference any symbol by
// name with no unsafe import or linkname (evading the symbol bans), and C and .syso objects leave
// Go's memory safety entirely (T-0215). Tier L (tools, lab) is exempt: it does not ship.
func scanNative(rel string, checks Checks, out *[]Finding) {
	if !checks["FF-SP2"] || policy.IsToolTier(rel) || policy.MatchAny(policy.DirOf(rel), nativeHomes) {
		return
	}
	*out = append(*out, Finding{FF: "FF-SP2", Rule: "asm-cgo", File: rel, Line: 1,
		Msg: "native source (" + filepath.Ext(rel) + ") is banned in product code: assembly and cgo escape the symbol and memory-safety bans and are not scanned (T-0215)"})
}
