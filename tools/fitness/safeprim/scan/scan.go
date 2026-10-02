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

// skipDir reports directories that hold no product code. Only names that can never be a product
// package are skipped at any depth (.git, node_modules, the Go testdata convention). Every other
// skip is tied to where that directory really is: repository-level working trees at the root, and
// build output only beside the project file that produces it (bin and obj beside a .csproj, target
// beside Cargo.toml, dist beside package.json). A product package that happens to be called target,
// bin or obj, such as internal/modules/target, is therefore scanned.
func skipDir(root, rel, name string) bool {
	switch name {
	case ".git", "node_modules", "testdata":
		return true
	}
	if !strings.Contains(rel, "/") {
		switch name {
		case "vendor", "factory", "knowledge", "garage", ".claude", "dist", "third_party":
			return true
		}
	}
	parent := filepath.Join(root, filepath.FromSlash(filepath.ToSlash(filepath.Dir(rel))))
	switch name {
	case "bin", "obj":
		return dirHasSuffix(parent, ".csproj", ".fsproj", ".vbproj")
	case "target":
		return dirHasSuffix(parent, "Cargo.toml")
	case "dist":
		return dirHasSuffix(parent, "package.json")
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
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && skipDir(root, rel, d.Name()) {
				return fs.SkipDir
			}
			return nil
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
