package main

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// blueprintPath is where the component catalogue lives, relative to the repository root.
const blueprintPath = "knowledge/development/architecture/blueprint.md"

// catalogueRoots maps a product root to the blueprint §5 section that must catalogue its packages
// (ADR-0003 rule 5, check M7).
var catalogueRoots = []struct{ dir, section string }{
	{"internal/platform", "5.1"},
	{"internal/directory", "5.2"},
	{"internal/connector", "5.3"},
}

var backticked = regexp.MustCompile("`([^`]+)`")

// stripParens removes parenthesised text, nesting included: `store` (+`exempt`) names only store.
func stripParens(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '(':
			depth++
		case r == ')':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// rowNames returns the package names a table row's first column carries: backticked tokens once
// parenthesised text is removed, minus any token containing "/" (a subpackage row).
func rowNames(firstColumn string) []string {
	var names []string
	for _, m := range backticked.FindAllStringSubmatch(stripParens(firstColumn), -1) {
		n := strings.TrimSpace(m[1])
		if n == "" || strings.Contains(n, "/") {
			continue
		}
		names = append(names, n)
	}
	return names
}

// catalogueRows reads blueprint §5.1-§5.3 and returns, per section, how many rows name each package.
// A row naming the same package twice still counts once. A missing blueprint or heading is an error:
// the check fails closed rather than passing because it found nothing to read.
func catalogueRows(root string) (map[string]map[string]int, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(blueprintPath)))
	if err != nil {
		return nil, fmt.Errorf("M7 needs the component catalogue: %w", err)
	}
	rows := map[string]map[string]int{}
	cur := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") {
			cur = ""
			for _, r := range catalogueRoots {
				if strings.HasPrefix(line, "### "+r.section) {
					cur = r.section
					if rows[cur] == nil {
						rows[cur] = map[string]int{}
					}
				}
			}
			continue
		}
		if cur == "" || !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		cells := strings.Split(strings.TrimSpace(line), "|")
		if len(cells) < 2 {
			continue
		}
		seen := map[string]bool{}
		for _, n := range rowNames(cells[1]) {
			if !seen[n] {
				seen[n] = true
				rows[cur][n]++
			}
		}
	}
	for _, r := range catalogueRoots {
		if rows[r.section] == nil {
			return nil, fmt.Errorf("M7: %s has no \"### %s\" section", blueprintPath, r.section)
		}
	}
	return rows, nil
}

// hasGo reports whether dir holds a .go file at any depth.
func hasGo(dir string) (bool, error) {
	found := false
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found, err
}

// checkCatalogue enforces ADR-0003 M7 (closed catalogue): every directory directly under
// internal/platform, internal/directory and internal/connector that holds Go code has exactly one row
// in its own blueprint §5 section. A name in the blueprint with no directory is a planned package and
// is allowed.
func checkCatalogue(root string) ([]Violation, error) {
	rows, err := catalogueRows(root)
	if err != nil {
		return nil, err
	}
	var vs []Violation
	for _, r := range catalogueRoots {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(r.dir)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			ok, err := hasGo(filepath.Join(root, filepath.FromSlash(r.dir), e.Name()))
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			name := e.Name()
			pkg := path.Join(r.dir, name)
			rule := fmt.Sprintf("closed catalogue: %s needs exactly one row in blueprint §%s", pkg, r.section)
			switch n := rows[r.section][name]; {
			case n == 1:
			case n == 0:
				var elsewhere []string
				for _, o := range catalogueRoots {
					if o.section != r.section && rows[o.section][name] > 0 {
						elsewhere = append(elsewhere, "§"+o.section)
					}
				}
				sort.Strings(elsewhere)
				msg := fmt.Sprintf("package %s has no row in blueprint §%s (%s)", pkg, r.section, rule)
				if len(elsewhere) > 0 {
					msg = fmt.Sprintf("package %s is named only in blueprint %s, not in its own §%s (%s)", pkg, strings.Join(elsewhere, ", "), r.section, rule)
				}
				vs = append(vs, Violation{Rule: "M7", Pos: pkg, Msg: msg})
			default:
				vs = append(vs, Violation{Rule: "M7", Pos: pkg, Msg: fmt.Sprintf("package %s has %d rows in blueprint §%s (%s)", pkg, n, r.section, rule)})
			}
		}
	}
	return vs, nil
}
