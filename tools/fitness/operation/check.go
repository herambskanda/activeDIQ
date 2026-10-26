// Package main is the fitness-operation job (ADR-0005). It carries O9 (the kernel import DAG of
// rule 13) and O1 (the step token: syntactic part, plus the type-aware stepescape pass). O2-O8 land
// with the code they inspect (Actions, the audit chain).
//
// O9 parses the ```dag block of the ADR file itself, maps each listed name to
// internal/platform/<name>, reads the import statements of every .go file (tests included) of each
// listed package that exists, and fails on any import of another listed package that the block does
// not allow. A listed package that does not exist yet is reported as pending, never as a pass. It
// needs no network and no build; build constraints are ignored, so a file no target compiles is
// still checked.
//
// Only the exact packages the block lists are governed: an import of an unlisted subpackage (for
// example store/exempt) is not an edge here; ADR-0003 and fitness-modules govern those.
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
	"sort"
	"strconv"
	"strings"
)

// DefaultADR is the ADR whose rule 13 holds the DAG, relative to the repository root.
const DefaultADR = "knowledge/development/decisions/0005-operation-pipeline-and-audit-trail.md"

// platformRoot is where a listed name lives: <name> is internal/platform/<name>.
const platformRoot = "internal/platform"

// Violation is one broken rule at one place.
type Violation struct {
	Check string // "O9"
	Pos   string // file:line, relative to the repository root
	Msg   string
}

func (v Violation) String() string {
	switch v.Check {
	case "O1", "O2":
		return fmt.Sprintf("%s: %s [rule 2] %s", v.Pos, v.Check, v.Msg)
	case "O4":
		return fmt.Sprintf("%s: %s [rule 3] %s", v.Pos, v.Check, v.Msg)
	}
	return fmt.Sprintf("%s: %s [rule 13] %s", v.Pos, v.Check, v.Msg)
}

// Pkg is one package the block lists, and whether the tree has it yet.
type Pkg struct {
	Name     string // as written in the block: "operation/step"
	Dir      string // internal/platform/operation/step
	Existing bool   // the directory holds at least one .go file
}

// Report is what one run found.
type Report struct {
	ADR        string
	Pkgs       []Pkg // in the block's order
	Edges      int   // imports among the listed packages that were checked
	Violations []Violation
}

// Check runs O9 on the repository at root against the DAG in the ADR file adr (relative to root,
// or absolute).
func Check(root, adr string) (*Report, error) {
	if !filepath.IsAbs(adr) {
		adr = filepath.Join(root, filepath.FromSlash(adr))
	}
	d, err := ParseDAGFile(adr)
	if err != nil {
		return nil, err
	}
	modPath, err := modulePath(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	rep := &Report{ADR: filepath.ToSlash(adr)}
	if rel, err := filepath.Rel(root, adr); err == nil && !strings.HasPrefix(rel, "..") {
		rep.ADR = filepath.ToSlash(rel)
	}
	byDir := map[string]string{} // import path -> listed name
	for _, name := range d.Order {
		dir := platformRoot + "/" + name
		ok, err := hasGoFiles(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			return nil, err
		}
		rep.Pkgs = append(rep.Pkgs, Pkg{Name: name, Dir: dir, Existing: ok})
		byDir[modPath+"/"+dir] = name
	}
	if err := selfTest(root, rep); err != nil {
		return nil, err
	}
	for _, p := range rep.Pkgs {
		if !p.Existing {
			continue
		}
		imps, err := importsOf(root, p.Dir)
		if err != nil {
			return nil, err
		}
		for _, i := range imps {
			to, listed := byDir[i.path]
			if !listed || to == p.Name {
				continue
			}
			rep.Edges++
			if d.Allow[p.Name][to] {
				continue
			}
			kind := ""
			if i.test {
				kind = " (test file)"
			}
			rep.Violations = append(rep.Violations, Violation{Check: "O9", Pos: i.pos, Msg: fmt.Sprintf(
				"%s imports %s%s; ADR-0005 rule 13 does not allow %s -> %s (%s may import: %s)",
				p.Name, to, kind, p.Name, to, p.Name, d.allowedList(p.Name))})
		}
	}
	sort.Slice(rep.Violations, func(i, j int) bool {
		if rep.Violations[i].Pos != rep.Violations[j].Pos {
			return rep.Violations[i].Pos < rep.Violations[j].Pos
		}
		return rep.Violations[i].Msg < rep.Violations[j].Msg
	})
	return rep, nil
}

// selfTest guards the mapping from names to directories. If no listed package resolves, yet the tree
// holds directories named platform/<listed name> elsewhere, the mapping is wrong and a pass would be
// a pass over nothing: that fails.
func selfTest(root string, rep *Report) error {
	for _, p := range rep.Pkgs {
		if p.Existing {
			return nil
		}
	}
	var found []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if p != root && skipDir(d.Name()) {
			return fs.SkipDir
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		for _, pk := range rep.Pkgs {
			if strings.HasSuffix(rel, "/platform/"+pk.Name) {
				if ok, _ := hasGoFiles(p); ok {
					found = append(found, rel)
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(found) > 0 {
		sort.Strings(found)
		rep.Violations = append(rep.Violations, Violation{Check: "O9", Pos: rep.ADR, Msg: fmt.Sprintf(
			"self-test: none of the %d listed packages resolved under %s, but the tree has %s; the name-to-directory mapping is wrong, so a pass would check nothing",
			len(rep.Pkgs), platformRoot, strings.Join(found, ", "))})
	}
	return nil
}

type imp struct {
	path string // import path as written
	pos  string // file:line relative to the root
	test bool
}

// importsOf lists the imports of every .go file directly in dir (relative to root).
func importsOf(root, dir string) ([]imp, error) {
	abs := filepath.Join(root, filepath.FromSlash(dir))
	ents, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	var out []imp
	fset := token.NewFileSet()
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		rel := path.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, filepath.Join(abs, e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		for _, is := range f.Imports {
			ip, err := strconv.Unquote(is.Path.Value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", rel, err)
			}
			out = append(out, imp{path: ip, pos: fmt.Sprintf("%s:%d", rel, fset.Position(is.Pos()).Line), test: strings.HasSuffix(e.Name(), "_test.go")})
		}
	}
	return out, nil
}

func hasGoFiles(dir string) (bool, error) {
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
			return true, nil
		}
	}
	return false, nil
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "testdata", "vendor", "factory", "knowledge", "garage", ".claude":
		return true
	}
	return false
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
