package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Violation is one failed rule. Check is FCS-1..6, Rule names the rule inside the check.
type Violation struct{ Check, Rule, Where, Msg string }

func (v Violation) String() string {
	return fmt.Sprintf("%s %s [%s]: %s", v.Where, v.Check, v.Rule, v.Msg)
}

type goFile struct {
	Rel  string
	Test bool
	File *ast.File
	Fset *token.FileSet
}

func (g goFile) where(p token.Pos) string { return g.Rel + ":" + strconv.Itoa(g.Fset.Position(p).Line) }
func (g goFile) in(dir string) bool       { return g.Rel == dir || strings.HasPrefix(g.Rel, dir+"/") }

var skipDirs = map[string]bool{".git": true, "node_modules": true, "testdata": true, "vendor": true, ".activeDIQ-worktrees": true, "web": true, "factory": true, "knowledge": true}

// loadGo parses every Go file under root. A file that does not parse is a hard error: a check never
// passes over code it could not read.
func loadGo(root string) ([]goFile, error) {
	var out []goFile
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, p, b, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		out = append(out, goFile{Rel: rel, Test: strings.HasSuffix(rel, "_test.go"), File: f, Fset: fset})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, err
}
