package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// O4 (ADR-0005 rule 3, state machine), the SQL half. SQL that updates the state column of the
// operation tables (operations, operation_items, operation_steps) may appear only in
// internal/platform/operation/persist.go, where the transition functions live. The table-versus-ADR
// half is TestTableMatchesADR in internal/platform/operation (go test ./...), and the random-walk
// property test is transitions_test.go.

var stateUpdate = regexp.MustCompile(`(?is)\bupdate\s+(?:public\.)?operation(?:s|_items|_steps)\b\s+set\s+(.*?)(?:\bwhere\b|\breturning\b|$)`)
var stateAssign = regexp.MustCompile(`(?i)(^|[\s,])state\s*=`)

const transitionFile = "internal/platform/operation/persist.go"

// CheckO4 returns the O4 violations under root.
func CheckO4(root string) ([]Violation, error) {
	var out []Violation
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == transitionFile {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, m := range stateUpdate.FindAllStringSubmatch(s, -1) {
				if stateAssign.MatchString(m[1]) {
					out = append(out, Violation{Check: "O4", Pos: fmt.Sprintf("%s:%d", rel, fset.Position(lit.Pos()).Line),
						Msg: "SQL updates a state column of the operation tables outside the transition functions in " + transitionFile})
					break
				}
			}
			return true
		})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Pos < out[j].Pos })
	return out, err
}
