package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// goFiles lists the non-test Go files under the given repository directories (slash paths).
func goFiles(root string, dirs ...string) []string {
	var out []string
	for _, d := range dirs {
		_ = filepath.WalkDir(filepath.Join(root, d), func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				if e.Name() == "testdata" || e.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				rel, _ := filepath.Rel(root, p)
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

// goHTTPStatusWrites reports http.Error and WriteHeader calls in internal/** outside apihost
// (ADR-0004 rule 8: only apihost writes status codes; A11).
func goHTTPStatusWrites(root string) []Violation {
	var vs []Violation
	fset := token.NewFileSet()
	for _, rel := range goFiles(root, "internal") {
		if strings.HasPrefix(rel, "internal/platform/apihost/") || isStatusFake(rel) {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, parser.SkipObjectResolution)
		if err != nil {
			vs = append(vs, Violation{"A11", rel, "cannot parse, so http.Error and WriteHeader cannot be ruled out: " + err.Error()})
			continue
		}
		httpName := importName(f, "net/http")
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pos := fset.Position(c.Pos())
			where := fmt.Sprintf("%s:%d", rel, pos.Line)
			if id, ok := sel.X.(*ast.Ident); ok && httpName != "" && id.Name == httpName && sel.Sel.Name == "Error" {
				vs = append(vs, Violation{"A11", where, "http.Error in internal/** outside apihost: only apihost writes errors, a handler returns an apitypes problem constructor (ADR-0004 rule 8)"})
			}
			if sel.Sel.Name == "WriteHeader" && len(c.Args) == 1 {
				vs = append(vs, Violation{"A11", where, "WriteHeader in internal/** outside apihost: only apihost writes status codes (ADR-0004 rule 8)"})
			}
			return true
		})
	}
	return vs
}

// statusFakeDirs are in-process fakes of EXTERNAL services (not shipped; tests import them). They
// must emit the status codes the real service emits, which is not an activeDIQ API response, so
// ADR-0004 rule 8 (only apihost writes our API's statuses) does not apply. Keep this list explicit.
//
// internal/platform/opsmetrics/ is the operator /metrics endpoint (T-0533) on its own ops listener:
// it is not part of the OpenAPI document and not an API response (a Prometheus scrape target with a
// bearer credential and plain-text bodies), so there is no problem+json contract for it to meet.
var statusFakeDirs = []string{"internal/connector/graph/graphtest/", "internal/platform/opsmetrics/"}

func isStatusFake(rel string) bool {
	for _, d := range statusFakeDirs {
		if strings.HasPrefix(rel, d) {
			return true
		}
	}
	return false
}

// importName is the local name a file gives an import path ("" when not imported).
func importName(f *ast.File, path string) string {
	for _, im := range f.Imports {
		if strings.Trim(im.Path.Value, "\"`") != path {
			continue
		}
		if im.Name != nil {
			return im.Name.Name
		}
		return filepath.Base(path)
	}
	return ""
}

var bannedJSONOptions = map[string]bool{"AllowInvalidUTF8": true, "AllowDuplicateNames": true, "MatchCaseInsensitiveNames": true}

// jsonV1Baseline reads tools/fitness/api/json-v1-baseline.txt: the files that imported encoding/json
// when A7 went active. The list may only shrink: a file that no longer imports v1 must be removed
// from it, and a new file is never added.
func jsonV1Baseline(root string) (map[string]string, []Violation) {
	out := map[string]string{}
	p := filepath.Join(root, "tools", "fitness", "api", "json-v1-baseline.txt")
	b, err := os.ReadFile(p)
	if err != nil {
		return out, nil
	}
	for i, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		out[f[0]] = fmt.Sprintf("tools/fitness/api/json-v1-baseline.txt:%d", i+1)
	}
	return out, nil
}

const baselinePath = "tools/fitness/api/json-v1-baseline.txt"

// baseBaseline is the seam for the baseline as it stands on main: (entries, checked, error). Outside
// a git repository there is no main, so checked is false; inside one, an unresolvable main is an
// error, never a pass.
var baseBaseline = gitBaseBaseline

func gitBaseBaseline(root string) (map[string]bool, bool, error) {
	if !isGitRepo(root) {
		return nil, false, nil
	}
	if err := exec.Command("git", "-C", root, "rev-parse", "--verify", "--quiet", "main^{commit}").Run(); err != nil {
		return nil, true, fmt.Errorf("cannot resolve git ref \"main\": the v1 baseline cannot be checked for growth (a shallow clone needs `git fetch origin main`)")
	}
	out := map[string]bool{}
	b, err := exec.Command("git", "-C", root, "show", "main:"+baselinePath).Output()
	if err != nil {
		return nil, false, nil // main has no baseline file yet (the change that introduces it): nothing to compare
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out[strings.Fields(l)[0]] = true
		}
	}
	return out, true, nil
}

var goexperimentRe = regexp.MustCompile(`GOEXPERIMENT[^\n]*nojsonv2`)

// buildFileNames are the files a GOEXPERIMENT value can reach the build through.
func isBuildFile(name string) bool {
	switch {
	case name == "Makefile", name == "GNUmakefile", name == "go.env", name == ".envrc":
		return true
	case strings.HasPrefix(name, "Dockerfile"), strings.HasPrefix(name, "Containerfile"), strings.HasPrefix(name, ".env"):
		return true
	}
	for _, ext := range []string{".mk", ".sh", ".env", ".yml", ".yaml", ".toml", ".service", ".ps1", ".cmd", ".bat"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// goStaticJSON is the static half of A7 (rule 7): no encoding/json (v1) import in internal/** or
// cmd/** beyond the shrinking baseline, no banned v2 option outside tests, and no GOEXPERIMENT
// containing nojsonv2 in any build file.
func goStaticJSON(root string) []Violation {
	var vs []Violation
	add := func(pos, f string, a ...any) { vs = append(vs, Violation{"A7", pos, fmt.Sprintf(f, a...)}) }
	baseline, _ := jsonV1Baseline(root)
	fset := token.NewFileSet()
	importing := map[string]bool{}
	for _, rel := range goFiles(root, "internal", "cmd") {
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, parser.SkipObjectResolution)
		if err != nil {
			add(rel, "cannot parse, so the v1 ban cannot be checked: %v", err)
			continue
		}
		for _, im := range f.Imports {
			if strings.Trim(im.Path.Value, "\"`") == "encoding/json" {
				importing[rel] = true
				if _, ok := baseline[rel]; !ok {
					add(fmt.Sprintf("%s:%d", rel, fset.Position(im.Pos()).Line), "imports encoding/json (v1): product code uses encoding/json/v2, which rejects invalid UTF-8 and duplicate names by default (ADR-0004 rule 7; lessons.md 2026-10-02)")
				}
			}
		}
		jsonNames := map[string]bool{}
		for _, p := range []string{"encoding/json/v2", "encoding/json/jsontext", "github.com/go-json-experiment/json", "github.com/go-json-experiment/json/jsontext"} {
			if n := importName(f, p); n != "" {
				jsonNames[n] = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && jsonNames[id.Name] && bannedJSONOptions[sel.Sel.Name] {
				add(fmt.Sprintf("%s:%d", rel, fset.Position(sel.Pos()).Line), "uses %s.%s: the strict decode options are never relaxed in product code (ADR-0004 rule 7)", id.Name, sel.Sel.Name)
			}
			return true
		})
	}
	mainSet, checked, err := baseBaseline(root)
	if err != nil {
		add(baselinePath, "%v", err)
	}
	for rel, pos := range baseline {
		if checked && err == nil && !mainSet[rel] {
			add(pos, "%s is in the baseline but not in the baseline on main: the list may only shrink, so a new importer is fixed, not listed (ADR-0004 rule 7)", rel)
		}
		if !importing[rel] {
			add(pos, "%s no longer imports encoding/json (or no longer exists): remove it from the baseline, which may only shrink (ADR-0004 rule 7)", rel)
		}
	}

	skip := map[string]bool{".git": true, "node_modules": true, "knowledge": true, "testdata": true, "vendor": true, "dist": true}
	_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			if skip[e.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !isBuildFile(e.Name()) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil || len(b) > 4<<20 {
			return nil
		}
		for i, l := range strings.Split(string(b), "\n") {
			if goexperimentRe.MatchString(l) && !strings.HasPrefix(strings.TrimSpace(l), "#") {
				rel, _ := filepath.Rel(root, p)
				add(fmt.Sprintf("%s:%d", filepath.ToSlash(rel), i+1), "GOEXPERIMENT contains nojsonv2: the strict v2 decoder is the only decoder (ADR-0004 rule 7)")
			}
		}
		return nil
	})
	return vs
}
