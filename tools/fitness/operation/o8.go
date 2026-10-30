package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// O8 (ADR-0005 fitness row O8, pipeline behaviour). The behaviour is exercised by the operation
// pipeline integration suite (T-0788: Postgres, the Samba lab, a fake for what Samba cannot emulate).
// Its manifest, internal/platform/operation/o8_manifest_test.go, maps every clause of the row to the
// named tests that pin it. This check reads that manifest (it parses the Go source, so the list is
// never copied here), runs the named tests, and fails when one
//
//   - does not exist (renamed or deleted),
//   - fails, or
//   - is skipped, in whole or in any subtest (a skipped test proves nothing; no Docker is a failure).
//
// A clause the manifest lists as a Gap is printed as pending with the ticket that closes it; that is
// not a pass. Tests that need the Samba lab (files tagged `lab`) must exist, and run under -o8-lab
// (`make lab-up` first); without it they are listed as not run, which is not a pass either.

const o8ManifestFile = "internal/platform/operation/o8_manifest_test.go"

// O8Test is one named test of the manifest, Dir relative to the repository root.
type O8Test struct{ Dir, Name string }

// O8Clause is one clause of the manifest.
type O8Clause struct {
	ID, Rule, Gap string
	Tests         []O8Test
}

// O8Runner runs the named top-level tests of one package directory and returns the `go test -json`
// stream. lab adds `-tags lab`.
type O8Runner func(ctx context.Context, root, dir string, lab bool, tests []string) ([]byte, error)

// O8Report is what a run found besides violations.
type O8Report struct {
	Clauses   int
	Pinned    int      // clauses with at least one test
	Ran       int      // distinct tests run and passed
	Gaps      []string // "<id> <gap>" for the pending line
	LabNotRun []string // lab-only tests that exist but were not run
}

// ReadO8Manifest parses the manifest source under root.
func ReadO8Manifest(root string) ([]O8Clause, error) {
	path := filepath.Join(root, filepath.FromSlash(o8ManifestFile))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("O8 manifest %s: %w", o8ManifestFile, err)
	}
	consts := map[string]string{}
	var lit *ast.CompositeLit
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, sp := range gd.Specs {
			vs, ok := sp.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, n := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				switch gd.Tok {
				case token.CONST:
					if s, ok := strLit(vs.Values[i], consts); ok {
						consts[n.Name] = s
					}
				case token.VAR:
					if n.Name == "o8Manifest" {
						lit, _ = vs.Values[i].(*ast.CompositeLit)
					}
				}
			}
		}
	}
	if lit == nil {
		return nil, fmt.Errorf("O8 manifest %s: no `var o8Manifest = []o8Clause{...}` found", o8ManifestFile)
	}
	var out []O8Clause
	for _, el := range lit.Elts {
		cl, ok := el.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("O8 manifest: an element of o8Manifest is not a composite literal")
		}
		var c O8Clause
		for _, kv := range cl.Elts {
			kve, ok := kv.(*ast.KeyValueExpr)
			if !ok {
				return nil, fmt.Errorf("O8 manifest: clause fields must be keyed")
			}
			key, _ := kve.Key.(*ast.Ident)
			if key == nil {
				continue
			}
			switch key.Name {
			case "ID", "Rule", "Gap":
				s, ok := strLit(kve.Value, consts)
				if !ok {
					return nil, fmt.Errorf("O8 manifest: field %s is not a string constant", key.Name)
				}
				switch key.Name {
				case "ID":
					c.ID = s
				case "Rule":
					c.Rule = s
				default:
					c.Gap = s
				}
			case "Tests":
				tl, ok := kve.Value.(*ast.CompositeLit)
				if !ok {
					return nil, fmt.Errorf("O8 manifest: Tests of %s is not a literal", c.ID)
				}
				for _, te := range tl.Elts {
					tt, ok := te.(*ast.CompositeLit)
					if !ok || len(tt.Elts) != 2 {
						return nil, fmt.Errorf("O8 manifest: a test of %s is not {Dir, Name}", c.ID)
					}
					dir, ok1 := strLit(tt.Elts[0], consts)
					name, ok2 := strLit(tt.Elts[1], consts)
					if !ok1 || !ok2 {
						return nil, fmt.Errorf("O8 manifest: a test of %s has a non-constant Dir or Name", c.ID)
					}
					c.Tests = append(c.Tests, O8Test{dir, name})
				}
			}
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("O8 manifest %s: no clauses", o8ManifestFile)
	}
	return out, nil
}

func strLit(e ast.Expr, consts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.Ident:
		s, ok := consts[v.Name]
		return s, ok
	}
	return "", false
}

var o8GapTicket = regexp.MustCompile(`(^T-\d{4}\b)|(follow-up T-\d{4}\b)`)
var labTag = regexp.MustCompile(`^//go:build\s.*\blab\b`)

// o8Funcs returns, for dir, every top-level Test function declared in a _test.go file, and whether it
// lives in a file tagged `lab`.
func o8Funcs(dir string) (map[string]bool, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		lab := false
		for _, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(line, "package ") {
				break
			}
			if labTag.MatchString(line) {
				lab = true
			}
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, 0)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, d := range af.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				out[fn.Name.Name] = lab
			}
		}
	}
	return out, nil
}

type o8Event struct {
	Action, Package, Test, Output string
}

// CheckO8 reads the manifest under root, runs its tests (lab ones only when lab is set) and returns
// the violations. Errors are for what stops the check from running at all.
func CheckO8(ctx context.Context, root string, lab bool, run O8Runner) ([]Violation, O8Report, error) {
	var rep O8Report
	clauses, err := ReadO8Manifest(root)
	if err != nil {
		return nil, rep, err
	}
	var vs []Violation
	bad := func(pos, msg string) { vs = append(vs, Violation{Check: "O8", Pos: pos, Msg: msg}) }

	funcs := map[string]map[string]bool{}
	type bound struct {
		clause string
		rule   string
	}
	// dir -> lab? -> test -> clauses that bind it
	bind := map[string]map[bool]map[string][]bound{}
	seen := map[string]bool{}
	for _, c := range clauses {
		rep.Clauses++
		where := o8ManifestFile + " " + c.ID
		if seen[c.ID] {
			bad(where, "duplicate clause")
		}
		seen[c.ID] = true
		if (len(c.Tests) == 0) == (c.Gap == "") {
			bad(where, "a clause needs named tests or a Gap, not both and not neither")
			continue
		}
		if c.Gap != "" {
			if !o8GapTicket.MatchString(c.Gap) {
				bad(where, fmt.Sprintf("a Gap must name the ticket that closes it (T-nnnn), got %q", c.Gap))
			}
			rep.Gaps = append(rep.Gaps, c.ID+": "+c.Gap)
			continue
		}
		rep.Pinned++
		for _, tc := range c.Tests {
			fs, ok := funcs[tc.Dir]
			if !ok {
				fs, err = o8Funcs(filepath.Join(root, filepath.FromSlash(tc.Dir)))
				if err != nil {
					return nil, rep, err
				}
				funcs[tc.Dir] = fs
			}
			isLab, exists := fs[tc.Name]
			if !exists {
				bad(tc.Dir+" "+tc.Name, c.ID+": the test the manifest names does not exist (renamed or deleted): "+c.Rule)
				continue
			}
			if bind[tc.Dir] == nil {
				bind[tc.Dir] = map[bool]map[string][]bound{}
			}
			if bind[tc.Dir][isLab] == nil {
				bind[tc.Dir][isLab] = map[string][]bound{}
			}
			bind[tc.Dir][isLab][tc.Name] = append(bind[tc.Dir][isLab][tc.Name], bound{c.ID, c.Rule})
		}
	}

	dirs := make([]string, 0, len(bind))
	for d := range bind {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		for _, isLab := range []bool{false, true} {
			tests := bind[dir][isLab]
			if len(tests) == 0 {
				continue
			}
			names := make([]string, 0, len(tests))
			for n := range tests {
				names = append(names, n)
			}
			sort.Strings(names)
			if isLab && !lab {
				for _, n := range names {
					rep.LabNotRun = append(rep.LabNotRun, dir+" "+n)
				}
				continue
			}
			out, err := run(ctx, root, dir, isLab, names)
			if err != nil && len(out) == 0 {
				return nil, rep, fmt.Errorf("go test %s: %w", dir, err)
			}
			verdict, subSkipped, build := parseO8Stream(out)
			for _, n := range names {
				first := tests[n][0]
				where := dir + " " + n
				ids := make([]string, 0, len(tests[n]))
				for _, b := range tests[n] {
					ids = append(ids, b.clause)
				}
				who := strings.Join(ids, ",") + ": " + first.rule
				switch verdict[n] {
				case "pass":
					if subSkipped[n] {
						bad(where, "a subtest was skipped (no Docker or lab?): the clause is not proven. "+who)
					} else {
						rep.Ran++
					}
				case "fail":
					bad(where, "the test failed. "+who)
				case "skip":
					bad(where, "the test was skipped (no Docker or lab?): a skipped test proves nothing. "+who)
				default:
					msg := "the test did not run: renamed, deleted or the package does not build. " + who
					if build != "" {
						msg += " go test said: " + build
					}
					bad(where, msg)
				}
			}
		}
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].Pos < vs[j].Pos })
	return vs, rep, nil
}

func parseO8Stream(out []byte) (verdict map[string]string, subSkipped map[string]bool, build string) {
	verdict, subSkipped = map[string]string{}, map[string]bool{}
	var b strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e o8Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			b.WriteString(sc.Text() + "\n")
			continue
		}
		if e.Test == "" {
			if e.Action == "output" {
				b.WriteString(e.Output)
			}
			continue
		}
		top, _, sub := strings.Cut(e.Test, "/")
		switch e.Action {
		case "pass", "fail", "skip":
			if !sub {
				verdict[top] = e.Action
			} else if e.Action == "skip" {
				subSkipped[top] = true
			}
		}
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) > 6 {
		lines = lines[:6]
	}
	return verdict, subSkipped, strings.TrimSpace(strings.Join(lines, " | "))
}

// GoTestRunner runs the named tests with `go test -json -count=1` (-count=1: a cached pass was not a
// run against today's database image).
func GoTestRunner(ctx context.Context, root, dir string, lab bool, tests []string) ([]byte, error) {
	args := []string{"test", "-json", "-count=1"}
	if lab {
		args = append(args, "-tags", "lab")
	}
	args = append(args, "-run", "^("+strings.Join(tests, "|")+")$", "./"+dir)
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = root
	return cmd.Output()
}
