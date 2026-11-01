package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/tools/fitness/internal/boundtest"
)

// Violation is one failed rule. Check is RP2..RP11, Rule names the rule inside the check.
type Violation struct{ Check, Rule, Where, Msg string }

func (v Violation) String() string {
	return fmt.Sprintf("%s %s [%s]: %s", v.Where, v.Check, v.Rule, v.Msg)
}

// Options configures one run.
type Options struct {
	Root       string
	StaticOnly bool
	LockBase   string
	// Runner runs the bound tests; nil means go test. Tests inject recorded output.
	Runner boundtest.Runner
	// Bindings overrides the bound-test table; nil means defaultBindings.
	Bindings []binding
}

// Result is everything a run found. Pending lists parts whose code has not landed. Passed lists
// each check that ran and found nothing, so the CI log itself is the evidence an ADR cites when it
// moves to accepted (ADR-0010 names RP3, RP4 and RP5).
type Result struct {
	Violations []Violation
	Pending    []string
	Notes      []string
	Passed     []string
}

// Run executes every check.
func Run(ctx context.Context, o Options) (*Result, error) {
	res := &Result{}
	ran := []string{"RP2 ReadScope.Terms/.Token and NewReadScope callers", "RP3 reportsql.Compile/CompileCount/Exec callers under internal/modules/reports", "RP7 library/LOCK hashes and append-only history"}
	st, err := checkStatic(o.Root)
	if err != nil {
		return nil, err
	}
	res.Violations = append(res.Violations, st.Violations...)
	res.Pending = append(res.Pending, st.Pending...)

	lv, lp, ln, err := checkLock(o.Root, o.LockBase)
	if err != nil {
		return nil, err
	}
	res.Violations = append(res.Violations, lv...)
	res.Pending = append(res.Pending, lp...)
	res.Notes = append(res.Notes, ln...)

	if !o.StaticOnly {
		bs := o.Bindings
		if bs == nil {
			bs = defaultBindings
		}
		run := o.Runner
		if run == nil {
			run = boundtest.GoTest
		}
		bv, bp, err := runBindings(ctx, o.Root, bs, st.Datasets, run)
		if err != nil {
			return nil, err
		}
		for _, b := range bs {
			if b.Landed {
				where := b.Pkg
				if b.PerDataset {
					where = fmt.Sprintf("%d dataset subtests", len(st.Datasets))
				}
				ran = append(ran, b.Check+" "+b.Name+" ("+where+")")
			}
		}
		res.Violations = append(res.Violations, bv...)
		res.Pending = append(res.Pending, bp...)
	}
	res.Passed = passed(ran, res.Pending, res.Violations)
	sort.SliceStable(res.Violations, func(i, j int) bool {
		a, b := res.Violations[i], res.Violations[j]
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Where < b.Where
	})
	return res, nil
}

// passed keeps each check that ran ("RPn …") with no pending part and no violation.
func passed(ran, pending []string, vs []Violation) []string {
	bad := map[string]bool{}
	for _, p := range pending {
		bad[checkOf(p)] = true
	}
	for _, v := range vs {
		bad[v.Check] = true
	}
	var out []string
	for _, r := range ran {
		if !bad[checkOf(r)] {
			out = append(out, r)
		}
	}
	return out
}

func checkOf(s string) string { c, _, _ := strings.Cut(s, " "); return c }

// relSlash returns p relative to root with forward slashes.
func relSlash(root, p string) string {
	r, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(r)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func under(rel, dir string) bool { return rel == dir || strings.HasPrefix(rel, dir+"/") }
