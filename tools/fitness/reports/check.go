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

// Result is everything a run found. Pending lists parts whose code has not landed.
type Result struct {
	Violations []Violation
	Pending    []string
	Notes      []string
}

// Run executes every check.
func Run(ctx context.Context, o Options) (*Result, error) {
	res := &Result{}
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
		res.Violations = append(res.Violations, bv...)
		res.Pending = append(res.Pending, bp...)
	}
	sort.SliceStable(res.Violations, func(i, j int) bool {
		a, b := res.Violations[i], res.Violations[j]
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Where < b.Where
	})
	return res, nil
}

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
