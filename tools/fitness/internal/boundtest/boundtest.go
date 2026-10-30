// Package boundtest runs the Go tests an architecture check is bound to and judges the outcome. A
// bound test that is absent, failed, or skipped (a subtest included) is a violation, so deleting a
// test, renaming it, or letting it skip because a dependency is missing cannot weaken the check.
// It exists so a new fitness job does not carry a private copy of the go test -json reader.
package boundtest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Test is one bound top-level test. Subtests, when set, are the subtest names (the part after the
// first slash) that must each have run and passed under it.
type Test struct {
	Check    string // for example "RP4"
	What     string // what the test proves, shown on failure
	Pkgs     []string
	Name     string
	Subtests []string
}

// Failure is one bound test that did not prove its claim.
type Failure struct{ Check, Kind, Where, Msg string }

func (f Failure) String() string {
	return fmt.Sprintf("%s %s [%s]: %s", f.Where, f.Check, f.Kind, f.Msg)
}

// Runner executes `go test` for the named top-level tests of the packages and returns its -json
// output. The default is GoTest; tests inject recorded output.
type Runner func(ctx context.Context, root string, pkgs []string, names []string) ([]byte, error)

// GoTest runs the tests with go test -json from root.
func GoTest(ctx context.Context, root string, pkgs, names []string) ([]byte, error) {
	args := append([]string{"test", "-count=1", "-json", "-run", "^(" + strings.Join(names, "|") + ")$"}, pkgs...)
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = root
	return cmd.CombinedOutput()
}

type event struct{ Action, Package, Test, Output string }

// outcome is what a run reported for one top-level test.
type outcome struct {
	result  string            // pass, fail or skip of the top-level test; "" if it never finished
	subs    map[string]string // subtest name (after the first slash) -> pass, fail or skip
	skipped bool              // some subtest below it was skipped
}

// Run runs every test (grouped by package set, one go test per group) and returns its failures.
func Run(ctx context.Context, root string, tests []Test, run Runner) ([]Failure, error) {
	groups := map[string][]Test{}
	var keys []string
	for _, t := range tests {
		k := strings.Join(t.Pkgs, " ")
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], t)
	}
	sort.Strings(keys)
	var out []Failure
	for _, k := range keys {
		ts := groups[k]
		var names []string
		for _, t := range ts {
			names = append(names, t.Name)
		}
		raw, err := run(ctx, root, ts[0].Pkgs, names)
		if err != nil && len(raw) == 0 {
			return nil, fmt.Errorf("go test %s: %w", k, err)
		}
		results, build := parse(raw)
		for _, t := range ts {
			out = append(out, judge(t, k, results[t.Name], build)...)
		}
	}
	return out, nil
}

func parse(raw []byte) (map[string]*outcome, string) {
	results := map[string]*outcome{}
	var build strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			build.WriteString(sc.Text() + "\n")
			continue
		}
		if e.Test == "" {
			if e.Action == "output" {
				build.WriteString(e.Output)
			}
			continue
		}
		if e.Action != "pass" && e.Action != "fail" && e.Action != "skip" {
			continue
		}
		top, sub, isSub := strings.Cut(e.Test, "/")
		o := results[top]
		if o == nil {
			o = &outcome{subs: map[string]string{}}
			results[top] = o
		}
		if !isSub {
			o.result = e.Action
			continue
		}
		o.subs[sub] = e.Action
		if e.Action == "skip" {
			o.skipped = true
		}
	}
	return results, build.String()
}

func judge(t Test, group string, o *outcome, build string) []Failure {
	where := group + " " + t.Name
	fail := func(kind, msg string) []Failure {
		return []Failure{{t.Check, kind, where, msg + " " + t.What}}
	}
	if o == nil || o.result == "" {
		msg := "the bound test did not run: it is missing, renamed, or the package does not build."
		if s := strings.TrimSpace(build); s != "" {
			l := strings.Split(s, "\n")
			if len(l) > 6 {
				l = l[:6]
			}
			msg += " go test said: " + strings.Join(l, " | ") + "."
		}
		return fail("test-missing", msg)
	}
	switch o.result {
	case "fail":
		return fail("test-failed", "the bound test failed.")
	case "skip":
		return fail("test-skipped", "the bound test was skipped, so nothing is proven.")
	}
	if o.skipped && len(t.Subtests) == 0 {
		return fail("test-skipped", "a subtest was skipped, so it is not proven.")
	}
	var out []Failure
	for _, s := range t.Subtests {
		switch o.subs[s] {
		case "pass":
		case "":
			out = append(out, Failure{t.Check, "subtest-missing", where + "/" + s, "no subtest named " + s + " ran. " + t.What})
		default:
			out = append(out, Failure{t.Check, "subtest-" + o.subs[s], where + "/" + s, "the subtest did not pass (" + o.subs[s] + "). " + t.What})
		}
	}
	return out
}
