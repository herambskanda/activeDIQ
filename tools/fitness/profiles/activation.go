package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// requiredActivation are the checks ADR-0002 says cannot run before their subject exists. The
// table must hold a row for each, so deleting a row cannot switch a check off.
var requiredActivation = []string{"P2", "P3", "P4", "P5", "P6", "U3", "U4"}

// Row is the evaluated state of one activation-table row.
type Row struct {
	Activation
	ActivatedBy []string // existing paths that activate it
	Passed      bool     // the check ran and passed
}

// State renders the row for the printed table.
func (r Row) State() string {
	switch {
	case len(r.ActivatedBy) == 0 && len(r.Command) == 0:
		return "pending"
	case len(r.ActivatedBy) == 0:
		return "ready"
	case r.Passed:
		return "active, passing"
	}
	return "ACTIVE, FAILING"
}

// matches lists the existing paths of a pattern. A trailing slash matches directories only.
func (c *Ctx) matches(pat string) []string {
	dirOnly := strings.HasSuffix(pat, "/")
	ms, err := filepath.Glob(filepath.Join(c.Root, filepath.FromSlash(strings.TrimSuffix(pat, "/"))))
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range ms {
		fi, err := os.Stat(m)
		if err != nil || (dirOnly && !fi.IsDir()) {
			continue
		}
		rel, _ := filepath.Rel(c.Root, m)
		out = append(out, filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out
}

// checkActivation evaluates the table: it fails when a required check has no row, when a row has
// no activating path, when a subject exists and its check is not implemented, and when an
// implemented check for an existing subject does not pass.
func (c *Ctx) checkActivation() ([]Row, []Violation) {
	var vs []Violation
	add := func(check, msg string) { vs = append(vs, Violation{"ACT", "activation table " + check, msg}) }
	seen := map[string]bool{}
	var rows []Row
	for _, a := range c.Cfg.Activation {
		if seen[a.Check] {
			add(a.Check, "the check has two rows")
		}
		seen[a.Check] = true
		r := Row{Activation: a}
		if len(a.Paths) == 0 {
			add(a.Check, "the row names no activating path, so the check could never become mandatory")
		}
		for _, p := range a.Paths {
			r.ActivatedBy = append(r.ActivatedBy, c.matches(p)...)
		}
		rows = append(rows, r)
		last := len(rows) - 1
		if len(r.ActivatedBy) == 0 {
			continue
		}
		subject := strings.Join(r.ActivatedBy, ", ")
		if len(a.Command) == 0 {
			add(a.Check, fmt.Sprintf("%s exists, which activates %s (%s), but the check is not implemented: the row has no command. A subject cannot merge without its check; implement %s and register its command in %s", subject, a.Check, a.Subject, a.Check, "tools/fitness/profiles/manifest.json"))
			continue
		}
		if msg := c.commandProblem(a.Command); msg != "" {
			add(a.Check, fmt.Sprintf("%s activates %s, but its command %q cannot run: %s", subject, a.Check, strings.Join(a.Command, " "), msg))
			continue
		}
		cmd := exec.Command(a.Command[0], a.Command[1:]...)
		cmd.Dir = c.Root
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			add(a.Check, fmt.Sprintf("%s activates %s and its check %q fails: %v\n%s", subject, a.Check, strings.Join(a.Command, " "), err, tail(out.String(), 20)))
			continue
		}
		rows[last].Passed = true
	}
	for _, id := range requiredActivation {
		if !seen[id] {
			add(id, "the table has no row for this check; ADR-0002 requires one for each of P2-P6, U3 and U4 so no profile, transport or contract can merge without its check")
		}
	}
	return rows, vs
}

// commandProblem reports why a command cannot be run: an unknown tool, or a local package or
// script argument that does not exist.
func (c *Ctx) commandProblem(argv []string) string {
	if _, err := exec.LookPath(argv[0]); err != nil {
		return "tool " + argv[0] + " not found"
	}
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "./") || strings.HasPrefix(a, "tools/") {
			p := strings.TrimSuffix(strings.TrimSuffix(a, "/..."), "/")
			if _, err := os.Stat(filepath.Join(c.Root, filepath.FromSlash(p))); err != nil {
				return a + " does not exist"
			}
		}
	}
	return ""
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// PrintTable writes the activation table.
func PrintTable(w interface{ Write([]byte) (int, error) }, rows []Row) {
	fmt.Fprintln(w, "fitness-profiles: activation table (a check becomes mandatory the moment its path exists)")
	for _, r := range rows {
		paths := strings.Join(r.Paths, " | ")
		if len(r.ActivatedBy) > 0 {
			paths = "EXISTS: " + strings.Join(r.ActivatedBy, ", ")
		}
		subject := r.Subject
		if len(subject) > 72 {
			subject = subject[:69] + "..."
		}
		fmt.Fprintf(w, "  %-3s %-16s %-52s %s\n", r.Check, r.State(), paths, subject)
	}
}
