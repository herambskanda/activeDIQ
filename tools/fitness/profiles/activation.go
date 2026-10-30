package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/tools/fitness/internal/adr"
)

// requiredActivation are the checks ADR-0002 says cannot run before their subject exists. The
// table must hold a row for each, so deleting a row cannot switch a check off.
var requiredActivation = []string{"P2-oci", "P2-msi", "P3", "P4", "P5", "P6", "U3", "U4"}

// Row is the evaluated state of one activation-table row.
type Row struct {
	Activation
	ActivatedBy []string // existing paths that activate it
	Passed      bool     // the check ran and passed
	Deferred    bool     // the subject exists, the check does not, and a valid deferral covers the gap
}

// State renders the row for the printed table.
func (r Row) State() string {
	switch {
	case r.Deferred:
		return fmt.Sprintf("ACTIVE, DEFERRED (%s until %s)", r.Deferral.Ticket, r.Deferral.Expires)
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
		dok := true
		if a.Deferral != nil {
			for _, why := range c.deferralProblems(a) {
				add(a.Check, "deferral "+why)
				dok = false
			}
		}
		rows = append(rows, r)
		last := len(rows) - 1
		if len(r.ActivatedBy) == 0 {
			continue
		}
		subject := strings.Join(r.ActivatedBy, ", ")
		if len(a.Command) == 0 && a.Deferral != nil && dok {
			rows[last].Deferred = true
			continue
		}
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
			add(id, "the table has no row for this check; ADR-0002 requires one for each of P2-oci, P2-msi, P3 to P6, U3 and U4 so no profile, transport or contract can merge without its check")
		}
	}
	return rows, vs
}

var ticketRe = regexp.MustCompile(`^T-[0-9]{4,}$`)

// deferralProblems lists why a row's deferral is not valid; nil means it is. A deferral is a
// violation when it expires (UTC date), names a malformed ticket, sits on a row that has a command
// (stale: remove it), or is not listed in the ADR's "Activation deferrals" table.
func (c *Ctx) deferralProblems(a Activation) []string {
	d := a.Deferral
	var out []string
	today := c.Now.UTC().Format("2006-01-02")
	if exp, err := time.Parse("2006-01-02", d.Expires); err != nil || exp.Format("2006-01-02") != d.Expires {
		out = append(out, fmt.Sprintf("expiry %q is not a YYYY-MM-DD date", d.Expires))
	} else if d.Expires < today {
		out = append(out, fmt.Sprintf("expired on %s (today is %s, UTC): implement %s and remove the deferral, or file an amendment line in the ADR with its reason", d.Expires, today, a.Check))
	}
	if !ticketRe.MatchString(d.Ticket) {
		out = append(out, fmt.Sprintf("ticket %q is malformed: want T- followed by four or more digits", d.Ticket))
	}
	if len(a.Command) > 0 {
		out = append(out, "is stale: the row has a command, so the check is implemented; remove the deferral")
	}
	rows, err := c.deferralTable(d.ADR)
	if err != nil {
		return append(out, "cannot be checked against the ADR: "+err.Error())
	}
	for _, r := range rows {
		if r.Check == a.Check && r.Ticket == d.Ticket && r.Expires == d.Expires {
			return out
		}
	}
	return append(out, fmt.Sprintf("(%s, %s, %s) has no row in the \"Activation deferrals\" table of %s: only the ADR approves a deferral, so the manifest cannot grant one alone", a.Check, d.Ticket, d.Expires, d.ADR))
}

// deferralRow is one row of the ADR's "Activation deferrals" table; columns 1 to 3 are machine-read.
type deferralRow struct{ Check, Ticket, Expires string }

const deferralsHeading = "**Activation deferrals**"

// deferralTable parses the table that follows the heading in the ADR file named by the deferral. It
// never reads a copy: like the dag block of fitness-operation, the ADR is the source. The ADR must
// sit in decisionsDir and have a status that can grant an exception.
func (c *Ctx) deferralTable(name string) ([]deferralRow, error) {
	if name == "" || name != filepath.Base(name) || !strings.HasSuffix(name, ".md") {
		return nil, fmt.Errorf("adr %q must be the file name of an ADR in %s", name, c.Cfg.DecisionsDir)
	}
	file := filepath.Join(c.Root, filepath.FromSlash(c.Cfg.DecisionsDir), name)
	st, err := adr.Status(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if !adr.Grants(st) {
		return nil, fmt.Errorf("%s has status %q; a deferral needs a ratified or accepted ADR", name, st)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var rows []deferralRow
	in, header := false, 0
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case !in && strings.HasPrefix(t, deferralsHeading):
			in = true
		case in && strings.HasPrefix(t, "|"):
			header++
			if header <= 2 { // column titles and the separator line
				continue
			}
			cells := strings.Split(strings.Trim(t, "|"), "|")
			if len(cells) < 3 {
				return nil, fmt.Errorf("%s: deferral table row %q has fewer than three columns", name, t)
			}
			rows = append(rows, deferralRow{strings.TrimSpace(cells[0]), strings.TrimSpace(cells[1]), strings.TrimSpace(cells[2])})
		case in && header > 0 && t != "":
			return rows, nil // the table ended
		}
	}
	if !in {
		return nil, fmt.Errorf("%s has no %s heading", name, deferralsHeading)
	}
	return rows, nil
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
		fmt.Fprintf(w, "  %-6s %-42s %-52s %s\n", r.Check, r.State(), paths, subject)
	}
}
