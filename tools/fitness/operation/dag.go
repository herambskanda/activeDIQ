package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// dagFence opens and closes the block that ADR-0005 rule 13 holds as the source of the kernel
// import DAG.
const (
	dagOpen  = "```dag"
	dagClose = "```"
)

// DAG is the parsed dag block: for each listed package, the listed packages it may import.
// Names are as written in the ADR, relative to internal/platform ("operation/step").
type DAG struct {
	Order []string                   // the packages in the order the block lists them
	Allow map[string]map[string]bool // importer -> allowed imports (the "anything operation may import" rows expanded)
}

var (
	nameRe  = regexp.MustCompile(`^[a-z][a-z0-9]*(/[a-z][a-z0-9]*)*$`)
	macroRe = regexp.MustCompile(`^\(anything ([a-z][a-z0-9/]*) may import\)$`)
)

// ParseDAGFile reads the ADR file and parses its one dag block. It never reads a copy of the block:
// the check follows the ADR.
func ParseDAGFile(file string) (*DAG, error) {
	fh, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var (
		blocks [][]string
		cur    []string
		in     bool
	)
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		switch {
		case !in && strings.TrimSpace(line) == dagOpen:
			in, cur = true, nil
		case in && strings.TrimSpace(line) == dagClose:
			in = false
			blocks = append(blocks, cur)
		case in:
			cur = append(cur, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if in {
		return nil, fmt.Errorf("%s: the %s block is never closed", file, dagOpen)
	}
	switch len(blocks) {
	case 0:
		return nil, fmt.Errorf("%s: no %s block; ADR-0005 rule 13 holds the import DAG there", file, dagOpen)
	case 1:
		return parseDAG(blocks[0])
	}
	return nil, fmt.Errorf("%s: %d %s blocks; the DAG has exactly one source", file, len(blocks), dagOpen)
}

func parseDAG(lines []string) (*DAG, error) {
	type row struct {
		name  string
		items []string
	}
	var rows []row
	seen := map[string]bool{}
	for n, line := range lines {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lhs, rhs, ok := strings.Cut(line, "->")
		if !ok {
			return nil, fmt.Errorf("dag block line %d: %q is not `package -> imports`", n+1, line)
		}
		name := strings.TrimSpace(lhs)
		if !nameRe.MatchString(name) {
			return nil, fmt.Errorf("dag block line %d: %q is not a package name", n+1, name)
		}
		if seen[name] {
			return nil, fmt.Errorf("dag block line %d: %s is listed twice", n+1, name)
		}
		seen[name] = true
		var items []string
		for _, it := range strings.Split(rhs, ",") {
			if it = strings.TrimSpace(it); it != "" {
				items = append(items, it)
			}
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("dag block line %d: %s has no imports; write (none)", n+1, name)
		}
		rows = append(rows, row{name, items})
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("dag block lists no packages")
	}
	d := &DAG{Allow: map[string]map[string]bool{}}
	direct := map[string]map[string]bool{}
	macros := map[string][]string{} // importer -> rows whose allow-list it inherits
	for _, r := range rows {
		d.Order = append(d.Order, r.name)
		set := map[string]bool{}
		direct[r.name] = set
		for _, it := range r.items {
			switch {
			case it == "(none)":
				if len(r.items) != 1 {
					return nil, fmt.Errorf("dag block: %s mixes (none) with other imports", r.name)
				}
			case strings.HasPrefix(it, "("):
				m := macroRe.FindStringSubmatch(it)
				if m == nil {
					return nil, fmt.Errorf("dag block: %s: %q is neither (none) nor (anything <package> may import)", r.name, it)
				}
				macros[r.name] = append(macros[r.name], m[1])
			case nameRe.MatchString(it):
				set[it] = true
			default:
				return nil, fmt.Errorf("dag block: %s: %q is not a package name", r.name, it)
			}
		}
	}
	for _, r := range rows {
		for it := range direct[r.name] {
			if !seen[it] {
				return nil, fmt.Errorf("dag block: %s imports %s, which has no row", r.name, it)
			}
		}
		for _, ref := range macros[r.name] {
			if !seen[ref] {
				return nil, fmt.Errorf("dag block: %s: (anything %s may import) names a package with no row", r.name, ref)
			}
			if len(macros[ref]) > 0 {
				return nil, fmt.Errorf("dag block: %s: (anything %s may import) refers to a row that itself uses a reference", r.name, ref)
			}
		}
	}
	for _, r := range rows {
		allow := map[string]bool{}
		for it := range direct[r.name] {
			allow[it] = true
		}
		for _, ref := range macros[r.name] {
			for it := range direct[ref] {
				allow[it] = true
			}
		}
		d.Allow[r.name] = allow
	}
	return d, nil
}

// allowedList renders what a package may import, for violation messages.
func (d *DAG) allowedList(name string) string {
	var l []string
	for it := range d.Allow[name] {
		l = append(l, it)
	}
	sort.Strings(l)
	if len(l) == 0 {
		return "(none)"
	}
	return strings.Join(l, ", ")
}
