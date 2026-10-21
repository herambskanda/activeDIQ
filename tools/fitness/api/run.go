package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Report is one run: the status table, the violations, and the count of inactive checks.
type Report struct {
	Lines      []string
	Violations []Violation
	active     int
	inactive   int
}

// Summary is the last stdout line. It names the inactive checks every time, so a green run cannot
// be read as "the contract is fully checked".
func (r *Report) Summary() string {
	if r.inactive == 0 {
		return fmt.Sprintf("fitness-api: %d of 14 checks active, none inactive", r.active)
	}
	return fmt.Sprintf("fitness-api: %d of 14 checks active, %d INACTIVE: ADR-0004 stays ratified, not accepted, until none is", r.active, r.inactive)
}

// Run loads the tree and runs the active checks named in sel (all when nil).
func Run(root string, sel map[string]bool) (*Report, error) {
	t, err := load(root)
	if err != nil {
		return nil, err
	}
	rep := &Report{}
	for _, c := range checks {
		ran := c.run != nil && (sel == nil || sel[c.ID])
		if c.run == nil {
			rep.inactive++
		} else {
			rep.active++
		}
		rep.Lines = append(rep.Lines, c.statusLine(root, t, ran || c.run == nil))
		if ran {
			rep.Violations = append(rep.Violations, c.run(t)...)
		}
	}
	if sel == nil || sel["A1"] || sel["A13"] {
		rep.Violations = append(rep.Violations, selfTest(t)...)
	}
	sort.SliceStable(rep.Violations, func(i, j int) bool {
		if rep.Violations[i].Pos != rep.Violations[j].Pos {
			return rep.Violations[i].Pos < rep.Violations[j].Pos
		}
		return rep.Violations[i].Msg < rep.Violations[j].Msg
	})
	return rep, nil
}

var policyEntryRe = regexp.MustCompile(`(?m)^( {0,2})-(\s|$)`)

// selfTest is the M12-style guard: a check that finds nothing where the tree has something fails
// instead of passing. It compares what the checks saw with facts gathered another way (a plain
// text count, and the committed bundle), so a loader that silently skips files, a renamed key or a
// parser that stops matching turns the job red instead of green.
func selfTest(t *tree) []Violation {
	var vs []Violation
	fail := func(pos, format string, a ...any) {
		vs = append(vs, Violation{"self-test", pos, fmt.Sprintf(format, a...)})
	}
	tagFiles := 0
	for _, f := range t.files {
		if f.kind == "module" || f.kind == "platform" {
			tagFiles++
		}
	}
	if t.byRel["openapi.yaml"] == nil || len(t.files) == 0 {
		fail(specDir, "A1 found no root document and %d file(s): it cannot be checking the contract", len(t.files))
	}
	if len(t.ops) != t.rawOpIDs {
		fail(specDir, "A1 read %d operation(s) from the tag files but a plain text count finds %d operationId line(s): the parser is missing operations, so its passes mean nothing", len(t.ops), t.rawOpIDs)
	}
	if t.bundleOps > 0 && len(t.ops) == 0 {
		fail(specDir, "the committed bundle holds %d operation(s) but A1 found 0 in %d tag file(s): the sources were not read (or the bundle is stale: run make gen-api)", t.bundleOps, tagFiles)
	}
	if t.bundleOps > 0 && tagFiles == 0 {
		fail(specDir, "the committed bundle holds %d operation(s) but A1 found 0 module or platform files", t.bundleOps)
	}

	if pf := t.byRel["policy.yaml"]; pf != nil && pf.doc != nil {
		entries := 0
		for _, s := range policySections {
			if l := get(pf.doc, s.name); l != nil {
				entries += len(l.Content)
			}
		}
		if len(t.anRows) == 0 {
			fail("knowledge/development/architecture/threat-model.md", "A13 read no AN-n rows from the threat model's anonymous allow-list: it cannot check anonymous references (is the table missing or renamed?)")
		}
		raw := len(policyEntryRe.FindAllString(stripComments(pf.text), -1))
		if entries != raw {
			fail(pf.pos, "A13 read %d entr(ies) but a plain text count finds %d list item(s): an entry sits where the check does not look (a renamed section, or a section that is not a list)", entries, raw)
		}
	}
	return vs
}

func stripComments(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}
