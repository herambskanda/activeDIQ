// Package owners is the table ownership map (ADR-0003 rule 6): which package owns which table, and
// the table's write class (ADR-0005 rule 10). It is a data-only leaf that imports nothing, so
// platform/module can read it without linking the store. module.Boot and report.Host check every
// dataset's tables against it.
//
// The map is generated, never written by hand: tools/gen/modules reads the migrations (the owner key
// is the second segment of the migration's file name; the class is the `-- write-class: <table>
// config|system` line beside the CREATE TABLE) and writes owners.gen.tsv. `make gen-modules-check`
// fails the build when the file is stale. A table no migration creates has no owner, so Lookup fails
// closed: a dataset naming it is refused at Boot.
//
// The map is data (owners.gen.tsv, embedded), not Go source, on purpose: it names every table, including
// the ones no other code may name (ADR-0007 P8 and FF-KEY-2 scan Go source for them), and an exemption
// for a generated Go file would be a hole in those scans.
package owners

import (
	_ "embed"
	"fmt"
	"strings"
)

// Class is a table's write class (ADR-0005 rule 10).
type Class string

const (
	// Config tables are changed by a principal, so every write is an Action that takes a step.Step.
	Config Class = "config"
	// System tables are bookkeeping written by their owner (the closed list in ADR-0005 rule 10).
	System Class = "system"
)

type entry struct {
	owner string
	class Class
}

//go:embed owners.gen.tsv
var genTSV string

var byTable = mustParse(genTSV)

// mustParse reads the generated file: `#` comment lines, then `table<TAB>owner<TAB>class`. A malformed
// file is a build defect (gen-modules-check and this package's tests catch it before release), so it
// panics at start-up rather than let a dataset through an incomplete map.
func mustParse(data string) map[string]entry {
	m := map[string]entry{}
	for i, line := range strings.Split(data, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[0] == "" || f[1] == "" || (Class(f[2]) != Config && Class(f[2]) != System) {
			panic(fmt.Sprintf("owners: owners.gen.tsv line %d is malformed (run `make gen-modules`)", i+1))
		}
		if _, dup := m[f[0]]; dup {
			panic(fmt.Sprintf("owners: owners.gen.tsv line %d repeats a table (run `make gen-modules`)", i+1))
		}
		m[f[0]] = entry{owner: f[1], class: Class(f[2])}
	}
	return m
}

// Lookup returns the owner key of a table, or false when no migration creates it.
func Lookup(table string) (owner string, ok bool) {
	e, ok := byTable[table]
	return e.owner, ok
}

// ClassOf returns the write class of a table, or false when no migration creates it.
func ClassOf(table string) (class Class, ok bool) {
	e, ok := byTable[table]
	return e.class, ok
}
