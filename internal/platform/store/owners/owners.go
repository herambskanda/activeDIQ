// Package owners is the table ownership map (ADR-0003 rule 6): which package owns which table.
// It is a data-only leaf that imports nothing, so platform/module can read it without linking the
// store. module.Boot and report.Host check every dataset's tables against it.
//
// The map is meant to be generated from the migrations (`-- write-class:` lines beside each
// table) by tools/gen/modules into owners.gen.go. That generator has not landed (T-0652 covers
// only the agent module list), so the map is empty and Lookup fails closed: a dataset naming any
// table is refused at Boot until its owner appears here. Do not fill it by hand.
package owners

// Lookup returns the owner key of a table, or false when no owner declared it.
func Lookup(table string) (owner string, ok bool) {
	owner, ok = byTable[table]
	return owner, ok
}

// byTable is replaced by the generated owners.gen.go; until then it is empty.
var byTable = map[string]string{}
