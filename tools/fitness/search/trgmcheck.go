package main

import (
	"fmt"
	"strings"
)

// The trigram postings (ADR-0011 rule 5a, revision 3) add a second table and one trigger function to the
// search surface. These checks keep them that narrow:
//
//   - SE1: only the reportsql search template reads either table; no Go code writes the postings; the one
//     function over the key table is inventory_search_trigrams_sync, SECURITY INVOKER with a fixed
//     search_path, attached by exactly three statement-level triggers, reading only their transition
//     tables and writing only the postings; every index and unique constraint of both tables leads with
//     tenant_id.
//   - SE2: show_trgm( appears in a migration only in that function and in the statement that backfills the
//     postings; no migration keeps a trigram operator class.

// Names of the posting table and its trigger function.
const (
	postingTable = "inventory_search_trigrams"
	syncFunc     = "inventory_search_trigrams_sync"
)

// syncKinds is the three events the function must be attached to, one trigger each.
var syncKinds = []string{"insert", "delete", "update"}

// migStmts is one migration file's statements.
type migStmts struct {
	rel   string
	stmts [][]tok
}

// located is a finding with the file it was found in.
type located struct {
	file string
	finding
}

// schemaName reads an optionally schema-qualified name starting at toks[i] and returns the bare name and
// the index after it.
func schemaName(toks []tok, i int) (string, int) {
	if i >= len(toks) || !(toks[i].kind == tWord || toks[i].kind == tQuoted) {
		return "", i
	}
	if i+2 < len(toks) && toks[i+1].is(tPunct, ".") && (toks[i+2].kind == tWord || toks[i+2].kind == tQuoted) {
		return toks[i+2].text, i + 3
	}
	return toks[i].text, i + 1
}

// definesFunction reports whether stmt is CREATE [OR REPLACE] FUNCTION name.
func definesFunction(stmt []tok, name string) bool {
	d, ok := definitionOf(stmt)
	return ok && d.kind == "function" && d.name == name
}

// insertsPostings reports whether stmt is an INSERT INTO the posting table: the backfill statement, the
// one place besides the trigger function that has to build trigrams.
func insertsPostings(stmt []tok) bool {
	if len(stmt) < 3 || !stmt[0].word("insert") || !stmt[1].word("into") {
		return false
	}
	n, _ := schemaName(stmt, 2)
	return n == postingTable
}

// trigger describes one CREATE TRIGGER statement.
type trigger struct {
	file     string
	line     int
	table    string
	timing   string
	events   []string
	hasOf    bool
	forRow   bool
	function string
	oldTable string
	newTable string
}

// parseTrigger reads a CREATE [OR REPLACE] [CONSTRAINT] TRIGGER statement.
func parseTrigger(file string, stmt []tok) (trigger, bool) {
	if len(stmt) < 4 || !stmt[0].word("create") {
		return trigger{}, false
	}
	at := -1
	for j := 1; j < len(stmt) && j < 5; j++ {
		if stmt[j].word("trigger") {
			at = j
			break
		}
	}
	if at < 0 {
		return trigger{}, false
	}
	tr := trigger{file: file, line: stmt[0].line}
	j := at + 2 // after the trigger's name
	for ; j < len(stmt) && !stmt[j].word("on"); j++ {
		switch {
		case stmt[j].word("before"), stmt[j].word("after"):
			tr.timing = stmt[j].text
		case stmt[j].word("instead"):
			tr.timing = "instead"
		case stmt[j].word("insert"), stmt[j].word("delete"), stmt[j].word("update"), stmt[j].word("truncate"):
			tr.events = append(tr.events, stmt[j].text)
		case stmt[j].word("of"):
			tr.hasOf = true
		}
	}
	if j >= len(stmt) {
		return trigger{}, false
	}
	tr.table, j = schemaName(stmt, j+1)
	for ; j < len(stmt); j++ {
		switch {
		case stmt[j].word("row") && stmt[j-1].word("each"):
			tr.forRow = true
		case stmt[j].word("table") && j+2 < len(stmt) && stmt[j+1].word("as"):
			if stmt[j-1].word("old") {
				tr.oldTable = stmt[j+2].text
			}
			if stmt[j-1].word("new") {
				tr.newTable = stmt[j+2].text
			}
		case stmt[j].word("execute") && j+1 < len(stmt) && (stmt[j+1].word("function") || stmt[j+1].word("procedure")):
			tr.function, _ = schemaName(stmt, j+2)
		}
	}
	return tr, true
}

// checkSyncFunction judges the definition of the trigger function over the key table. triggers are the
// CREATE TRIGGER statements of the whole migration set that execute it.
func checkSyncFunction(stmt []tok, triggers []trigger) []finding {
	var out []finding
	line := stmt[0].line
	add := func(msg string) {
		out = append(out, finding{"SE1", "trigram-sync-function", line, syncFunc + ": " + msg + " (ADR-0011 SE1, rule 5a)"})
	}
	d, _ := definitionOf(stmt)
	if !d.trigger {
		add("must RETURN trigger")
	}
	invoker, definer := false, false
	for i, t := range stmt {
		if t.word("security") && i+1 < len(stmt) {
			invoker = invoker || stmt[i+1].word("invoker")
			definer = definer || stmt[i+1].word("definer")
		}
	}
	if definer || !invoker {
		add("must be declared SECURITY INVOKER: a definer function runs as its owner")
	}
	if !hasSearchPath(stmt) {
		add("must have SET search_path = pg_catalog, public")
	}
	transition := map[string]bool{}
	for _, tr := range triggers {
		if tr.oldTable != "" {
			transition[tr.oldTable] = true
		}
		if tr.newTable != "" {
			transition[tr.newTable] = true
		}
	}
	for i, t := range stmt {
		if t.word("show_trgm") && !(i >= 1 && stmt[i-1].is(tPunct, ".")) {
			add("calls show_trgm without a schema: write public.show_trgm")
		}
		if t.kind != tWord {
			continue
		}
		write := t.word("update") || (t.word("into") && i > 0 && stmt[i-1].word("insert")) || (t.word("from") && i > 0 && stmt[i-1].word("delete"))
		read := (t.word("from") && !write && !(i > 0 && stmt[i-1].word("distinct"))) || t.word("join") || t.word("using")
		if !write && !read {
			continue
		}
		j := i + 1
		for j < len(stmt) && (stmt[j].word("lateral") || stmt[j].word("only")) {
			j++
		}
		if j >= len(stmt) || stmt[j].is(tPunct, "(") {
			continue // a subquery
		}
		name, after := schemaName(stmt, j)
		if after < len(stmt) && stmt[after].is(tPunct, "(") {
			continue // a function call: unnest(...)
		}
		switch {
		case write && name != postingTable:
			add("writes " + name + ": it may write only " + postingTable)
		case read && name != postingTable && !transition[name]:
			add("reads " + name + ": it may read only the transition tables of its triggers")
		}
	}
	counts := map[string]int{}
	for _, tr := range triggers {
		switch {
		case tr.table != keyTable:
			out = append(out, finding{"SE1", "trigram-sync-trigger", tr.line, syncFunc + " is attached to " + tr.table + ": only " + keyTable + " (ADR-0011 SE1, rule 5a)"})
		case tr.timing != "after" || tr.forRow || tr.hasOf || len(tr.events) != 1:
			out = append(out, finding{"SE1", "trigram-sync-trigger", tr.line, "a trigger of " + syncFunc + " must be AFTER, FOR EACH STATEMENT, one event, and no column list: PostgreSQL gives transition tables to nothing else (ADR-0011 SE1, rule 5a)"})
		default:
			counts[tr.events[0]]++
		}
	}
	for _, ev := range syncKinds {
		if counts[ev] != 1 {
			add(fmt.Sprintf("must be attached to %s by exactly one AFTER %s statement trigger, found %d", keyTable, strings.ToUpper(ev), counts[ev]))
		}
	}
	return out
}

// hasSearchPath reports whether stmt carries SET search_path = pg_catalog, public (or TO).
func hasSearchPath(stmt []tok) bool {
	for i := 0; i+5 < len(stmt); i++ {
		if stmt[i].word("set") && stmt[i+1].word("search_path") && (stmt[i+2].is(tOp, "=") || stmt[i+2].word("to")) &&
			stmt[i+3].word("pg_catalog") && stmt[i+4].is(tPunct, ",") && stmt[i+5].word("public") &&
			!(i+6 < len(stmt) && stmt[i+6].is(tPunct, ",")) {
			return true
		}
	}
	return false
}

// syncTriggers returns every CREATE TRIGGER of the migrations that executes the sync function.
func syncTriggers(migs []migStmts) []trigger {
	var out []trigger
	for _, m := range migs {
		for _, s := range m.stmts {
			if tr, ok := parseTrigger(m.rel, s); ok && tr.function == syncFunc {
				out = append(out, tr)
			}
		}
	}
	return out
}

// index is one index or unique/primary key/exclusion constraint of a table the rules watch.
type index struct {
	file, name, table, first string
	line                     int
	trgmOps                  bool
}

var searchTables = map[string]bool{keyTable: true, postingTable: true}

// droppedNames returns the index and constraint names a DROP INDEX or ALTER TABLE ... DROP CONSTRAINT
// statement removes.
func droppedNames(s []tok) []string {
	var out []string
	from := -1
	switch {
	case len(s) > 1 && s[0].word("drop") && s[1].word("index"):
		from = 2
	case len(s) > 1 && s[0].word("alter") && s[1].word("table"):
		for i := 2; i+1 < len(s); i++ {
			if s[i].word("drop") && s[i+1].word("constraint") {
				from = i + 2
				break
			}
		}
	}
	if from < 0 {
		return nil
	}
	for i := from; i < len(s); i++ {
		if (s[i].kind == tWord || s[i].kind == tQuoted) && !s[i].word("concurrently") && !s[i].word("if") && !s[i].word("exists") && !s[i].word("cascade") && !s[i].word("restrict") {
			if i+1 < len(s) && s[i+1].is(tPunct, ".") {
				continue // the schema
			}
			out = append(out, s[i].text)
		}
	}
	return out
}

// indexesOf collects the indexes and constraints of the key and posting tables across the migrations, in
// order, minus the ones a later statement drops by name.
func indexesOf(migs []migStmts) []index {
	var all []index
	dropped := map[string]bool{}
	for _, m := range migs {
		for _, s := range m.stmts {
			all = append(all, indexesIn(m.rel, s)...)
			for _, n := range droppedNames(s) {
				dropped[n] = true
			}
		}
	}
	var out []index
	for _, ix := range all {
		if !dropped[ix.name] {
			out = append(out, ix)
		}
	}
	return out
}

// firstOf returns the first token inside the parenthesis at toks[i].
func firstOf(toks []tok, i int) string {
	if i+1 < len(toks) && toks[i].is(tPunct, "(") {
		return toks[i+1].text
	}
	return ""
}

func indexesIn(file string, s []tok) []index {
	if len(s) < 3 {
		return nil
	}
	var out []index
	switch {
	case s[0].word("create"):
		j := 1
		for j < len(s) && (s[j].word("unique") || s[j].word("or") || s[j].word("replace")) {
			j++
		}
		switch {
		case j < len(s) && s[j].word("index"):
			j++
			for j < len(s) && (s[j].word("concurrently") || s[j].word("if") || s[j].word("not") || s[j].word("exists")) {
				j++
			}
			name, j := schemaName(s, j)
			for j < len(s) && !s[j].word("on") {
				j++
			}
			if j >= len(s) {
				return nil
			}
			j++
			if j < len(s) && s[j].word("only") {
				j++
			}
			table, j := schemaName(s, j)
			if !searchTables[table] {
				return nil
			}
			for j < len(s) && !s[j].is(tPunct, "(") {
				j++
			}
			ix := index{file: file, name: name, table: table, first: firstOf(s, j), line: s[0].line}
			for _, t := range s {
				ix.trgmOps = ix.trgmOps || t.kind == tWord && strings.HasSuffix(t.text, "_trgm_ops")
			}
			out = append(out, ix)
		case j < len(s) && s[j].word("table"):
			j++
			for j < len(s) && (s[j].word("if") || s[j].word("not") || s[j].word("exists")) {
				j++
			}
			table, j := schemaName(s, j)
			if !searchTables[table] || j >= len(s) || !s[j].is(tPunct, "(") {
				return nil
			}
			out = append(out, tableElements(file, table, s[j:])...)
		}
	case s[0].word("alter") && s[1].word("table"):
		j := 2
		for j < len(s) && (s[j].word("only") || s[j].word("if") || s[j].word("exists")) {
			j++
		}
		table, j := schemaName(s, j)
		if !searchTables[table] {
			return nil
		}
		for k := j; k < len(s); k++ {
			if !s[k].word("add") {
				continue
			}
			rest := s[k+1:]
			name := ""
			if len(rest) > 1 && rest[0].word("constraint") {
				name = rest[1].text
				rest = rest[2:]
			}
			if len(rest) > 0 && rest[0].word("column") {
				rest = rest[1:]
			}
			out = append(out, constraintIn(file, table, name, rest, s[0].line)...)
		}
	}
	return out
}

// constraintIn reads one UNIQUE | PRIMARY KEY | EXCLUDE (...) constraint, or the inline UNIQUE or PRIMARY
// KEY of one ADD COLUMN, from the clause that starts at rest[0].
func constraintIn(file, table, name string, rest []tok, line int) []index {
	end := len(rest)
	depth := 0
	for k, t := range rest { // up to the next top-level comma: the next clause of the same ALTER
		switch {
		case t.is(tPunct, "("):
			depth++
		case t.is(tPunct, ")"):
			depth--
		case t.is(tPunct, ",") && depth == 0:
			end = k
		}
		if end != len(rest) {
			break
		}
	}
	rest = rest[:end]
	for k, t := range rest {
		switch {
		case t.word("unique") || t.word("primary") && k+1 < len(rest) && rest[k+1].word("key"):
			p := k + 1
			if t.word("primary") {
				p = k + 2
			}
			if p < len(rest) && rest[p].is(tPunct, "(") {
				return []index{{file: file, name: name, table: table, first: firstOf(rest, p), line: line}}
			}
			if k > 0 && name == "" { // ADD COLUMN c type UNIQUE: the column itself leads
				return []index{{file: file, name: rest[0].text + "_key", table: table, first: rest[0].text, line: line}}
			}
		case t.word("exclude"):
			for p := k + 1; p < len(rest); p++ {
				if rest[p].is(tPunct, "(") {
					return []index{{file: file, name: name, table: table, first: firstOf(rest, p), line: line}}
				}
			}
		}
	}
	return nil
}

// tableElements reads the primary key, unique and exclusion constraints of a CREATE TABLE body; toks
// starts at its opening parenthesis.
func tableElements(file, table string, toks []tok) []index {
	var elems [][]tok
	depth := 0
	var cur []tok
loop:
	for _, t := range toks {
		switch {
		case t.is(tPunct, "("):
			depth++
			if depth == 1 {
				continue
			}
		case t.is(tPunct, ")"):
			depth--
			if depth == 0 {
				elems = append(elems, cur)
				break loop
			}
		case t.is(tPunct, ",") && depth == 1:
			elems = append(elems, cur)
			cur = nil
			continue
		}
		cur = append(cur, t)
	}
	var out []index
	for _, e := range elems {
		name := ""
		if len(e) > 1 && e[0].word("constraint") {
			name = e[1].text
			e = e[2:]
		}
		if len(e) == 0 {
			continue
		}
		if e[0].word("primary") || e[0].word("unique") || e[0].word("exclude") {
			out = append(out, constraintIn(file, table, name, e, e[0].line)...)
			continue
		}
		// a column definition with an inline PRIMARY KEY or UNIQUE
		d := 0
		for k, t := range e {
			switch {
			case t.is(tPunct, "("):
				d++
			case t.is(tPunct, ")"):
				d--
			case d == 0 && (t.word("unique") || t.word("primary") && k+1 < len(e) && e[k+1].word("key")):
				out = append(out, index{file: file, name: e[0].text + "_key", table: table, first: e[0].text, line: e[0].line})
			}
		}
	}
	return out
}

// checkSearchTables runs the migration-set rules for the key and posting tables.
func checkSearchTables(migs []migStmts) []located {
	var out []located
	for _, ix := range indexesOf(migs) {
		if ix.first != "tenant_id" {
			out = append(out, located{ix.file, finding{"SE1", "index-leads-with-tenant", ix.line,
				fmt.Sprintf("index %q on %s leads with %q: every index and unique constraint on %s and %s leads with tenant_id, or a later index on trgm or key would reopen rule 16 (ADR-0011 SE1)", ix.name, ix.table, ix.first, keyTable, postingTable)}})
		}
		if ix.trgmOps {
			out = append(out, located{ix.file, finding{"SE2", "trigram-opclass", ix.line,
				"index " + ix.name + " uses a trigram operator class and is never dropped: the postings replaced the GIN, and no migration may keep one (ADR-0011 SE2)"}})
		}
	}
	triggers := syncTriggers(migs)
	defined := false
	for _, m := range migs {
		for _, s := range m.stmts {
			if definesFunction(s, syncFunc) {
				defined = true
				for _, f := range checkSyncFunction(s, triggers) {
					out = append(out, located{m.rel, f})
				}
			}
		}
	}
	if !defined {
		for _, tr := range triggers {
			out = append(out, located{tr.file, finding{"SE1", "trigram-sync-trigger", tr.line, "a trigger executes " + syncFunc + ", which no migration defines (ADR-0011 SE1)"}})
		}
	}
	return out
}
