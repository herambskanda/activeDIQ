package main

import (
	"regexp"
	"strings"
)

// finding is one rule broken inside a piece of SQL text. Line is relative to the lexed text.
type finding struct {
	Check, Rule string
	Line        int
	Msg         string
}

// sqlScope says which SE2 bans apply to a piece of SQL.
type sqlScope int

const (
	scopeRepo     sqlScope = iota // trigram operators and functions, SET pg_trgm, set_config
	scopeSearch                   // plus LIKE, ILIKE, SIMILAR TO and regular expressions (inventory, modules/search)
	scopeTemplate                 // the reportsql search template: trigram use is its job, patterns are still banned
)

// trigramOps are the pg_trgm operators ADR-0011 SE2 allows only in the reportsql search template.
var trigramOps = map[string]bool{
	"%": true, "<%": true, "%>": true, "<<%": true, "%>>": true,
	"<->": true, "<<->": true, "<->>": true, "<<<->": true, "<->>>": true,
}

// trigramFuncs are the pg_trgm functions with the same restriction.
var trigramFuncs = map[string]bool{
	"similarity": true, "word_similarity": true, "strict_word_similarity": true,
	"show_trgm": true, "set_limit": true, "show_limit": true,
}

// Names of the tables the rules protect.
const keyTable = "inventory_search_keys"

var rbacTables = []string{"authz_assignments", "authz_assignment_roots", "authz_roles", "authz_role_permissions"}

// sqlOpts carries what the caller knows about where the text came from.
type sqlOpts struct {
	scope sqlScope
	// format is true for text that is a printf format string (tools only): a % there is a verb.
	format bool
	// trgmSetting is true where set_config('pg_trgm.…', $n, true) may appear (the search transaction).
	trgmSetting bool
	// showTrgm is true for the two migration statements that may call show_trgm( outside the template: the
	// body of inventory_search_trigrams_sync and the INSERT that backfills the postings (ADR-0011 SE2).
	showTrgm bool
}

// checkSE2 applies the SE2 bans to one statement.
func checkSE2(stmt []tok, o sqlOpts) []finding {
	var out []finding
	add := func(rule string, line int, msg string) { out = append(out, finding{"SE2", rule, line, msg}) }
	seenSet := false
	for i, t := range stmt {
		switch t.kind {
		case tOp:
			if t.text == "%" && i+1 < len(stmt) && (stmt[i+1].word("rowtype") || stmt[i+1].word("type")) {
				continue // plpgsql: table%ROWTYPE, column%TYPE
			}
			if t.text == "%" && o.format {
				continue
			}
			if trigramOps[t.text] && o.scope != scopeTemplate {
				add("trigram-operator", t.line, "the trigram operator "+t.text+" appears outside the reportsql search template: the template is the one place a fuzzy match is written (ADR-0011 SE2)")
			}
			if strings.Contains(t.text, "~") && o.scope != scopeRepo {
				add("pattern-operator", t.line, "the pattern operator "+t.text+" in search SQL: search matches by equality, range and the trigram operator, never by a LIKE or regular-expression pattern (ADR-0011 SE2)")
			}
		case tWord:
			next := tok{}
			if i+1 < len(stmt) {
				next = stmt[i+1]
			}
			if t.text == "set" {
				seenSet = true
			}
			if next.is(tPunct, "(") && trigramFuncs[t.text] && o.scope != scopeTemplate && !(t.text == "show_trgm" && o.showTrgm) {
				add("trigram-function", t.line, t.text+"( appears outside the reportsql search template (ADR-0011 SE2)")
			}
			if o.scope != scopeRepo {
				switch {
				case t.text == "like" || t.text == "ilike":
					add("pattern", t.line, strings.ToUpper(t.text)+" in search SQL: no LIKE, ILIKE, SIMILAR TO or regular expression (ADR-0011 SE2)")
				case t.text == "similar" && next.word("to"):
					add("pattern", t.line, "SIMILAR TO in search SQL: no LIKE, ILIKE, SIMILAR TO or regular expression (ADR-0011 SE2)")
				case strings.HasPrefix(t.text, "regexp_") || t.text == "similar_to_escape":
					add("pattern", t.line, t.text+" in search SQL: no regular expression (ADR-0011 SE2)")
				}
			}
			if t.text == "pg_trgm" && next.is(tPunct, ".") && seenSet {
				add("set-pg_trgm", t.line, "SET of a pg_trgm.* setting: the only way to set one is set_config('pg_trgm.…', $n, true) in the search transaction (ADR-0011 SE2)")
			}
			if t.text == "set_config" && next.is(tPunct, "(") {
				out = append(out, checkSetConfig(stmt[i+1:], o)...)
			}
		}
	}
	return out
}

// checkSetConfig judges one set_config( call; toks starts at its opening parenthesis.
func checkSetConfig(toks []tok, o sqlOpts) []finding {
	var args [][]tok
	depth := 0
	var cur []tok
	line := toks[0].line
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
				args = append(args, cur)
				break loop
			}
		case t.is(tPunct, ",") && depth == 1:
			args = append(args, cur)
			cur = nil
			continue
		}
		cur = append(cur, t)
	}
	var out []finding
	add := func(rule, msg string) { out = append(out, finding{"SE2", rule, line, msg}) }
	if len(args) != 3 || len(args[2]) != 1 || !args[2][0].word("true") {
		add("set-config-persistent", "set_config( without a literal true as its third argument: a setting must be transaction-local, never session-wide (ADR-0011 SE2)")
	}
	if len(args) >= 1 && len(args[0]) == 1 && args[0][0].kind == tStr {
		if strings.HasPrefix(strings.ToLower(args[0][0].text), "pg_trgm.") {
			if !o.trgmSetting {
				add("set-config-pg_trgm", "set_config('pg_trgm.…') outside "+trgmSettingFile+": the search transaction is the one place the threshold is set (ADR-0011 SE2)")
			} else if len(args) < 2 || len(args[1]) != 1 || args[1][0].kind != tParam {
				add("set-config-pg_trgm", "set_config('pg_trgm.…') with a value that is not one bound parameter (ADR-0011 SE2)")
			}
		}
	} else if len(args) >= 1 {
		add("set-config-name", "set_config( with a setting name that is not a string literal: the rules above cannot be judged, so write it as a literal (ADR-0011 SE2)")
	}
	return out
}

// likeBoundParams returns the parameter numbers used as the operand of a LIKE or ILIKE in stmt: the
// first parameter between the keyword and the end of its operand. An operand that holds no parameter is
// a literal pattern and needs no LikePattern.
func likeBoundParams(stmt []tok) []int {
	var out []int
	for i, t := range stmt {
		if !(t.word("like") || t.word("ilike")) {
			continue
		}
		depth := 0
		for j := i + 1; j < len(stmt) && j < i+12; j++ {
			u := stmt[j]
			switch {
			case u.is(tPunct, "("):
				depth++
			case u.is(tPunct, ")"):
				depth--
			}
			if depth < 0 || (depth == 0 && (u.is(tPunct, ",") || u.is(tPunct, ";") || u.kind == tWord && stopWords[u.text])) {
				break
			}
			if u.kind == tParam {
				n := 0
				for _, c := range u.text[1:] {
					n = n*10 + int(c-'0')
				}
				out = append(out, n)
				break
			}
		}
	}
	return out
}

var stopWords = map[string]bool{"and": true, "or": true, "then": true, "else": true, "end": true, "order": true, "limit": true, "escape": true, "group": true, "union": true, "from": true, "where": true, "returning": true}

// endsWithLike reports whether the text ends in LIKE or ILIKE (a fragment that a pattern operand follows).
func endsWithLike(toks []tok) bool {
	return len(toks) > 0 && (toks[len(toks)-1].word("like") || toks[len(toks)-1].word("ilike"))
}

// keyTableReads returns the index of each FROM, JOIN or USING that reads inventory_search_keys in stmt. A
// DELETE FROM is a write.
func keyTableReads(stmt []tok) []int {
	var out []int
	for i := 0; i < len(stmt); i++ {
		t := stmt[i]
		if !(t.word("from") || t.word("join") || t.word("using")) {
			continue
		}
		if t.word("from") && i > 0 && stmt[i-1].word("delete") {
			continue
		}
		j := i + 1
		if j+1 < len(stmt) && stmt[j].kind != tPunct && stmt[j+1].is(tPunct, ".") { // schema.table
			j += 2
		}
		if j < len(stmt) && (stmt[j].kind == tWord || stmt[j].kind == tQuoted) && stmt[j].text == keyTable {
			out = append(out, i)
		}
	}
	return out
}

// backfillProjection reports whether the read at stmt[at] is the named backfill: a subquery or query
// whose select list is only (connection_id, object_guid, norm_version) and that never mentions key.
func backfillProjection(stmt []tok, at int) bool {
	for _, t := range stmt {
		if (t.kind == tWord || t.kind == tQuoted) && t.text == "key" {
			return false
		}
	}
	allowed := map[string]bool{"connection_id": true, "object_guid": true, "norm_version": true}
	depth := 0
	start := -1
	for j := at - 1; j >= 0; j-- {
		switch {
		case stmt[j].is(tPunct, ")"):
			depth++
		case stmt[j].is(tPunct, "("):
			depth--
		case stmt[j].word("select") && depth == 0:
			start = j
		}
		if start >= 0 {
			break
		}
	}
	if start < 0 {
		return false
	}
	cols := 0
	for _, t := range stmt[start+1 : at] {
		switch {
		case t.word("distinct"), t.is(tPunct, ","), t.is(tPunct, "."):
		case t.kind == tWord || t.kind == tQuoted:
			if allowed[t.text] {
				cols++
			} else if !isAlias(t.text) {
				return false
			}
		default:
			return false
		}
	}
	return cols == 3
}

// isAlias accepts a one-or-two-letter table alias used to qualify a column (k.connection_id).
func isAlias(s string) bool { return len(s) > 0 && len(s) <= 2 }

// ---- migrations ----

// rbacTriggerGuards are the trigger functions allowed to name an RBAC table in a migration: each is
// attached to an RBAC table by a trigger of the same migration set (ADR-0011 SE1).
var rbacTriggerGuards = map[string]bool{
	"authz_tier2_guard":             true, // 0018
	"authz_tenant_owner_role_guard": true, // 0034, replaced by 0043
	"authz_control_plane_guard":     true, // 0037, on authz_assignments and authz_role_permissions
}

var definerKinds = map[string]bool{"view": true, "rule": true, "function": true, "procedure": true}

// definition describes a statement that creates a view, rule, function or procedure.
type definition struct {
	kind, name string
	trigger    bool // a function that RETURNS trigger
}

// definitionOf returns the object a statement defines, if it is one that SE1 restricts. A DO block that
// holds such a statement counts as defining one.
func definitionOf(stmt []tok) (definition, bool) {
	if len(stmt) == 0 {
		return definition{}, false
	}
	if stmt[0].word("do") {
		for i := 0; i+1 < len(stmt); i++ {
			if stmt[i].word("create") {
				for j := i + 1; j < len(stmt) && j < i+6; j++ {
					if definerKinds[stmt[j].text] && stmt[j].kind == tWord {
						return definition{kind: "do " + stmt[j].text}, true
					}
				}
			}
		}
		return definition{}, false
	}
	if !stmt[0].word("create") {
		return definition{}, false
	}
	for j := 1; j < len(stmt) && j < 7; j++ {
		if stmt[j].kind == tWord && definerKinds[stmt[j].text] {
			d := definition{kind: stmt[j].text}
			k := j + 1
			var name string
			for k < len(stmt) && (stmt[k].kind == tWord || stmt[k].kind == tQuoted || stmt[k].is(tPunct, ".")) {
				if stmt[k].kind != tPunct {
					name = stmt[k].text
				}
				if k+1 < len(stmt) && stmt[k+1].is(tPunct, ".") {
					k += 2
					continue
				}
				break
			}
			d.name = name
			for m := k; m+1 < len(stmt); m++ {
				if stmt[m].word("returns") && stmt[m+1].word("trigger") {
					d.trigger = true
				}
			}
			return d, true
		}
	}
	return definition{}, false
}

// triggerAttachments maps a function name to true when some CREATE TRIGGER ... ON <rbac table> executes it.
func triggerAttachments(stmts [][]tok) map[string]bool {
	out := map[string]bool{}
	for _, s := range stmts {
		if len(s) == 0 || !s[0].word("create") {
			continue
		}
		trig := false
		for j := 1; j < len(s) && j < 5; j++ {
			trig = trig || s[j].word("trigger")
		}
		if !trig {
			continue
		}
		onRBAC := false
		for j := 0; j+1 < len(s); j++ {
			if s[j].word("on") {
				k := j + 1
				if k+2 < len(s) && s[k+1].is(tPunct, ".") {
					k += 2
				}
				for _, t := range rbacTables {
					if s[k].text == t {
						onRBAC = true
					}
				}
			}
		}
		if !onRBAC {
			continue
		}
		for j := 0; j+1 < len(s); j++ {
			if s[j].word("execute") && (s[j+1].word("function") || s[j+1].word("procedure")) {
				k := j + 2
				name := ""
				for k < len(s) && (s[k].kind == tWord || s[k].kind == tQuoted || s[k].is(tPunct, ".")) {
					if s[k].kind != tPunct {
						name = s[k].text
					}
					k++
				}
				out[name] = true
			}
		}
	}
	return out
}

// namesInside reports whether the statement mentions name as an identifier or as a whole word inside a
// string literal (a function body may build its SQL with format()).
func namesInside(stmt []tok, name string) (int, bool) {
	re := regexp.MustCompile(`(?i)(^|[^a-z0-9_])` + regexp.QuoteMeta(name) + `([^a-z0-9_]|$)`)
	for _, t := range stmt {
		switch t.kind {
		case tWord, tQuoted:
			if t.text == name {
				return t.line, true
			}
		case tStr:
			if re.MatchString(t.text) {
				return t.line, true
			}
		}
	}
	return 0, false
}

// checkMigration applies the SE1 and SE2 rules to the statements of one migration. attached comes from
// triggerAttachments over every migration.
func checkMigration(stmts [][]tok, attached map[string]bool, extraRBAC []string) []finding {
	var out []finding
	rbac := append(append([]string{}, rbacTables...), extraRBAC...)
	for _, s := range stmts {
		d, ok := definitionOf(s)
		if !ok {
			continue
		}
		for _, tbl := range rbac {
			line, names := namesInside(s, tbl)
			if !names {
				continue
			}
			switch {
			case d.kind == "function" && d.trigger && rbacTriggerGuards[d.name] && attached[d.name]:
				// a listed guard, attached to an RBAC table
			case d.kind == "function" && d.trigger && rbacTriggerGuards[d.name]:
				out = append(out, finding{"SE1", "rbac-guard-detached", line, "trigger function " + d.name + " names " + tbl + " but no CREATE TRIGGER on an RBAC table executes it: only a guard attached to an RBAC table may name one (ADR-0011 SE1)"})
			default:
				out = append(out, finding{"SE1", "rbac-derived-object", line, d.kind + " " + d.name + " names " + tbl + ": a migration may create, alter, index, police and grant on the RBAC tables, but defines no view, materialised view, rule or non-trigger function or procedure over them; the listed trigger guards are " + joinKeys(rbacTriggerGuards) + " (ADR-0011 SE1)"})
			}
			break
		}
		for _, tbl := range []string{keyTable, postingTable} {
			if line, names := namesInside(s, tbl); names {
				if tbl == postingTable && d.kind == "function" && d.name == syncFunc {
					continue // the one listed function; checkSearchTables judges its shape
				}
				out = append(out, finding{"SE1", "key-table-derived-object", line, d.kind + " " + d.name + " names " + tbl + ": no migration defines a view or function over the search key or trigram table; only the reportsql search template reads them, and " + syncFunc + " is the one listed trigger function (ADR-0011 SE1)"})
			}
		}
	}
	return out
}

func joinKeys(m map[string]bool) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sortStrings(ks)
	return strings.Join(ks, ", ")
}
