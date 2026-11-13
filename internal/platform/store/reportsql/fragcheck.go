package reportsql

import (
	"fmt"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

// A fragment is constant SQL that a dataset author writes, so the registry decides what it may say
// by allowlist (contract §3.3): a word is refused unless it is listed here. The check exists to
// keep a fragment from reading a table outside {rel.<id>}, because such a read skips the per-row
// scope. A denylist cannot do that: query_to_xml('select … from t'), table_to_xml, xpath, ts_stat,
// to_regclass and information_schema.* all read data with no word the old list named.
//
// Adding a word is a reviewed change to this file and a test. Nothing here can read a table, call
// a function with side effects, or reach the clock: `now` comes only through {now}.

// fragKeywords may stand alone or open a parenthesis. They shape an expression; none of them names
// a table, a function or a schema.
var fragKeywords = wordSet(
	"case", "when", "then", "else", "end",
	"and", "or", "not", "is", "null", "true", "false", "unknown",
	"in", "between", "like", "ilike", "distinct",
	"exists", "any", "all", "array",
	"select", "from", "where",
	"as", "cast",
	"extract", "epoch", "day",
	// Query shape. Every one of them is followed by something this file checks: from and join by a
	// scoped slot, a declared CTE or a derived table; on by an expression; with and for are judged
	// separately (declare, substring).
	"join", "inner", "outer", "on",
	"union", "order", "by", "limit", "nulls", "first", "last", "asc", "desc",
)

// fragSpecial are words with a role of their own, judged where they stand: left is a function before
// "(" and a join modifier before JOIN or OUTER; with opens a CTE list, recursive follows it, and for
// is the second keyword of substring(x FROM n FOR m). None may be declared as a name.
var fragSpecial = wordSet("left", "with", "recursive", "for")

// fragValueFuncs read the session or the clock without a "(". Only {now} reaches the clock, and no
// fragment reads the session, so these are refused by name, wherever they stand.
var fragValueFuncs = wordSet(
	"current_user", "session_user", "user", "current_role", "current_schema", "current_catalog",
	"current_timestamp", "current_date", "current_time", "localtime", "localtimestamp", "system_user",
)

// fragFunctions are the functions a fragment may call. Each is pure: it reads its arguments only.
var fragFunctions = wordSet(
	"coalesce", "nullif", "greatest", "least",
	"count", "min", "max", "sum",
	"lower", "upper", "length", "abs", "cardinality",
	"substring", "position", "decode", "uuid_send", "floor", "jsonb_typeof", "jsonb_array_length",
)

// fragTypes are the types a fragment may cast to (`::t`, CAST(x AS t)) or prefix a literal with
// (interval '90 days'). regclass, regproc, xml and the other types that make a string do work are
// not here.
var fragTypes = wordSet(
	"text", "integer", "int", "bigint", "smallint", "boolean", "uuid",
	"timestamptz", "date", "interval", "numeric",
)

func wordSet(w ...string) map[string]bool {
	m := make(map[string]bool, len(w))
	for _, s := range w {
		m[s] = true
	}
	return m
}

type tokKind uint8

const (
	tokWord tokKind = iota
	tokNumber
	tokLiteral
	tokPunct // one operator or bracket character
	tokSlot
)

type token struct {
	kind tokKind
	text string // lower-cased word, the character, or the number; "" for a literal
	lit  string // a string literal's content, quotes removed and '' unescaped
	raw  string // a word as written, for messages
	slot report.SlotKind
	id   report.AnchorID // the <id> of a {rel.<id>} slot
}

// tokenize splits parts into words, numbers, string literals, single punctuation characters and
// slots. It refuses a character that is none of those, and a slot inside a string literal.
func tokenize(parts []report.Part) ([]token, error) {
	var out []token
	inLit := false
	var lit strings.Builder
	for _, p := range parts {
		if p.Kind != report.SlotLiteral {
			if inLit {
				return nil, fmt.Errorf("a slot sits inside a string literal")
			}
			out = append(out, token{kind: tokSlot, slot: p.Kind, id: p.ID})
			continue
		}
		s := p.Text
		for i := 0; i < len(s); {
			c := s[i]
			switch {
			case inLit:
				if c == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						lit.WriteByte('\'')
						i += 2
						continue
					}
					inLit = false
					out = append(out, token{kind: tokLiteral, lit: lit.String()})
					lit.Reset()
				} else {
					lit.WriteByte(c)
				}
				i++
			case c == '\'':
				inLit = true
				i++
			case c == ' ' || c == '\t' || c == '\n' || c == '\r':
				i++
			case isWordStart(c):
				j := i + 1
				for j < len(s) && (isWordStart(s[j]) || isDigit(s[j])) {
					j++
				}
				out = append(out, token{kind: tokWord, text: strings.ToLower(s[i:j]), raw: s[i:j]})
				i = j
			case isDigit(c):
				j := i + 1
				for j < len(s) && isDigit(s[j]) {
					j++
				}
				if j+1 < len(s) && s[j] == '.' && isDigit(s[j+1]) {
					j++
					for j < len(s) && isDigit(s[j]) {
						j++
					}
				}
				out = append(out, token{kind: tokNumber, text: s[i:j]})
				i = j
			case strings.IndexByte("()[],.=<>!+-*/%|&~^@#:?", c) >= 0:
				out = append(out, token{kind: tokPunct, text: string(c)})
				i++
			default:
				return nil, fmt.Errorf("character %q is not allowed", string(rune(c)))
			}
		}
	}
	if inLit {
		return nil, fmt.Errorf("a string literal is not closed")
	}
	return out, nil
}

func isWordStart(c byte) bool { return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool     { return c >= '0' && c <= '9' }

// fragEnv is what the check knows about the dataset a fragment belongs to.
type fragEnv struct {
	tables     map[string]bool          // lower-cased table names (the schema's, and the dataset's)
	rowAnchors map[report.AnchorID]bool // joined RowAnchors: their slot is a bare alias
	ids        map[string]bool          // lower-cased anchor and relation IDs, and "t": the aliases a fragment writes as text
	isColumn   func(name string) bool   // is name a column of a table the dataset uses
	secretKey  func(key string) bool    // is a JSON attribute key a secret; nil refuses every JSON key operator
}

// reserved says whether w has a role of its own and so cannot be a name a fragment declares.
func (e *fragEnv) reserved(w string) bool {
	return fragKeywords[w] || fragFunctions[w] || fragTypes[w] || fragSpecial[w] || fragValueFuncs[w]
}

// checkName judges a name a fragment declares (a CTE, a derived table's alias, a column alias). A
// table-like name (a CTE or a derived-table alias) may not be an anchor or relation ID either, so
// `x.col` always means one thing.
func (e *fragEnv) checkName(raw string, tableLike bool) error {
	w := strings.ToLower(raw)
	switch {
	case e.tables[w]:
		return fmt.Errorf("a fragment names no table: %q is a table name and may not be declared as a name", raw)
	case strings.HasPrefix(w, "pg_") || w == "public" || w == "information_schema":
		return fmt.Errorf("%q may not be declared as a name: it names a system relation or a schema", raw)
	case e.reserved(w):
		return fmt.Errorf("%q is a reserved word and may not be declared as a name", raw)
	case tableLike && e.ids[w]:
		return fmt.Errorf("%q may not be declared as a name: it is also an anchor or relation ID", raw)
	}
	return nil
}

// decls are the names a fragment declares, found before the main pass so a name may be used before
// the clause that declares it (a select list reads `res.lockdur` ahead of `FROM (…) res`).
type decls struct {
	ctes    map[string][]span // names declared by WITH, each with the token range where it is visible
	aliases map[string]bool   // what may stand before a ".": anchor and relation IDs, derived-table aliases (a CTE is judged by ctes)
	cols    map[string]bool   // column names declared by `AS name` and by a CTE's column list
	ok      map[int]bool      // token indexes already judged: a declared name, or WITH / RECURSIVE of a CTE list
	derived map[int]bool      // token indexes of the "(" that opens a derived table: FROM|JOIN ( SELECT|WITH
}

// span is a half-open token range [from, to).
type span struct{ from, to int }

// cteVisible says whether the name w, written at token index at, is a CTE in scope there. Postgres
// makes a CTE visible only inside the query its WITH belongs to: from the WITH to the bracket that
// encloses it (or the end of the fragment at top level). Anywhere else the name resolves through
// search_path to a relation of the schema, which a fragment would read with no {rel.x} scope (T-1103).
func (d *decls) cteVisible(w string, at int) bool {
	for _, s := range d.ctes[w] {
		if at >= s.from && at < s.to {
			return true
		}
	}
	return false
}

func isWord(toks []token, k int, w string) bool {
	return k >= 0 && k < len(toks) && toks[k].kind == tokWord && toks[k].text == w
}
func isPunct(toks []token, k int, c string) bool {
	return k >= 0 && k < len(toks) && toks[k].kind == tokPunct && toks[k].text == c
}

// matching returns the index of the ")" that closes the "(" at toks[open], or -1.
func matching(toks []token, open int) int {
	depth := 0
	for k := open; k < len(toks); k++ {
		if toks[k].kind != tokPunct {
			continue
		}
		switch toks[k].text {
		case "(", "[":
			depth++
		case ")", "]":
			depth--
			if depth == 0 {
				return k
			}
		}
	}
	return -1
}

// aliasEnds are the words that may follow a derived table's alias given without AS.
var aliasEnds = wordSet("left", "inner", "join", "where", "order", "limit", "union")

func declare(toks []token, env *fragEnv) (*decls, error) {
	d := &decls{ctes: map[string][]span{}, aliases: map[string]bool{}, cols: map[string]bool{}, ok: map[int]bool{}, derived: map[int]bool{}}
	for id := range env.ids {
		d.aliases[id] = true
	}
	type open struct {
		bracket string
		index   int // token index of the opening bracket
		derived bool
		cast    bool
	}
	var stack []open
	for i, t := range toks {
		if t.kind != tokPunct && t.kind != tokWord {
			continue
		}
		if t.kind == tokPunct {
			switch t.text {
			case "(", "[":
				o := open{bracket: t.text, index: i}
				if t.text == "(" {
					o.derived = (isWord(toks, i-1, "from") || isWord(toks, i-1, "join")) && (isWord(toks, i+1, "select") || isWord(toks, i+1, "with"))
					o.cast = isWord(toks, i-1, "cast")
				}
				if o.derived {
					d.derived[i] = true
				}
				stack = append(stack, o)
			case ")", "]":
				if len(stack) == 0 || stack[len(stack)-1].bracket != map[string]string{")": "(", "]": "["}[t.text] {
					return nil, fmt.Errorf("brackets do not balance at %q", t.text)
				}
				o := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if o.derived {
					if err := declareDerivedAlias(toks, i, env, d); err != nil {
						return nil, err
					}
				}
			}
			continue
		}
		switch t.text {
		case "with":
			// The WITH belongs to the query inside the innermost open bracket, or to the whole fragment.
			scope := span{from: i, to: len(toks)}
			if len(stack) > 0 {
				k := matching(toks, stack[len(stack)-1].index)
				if k < 0 {
					return nil, fmt.Errorf("brackets do not balance")
				}
				scope.to = k
			}
			if err := declareCTEs(toks, i, scope, env, d); err != nil {
				return nil, err
			}
		case "as":
			if d.ok[i] {
				continue
			}
			var n *token
			if i+1 < len(toks) {
				n = &toks[i+1]
			}
			switch {
			case len(stack) > 0 && stack[len(stack)-1].cast:
				if n == nil || n.kind != tokWord || !fragTypes[n.text] {
					return nil, fmt.Errorf("a fragment may cast only to the types in the allowlist (fragTypes)%s", nameOf(n))
				}
			case n != nil && n.kind == tokPunct && n.text == "(":
				// the `AS (` of a CTE; declareCTEs judged it
			case n != nil && n.kind == tokWord:
				if err := env.checkName(n.raw, false); err != nil {
					return nil, err
				}
				d.cols[n.text] = true
				d.ok[i+1] = true
			default:
				return nil, fmt.Errorf(`"as" must be followed by a plain name`)
			}
		}
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("brackets do not balance")
	}
	return d, nil
}

func nameOf(n *token) string {
	if n != nil && n.kind == tokWord {
		return fmt.Sprintf(" (found %q)", n.raw)
	}
	return ""
}

// declareCTEs reads `WITH [RECURSIVE] name [(col, …)] AS ( … ) [, name … AS ( … )]` at toks[i]. The
// bodies are checked by the main pass like any other text; a name is declared only here, so a CTE
// is always a name this fragment wrote itself. scope is where the names are visible.
func declareCTEs(toks []token, i int, scope span, env *fragEnv, d *decls) error {
	d.ok[i] = true
	j := i + 1
	recursive := isWord(toks, j, "recursive")
	if recursive {
		d.ok[j] = true
		j++
	}
	var list []cteBody
	for {
		if j >= len(toks) || toks[j].kind != tokWord {
			return fmt.Errorf(`"with" must be followed by a CTE name; only WITH [RECURSIVE] name [(columns)] AS (…) is allowed`)
		}
		if err := env.checkName(toks[j].raw, true); err != nil {
			return err
		}
		name, raw := toks[j].text, toks[j].raw
		d.ctes[name] = append(d.ctes[name], scope)
		d.ok[j] = true
		j++
		if isPunct(toks, j, "(") {
			j++
			for {
				if j >= len(toks) || toks[j].kind != tokWord {
					return fmt.Errorf("a CTE column list holds names only")
				}
				if err := env.checkName(toks[j].raw, false); err != nil {
					return err
				}
				d.cols[toks[j].text], d.ok[j] = true, true
				j++
				if isPunct(toks, j, ",") {
					j++
					continue
				}
				break
			}
			if !isPunct(toks, j, ")") {
				return fmt.Errorf("a CTE column list is not closed")
			}
			j++
		}
		if !isWord(toks, j, "as") || !isPunct(toks, j+1, "(") {
			return fmt.Errorf(`a CTE name must be followed by AS (…); MATERIALIZED and other options are not allowed`)
		}
		d.ok[j] = true
		k := matching(toks, j+1)
		if k < 0 {
			return fmt.Errorf("a CTE body is not closed")
		}
		list = append(list, cteBody{name: name, raw: raw, start: j + 2, end: k})
		if isPunct(toks, k+1, ",") {
			j = k + 2
			continue
		}
		if !recursive {
			return checkCTEForwardRefs(toks, list)
		}
		return nil
	}
}

// cteBody is one CTE of a WITH list: its name and the token range of its body, brackets excluded.
type cteBody struct {
	name, raw  string
	start, end int
}

// checkCTEForwardRefs refuses, in a non-recursive WITH, a body that names its own CTE or one
// declared after it. Without RECURSIVE such a name resolves to a relation of the schema (a view, a
// materialized view, a sequence), which would be read with no {rel.x} scope, and a view runs with
// its owner's rights (T-1087). The word is refused wherever it stands in the body, a column alias
// of the same name included: the cost is a rename, and no resolution rule has to be reasoned about.
func checkCTEForwardRefs(toks []token, list []cteBody) error {
	for n, c := range list {
		for _, later := range list[n:] {
			for k := c.start; k < c.end; k++ {
				if toks[k].kind != tokWord || toks[k].text != later.name {
					continue
				}
				if later.name == c.name {
					return fmt.Errorf("CTE %q refers to itself without RECURSIVE: inside its own body the name resolves to a relation of the schema, not to the CTE", c.raw)
				}
				return fmt.Errorf("CTE %q refers to %q, which is declared after it: the name resolves to a relation of the schema, not to the CTE", c.raw, later.raw)
			}
		}
	}
	return nil
}

// declareDerivedAlias reads the alias after the ")" at toks[k] that closes a derived table.
func declareDerivedAlias(toks []token, k int, env *fragEnv, d *decls) error {
	a := k + 1
	explicit := isWord(toks, a, "as")
	if explicit {
		d.ok[a] = true
		a++
	}
	if a >= len(toks) || toks[a].kind != tokWord || (!explicit && env.reserved(toks[a].text)) {
		if explicit {
			return fmt.Errorf(`"as" after a subselect must be followed by a name`)
		}
		return nil // no alias
	}
	if !explicit {
		// An alias without AS must be followed by what ends a FROM item, so a keyword that the allowlist
		// does not know cannot ride in as an "alias".
		if a+1 < len(toks) && !(toks[a+1].kind == tokPunct && toks[a+1].text == ")") && !(toks[a+1].kind == tokWord && aliasEnds[toks[a+1].text]) {
			return fmt.Errorf("%q follows a subselect but is not an alias the check can place; write AS %s", toks[a].raw, toks[a].raw)
		}
	}
	if err := env.checkName(toks[a].raw, true); err != nil {
		return err
	}
	d.aliases[toks[a].text], d.ok[a] = true, true
	return nil
}

// special is an open EXTRACT( or SUBSTRING( : the FROM directly inside it is part of its syntax.
type special struct {
	depth               int
	fromUsed, sawSelect bool
	substring           bool
}

// checkFragment applies the allowlist to a parsed fragment.
//
// The rules, in token terms:
//   - a word is a keyword, a function followed by "(", a type after "::", "as" or before a literal,
//     a name the fragment declares (CTE, derived-table alias, column alias), a column of a table the
//     dataset uses, or a column after "." ;
//   - a "." follows {t}, {rel.x} or a declared alias, never a schema: public.x, pg_catalog.x and
//     information_schema.x are refused;
//   - FROM and JOIN are followed by exactly one of: a {rel.x} slot (not a RowAnchor, not dotted), a CTE
//     this fragment declared, or a derived table "( SELECT|WITH …". So a subselect reads only
//     relations the compiler built and scoped, or what such relations feed. FROM is not followed by a
//     table, ONLY, a function or LATERAL. Exempt: IS [NOT] DISTINCT FROM, and the FROM directly inside
//     EXTRACT( and SUBSTRING( ;
//   - no "," follows a FROM or JOIN item at its bracket level before the next SELECT, UNION, ORDER or
//     LIMIT (a second item would be unscoped);
//   - the session and clock words (current_user, current_timestamp, …) are refused wherever they stand.
func checkFragment(parts []report.Part, env *fragEnv) error {
	toks, err := tokenize(parts)
	if err != nil {
		return err
	}
	d, err := declare(toks, env)
	if err != nil {
		return err
	}
	var specials []*special
	depth := 0
	inFrom := map[int]bool{}
	topSpecial := func() *special {
		if k := len(specials); k > 0 && specials[k-1].depth == depth {
			return specials[k-1]
		}
		return nil
	}
	for i, t := range toks {
		var p, pp, n *token
		if i > 0 {
			p = &toks[i-1]
		}
		if i > 1 {
			pp = &toks[i-2]
		}
		if i+1 < len(toks) {
			n = &toks[i+1]
		}
		if t.kind == tokWord && t.text == "as" && n != nil && n.kind == tokWord && (n.text == "timestamptz" || n.text == "date") {
			for k, depth := i-1, 0; k >= 0; k-- {
				if isPunct(toks, k, ")") {
					depth++
				} else if isPunct(toks, k, "(") {
					if depth == 0 {
						if isWord(toks, k-1, "cast") {
							if err := checkTemporalOperand(toks[k+1:i], n.text); err != nil {
								return err
							}
						}
						break
					}
					depth--
				}
			}
		}
		switch t.kind {
		case tokSlot:
			// {t} or a RowAnchor's {rel.x} on its own is the whole row (`{t}::text` prints every column,
			// attributes included); only a column read, {t}.col, is allowed.
			whole := t.slot == report.SlotBase || t.slot == report.SlotRel && env.rowAnchors[t.id]
			if whole && !isPunct(toks, i+1, ".") && !isWord(toks, i-1, "from") && !isWord(toks, i-1, "join") {
				return fmt.Errorf("a slot stands for a whole row here; read a column as {t}.col or {rel.<id>}.col")
			}
		case tokLiteral:
			if specialInput(t.lit) != "" {
				return fmt.Errorf("the literal %q names the clock or a special date; the clock comes only through {now}", t.lit)
			}
		case tokPunct:
			if t.text == ">" {
				if err := checkJSONOp(toks, i, env); err != nil {
					return err
				}
			}
			if t.text == "[" {
				if err := checkSubscript(toks, i, env); err != nil {
					return err
				}
			}
			if t.text == ":" && isPunct(toks, i+1, ":") && i+2 < len(toks) && toks[i+2].kind == tokWord {
				if err := checkCast(toks, i, toks[i+2].text, env); err != nil {
					return err
				}
			}
			switch t.text {
			case "(", "[":
				depth++
				if t.text == "(" && p != nil && p.kind == tokWord && (p.text == "extract" || p.text == "substring") {
					specials = append(specials, &special{depth: depth, substring: p.text == "substring"})
				}
			case ")", "]":
				if topSpecial() != nil {
					specials = specials[:len(specials)-1]
				}
				delete(inFrom, depth)
				depth--
			case ",":
				if inFrom[depth] {
					return fmt.Errorf(`a "," follows the FROM or JOIN item at the same level: a FROM list may hold one item only, because any further item would be read unscoped`)
				}
			case ".":
				qualified := p != nil && (p.kind == tokSlot && (p.slot == report.SlotBase || p.slot == report.SlotRel) ||
					p.kind == tokWord && (d.aliases[p.text] || d.cteVisible(p.text, i-1)))
				if p != nil && p.kind == tokWord && !qualified && len(d.ctes[p.text]) > 0 {
					return fmt.Errorf("CTE %q is used with a dot outside the query its WITH belongs to: there the name is not the CTE", p.raw)
				}
				if !qualified || pp != nil && pp.kind == tokPunct && pp.text == "." {
					return fmt.Errorf("a schema-qualified or dotted name is not allowed%s; reach a column as {t}.col, {rel.<id>}.col or alias.col of a name the fragment declares", nearWord(p, n))
				}
				if n != nil && n.kind == tokPunct && n.text == "*" && p.kind == tokSlot && (p.slot == report.SlotBase || env.rowAnchors[p.id]) {
					return fmt.Errorf("a slot stands for a whole row here ({t}.* expands to every column, attributes included); read named columns")
				}
				if n == nil || n.kind != tokWord && !(n.kind == tokPunct && n.text == "*") {
					return fmt.Errorf("a %q must be followed by a column name", ".")
				}
			}
		case tokWord:
			if d.ok[i] {
				continue
			}
			w := t.text
			if p != nil && p.kind == tokPunct && p.text == "." {
				if n != nil && n.kind == tokPunct && n.text == "(" {
					return fmt.Errorf("a fragment may not call %q as a method", t.raw)
				}
				continue // a column of {t}, of a relation or of a declared alias
			}
			if p != nil && p.kind == tokPunct && p.text == ":" && pp != nil && pp.kind == tokPunct && pp.text == ":" {
				if fragTypes[w] {
					continue
				}
				return fmt.Errorf("a fragment may cast only to the types in the allowlist (fragTypes); found %q", t.raw)
			}
			if p != nil && p.kind == tokWord && p.text == "as" && fragTypes[w] {
				continue
			}
			if n != nil && n.kind == tokLiteral && fragTypes[w] {
				continue // interval '90 days'
			}
			if w == "left" {
				if n != nil && (n.kind == tokPunct && n.text == "(" || n.kind == tokWord && (n.text == "join" || n.text == "outer")) {
					continue
				}
				return fmt.Errorf(`"left" must be a function call or precede JOIN`)
			}
			if w == "for" {
				if s := topSpecial(); s != nil && s.substring && !s.sawSelect {
					continue
				}
				return fmt.Errorf(`"for" is allowed only inside substring(… FROM … FOR …)`)
			}
			if fragFunctions[w] {
				if n == nil || n.kind != tokPunct || n.text != "(" {
					return fmt.Errorf("%q is a function and must be called", t.raw)
				}
				continue
			}
			if fragKeywords[w] {
				switch w {
				case "from", "join":
					item, err := checkFrom(toks, i, w, topSpecial(), env, d)
					if err != nil {
						return err
					}
					if item {
						inFrom[depth] = true
					}
				case "select":
					delete(inFrom, depth)
					if s := topSpecial(); s != nil {
						s.sawSelect = true
					}
				case "union", "order", "limit":
					delete(inFrom, depth)
				}
				continue
			}
			if fragSpecial[w] || fragValueFuncs[w] {
				if fragValueFuncs[w] {
					return fmt.Errorf("a fragment may not use %q: the session and the clock are reached through {now} only", t.raw)
				}
				return fmt.Errorf("a fragment may not use %q here; WITH must open a CTE list", t.raw)
			}
			if env.tables[w] {
				return fmt.Errorf("a fragment names no table (found %q); tables enter through {rel.<id>}", t.raw)
			}
			if n != nil && n.kind == tokPunct && n.text == "(" {
				return fmt.Errorf("a fragment may not call %q; its functions come from the allowlist (fragFunctions)", t.raw)
			}
			if n != nil && n.kind == tokLiteral {
				return fmt.Errorf("a fragment may not use %q before a literal; only the types in fragTypes may", t.raw)
			}
			if n != nil && n.kind == tokPunct && n.text == "." {
				if d.aliases[w] || len(d.ctes[w]) > 0 {
					continue // the "." case judges the qualified name
				}
				return fmt.Errorf("a schema-qualified name is not allowed (found %q.…)", t.raw)
			}
			if d.cols[w] || env.isColumn(w) {
				continue
			}
			return fmt.Errorf("a fragment may not use %q; it is not a keyword, function or type on the allowlist (fragKeywords, fragFunctions, fragTypes), nor a column of the dataset's tables, nor a name the fragment declares", t.raw)
		}
	}
	return nil
}

// checkFrom judges the FROM or JOIN at toks[i]. It reports whether the word opens a FROM item (as
// opposed to being part of IS [NOT] DISTINCT FROM, or the FROM of EXTRACT( / SUBSTRING( ).
//
// An item is: one {rel.x} slot that expands to a subselect the compiler built (Rel, FilterAnchor,
// MaskAnchor), never a RowAnchor's bare alias, and not followed by "." (that would reach
// {rel.public}.directory_objects); or a CTE name the fragment declared with WITH, not followed by "."
// (that would be a schema); or a derived table "( SELECT|WITH …" whose body this pass checks like
// any other text. Everything else, a table, ONLY, LATERAL or a function included, is refused.
//
// Only the exact phrases IS DISTINCT FROM and IS NOT DISTINCT FROM are exempt: "distinct" before
// "from" is not enough, since `AS distinct FROM {rel.x}` is a select list ending in an alias. The
// first FROM directly inside EXTRACT( or SUBSTRING( is exempt, unless a SELECT stands at that level.
func checkFrom(toks []token, i int, kw string, s *special, env *fragEnv, d *decls) (bool, error) {
	if kw == "from" {
		// A word after "." is a column, never a keyword: `{t}.is distinct FROM …` is a select list ending
		// in the column label "distinct", followed by a real FROM.
		kwIs := func(k int) bool { return isWord(toks, k, "is") && !isPunct(toks, k-1, ".") }
		if isWord(toks, i-1, "distinct") && (kwIs(i-2) || isWord(toks, i-2, "not") && kwIs(i-3)) {
			return false, nil
		}
		if s != nil && !s.fromUsed && !s.sawSelect {
			s.fromUsed = true
			return false, nil
		}
	}
	var n *token
	if i+1 < len(toks) {
		n = &toks[i+1]
	}
	dotted := i+2 < len(toks) && toks[i+2].kind == tokPunct && toks[i+2].text == "."
	switch {
	case n != nil && n.kind == tokSlot && n.slot == report.SlotRel:
		if env.rowAnchors[n.id] {
			return false, fmt.Errorf("{rel.%s} follows %s, but %q is a RowAnchor: its slot is a bare alias, which %s would resolve as a table; read it as {rel.%s}.col outside FROM, or declare a FilterAnchor or Rel", n.id, kw, n.id, kw, n.id)
		}
		if dotted {
			return false, fmt.Errorf("{rel.%s} follows %s and is followed by a dot: a FROM item is the bare slot, never a qualified name", n.id, kw)
		}
		return true, nil
	case n != nil && n.kind == tokWord && len(d.ctes[n.text]) > 0:
		if !d.cteVisible(n.text, i+1) {
			return false, fmt.Errorf("CTE %q follows %s outside the query its WITH belongs to: there the name resolves to a relation of the schema, not to the CTE", n.raw, kw)
		}
		if dotted {
			return false, fmt.Errorf("%q follows %s and is followed by a dot: a CTE is never schema-qualified", n.raw, kw)
		}
		d.ok[i+1] = true
		return true, nil
	case n != nil && n.kind == tokPunct && n.text == "(":
		if !d.derived[i+1] {
			return false, fmt.Errorf(`"(" follows %s but does not open a subselect (SELECT or WITH); a fragment names no table`, kw)
		}
		return true, nil
	case n != nil && n.kind == tokWord:
		return false, fmt.Errorf("a fragment names no table: %q follows %s, which must be followed by a {rel.<id>} slot, a CTE the fragment declares, or a subselect", n.raw, kw)
	}
	return false, fmt.Errorf(`%q must be followed by a {rel.<id>} slot, a CTE the fragment declares, or a subselect; a fragment names no table`, kw)
}

// specialInput returns the word of a literal that PostgreSQL parses as the clock or a special
// date or time (now, today, tomorrow, yesterday, epoch, infinity, allballs), or "".
func specialInput(lit string) string {
	for _, w := range strings.FieldsFunc(strings.ToLower(lit), func(r rune) bool { return r < 'a' || r > 'z' }) {
		switch w {
		case "now", "today", "tomorrow", "yesterday", "epoch", "infinity", "allballs":
			return w
		}
	}
	return ""
}

// checkJSONOp judges the JSON operator whose last ">" is at toks[i]: ->, ->>, #> or #>>. Its right
// operand must be a string literal (or, for -> and ->>, an integer), and a literal key is run
// through the SecretKey predicate, so a derived fragment cannot read a key a JSONAttr column
// refuses. Anything else (a parenthesis, a concatenation) could build the key, so it is refused.
func checkJSONOp(toks []token, i int, env *fragEnv) error {
	if i == 0 || toks[i-1].kind != tokPunct || (toks[i-1].text != "-" && toks[i-1].text != "#") {
		return nil
	}
	path := toks[i-1].text == "#"
	j := i + 1
	if isPunct(toks, j, ">") {
		j++
	}
	if j < len(toks) && toks[j].kind == tokNumber && !path {
		return nil
	}
	if j >= len(toks) || toks[j].kind != tokLiteral {
		return fmt.Errorf("a JSON key operator must be followed by a string literal, so the key can be checked")
	}
	if env.secretKey == nil {
		return fmt.Errorf("a JSON key operator is refused: no SecretKey predicate is configured")
	}
	keys := []string{toks[j].lit}
	if path {
		for _, k := range strings.FieldsFunc(toks[j].lit, func(r rune) bool { return strings.ContainsRune("{}, \"", r) }) {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		if env.secretKey(k) {
			return fmt.Errorf("the JSON key %q is a secret attribute and may not be read", k)
		}
	}
	return nil
}

func nearWord(p, n *token) string {
	switch {
	case p != nil && p.kind == tokWord && n != nil && n.kind == tokWord:
		return fmt.Sprintf(" (found %q.%q)", p.raw, n.raw)
	case p != nil && p.kind == tokWord:
		return fmt.Sprintf(" (found %q.…)", p.raw)
	}
	return ""
}

// checkSubscript judges the "[" at toks[i]. After ARRAY it opens an array constructor. Anywhere else it
// is a subscript, and a jsonb subscript reads a key (`attributes['unicodePwd']`). An index holding no
// string literal is an array index computed from columns and numbers (`{t}.via[hop.i]`), which cannot
// spell a key. One holding a string literal must be that single literal, run through SecretKey.
func checkSubscript(toks []token, i int, env *fragEnv) error {
	if isWord(toks, i-1, "array") {
		return nil
	}
	depth, lits, end := 0, 0, -1
	for k := i; k < len(toks) && end < 0; k++ {
		switch {
		case isPunct(toks, k, "["):
			depth++
		case isPunct(toks, k, "]"):
			if depth--; depth == 0 {
				end = k
			}
		case toks[k].kind == tokLiteral:
			lits++
		}
	}
	if end < 0 || lits == 0 {
		return nil
	}
	if lits > 1 || end != i+2 || toks[i+1].kind != tokLiteral {
		return fmt.Errorf("a subscript holding a string must hold one literal alone, so the key can be checked")
	}
	if env.secretKey == nil {
		return fmt.Errorf("a subscript is refused: no SecretKey predicate is configured")
	}
	if env.secretKey(toks[i+1].lit) {
		return fmt.Errorf("the JSON key %q is a secret attribute and may not be read", toks[i+1].lit)
	}
	return nil
}

// checkCast judges the cast "::typ" whose first colon is at toks[i]. A string cast to timestamptz or
// date can name the clock ('now'), and a built string ('n' || 'ow') hides it from the literal check, so
// the operand must not contain a string literal unless it is the single literal, which the literal
// check has already vetted. Casting the whole attributes column to text is refused too: it prints
// every key.
func checkCast(toks []token, i int, typ string, env *fragEnv) error {
	if typ == "text" && isWord(toks, i-1, "attributes") {
		return fmt.Errorf("the attributes column may not be cast to text: it would print every key, secrets included")
	}
	if typ != "timestamptz" && typ != "date" {
		return nil
	}
	if i == 0 {
		return nil
	}
	if !isPunct(toks, i-1, ")") {
		if toks[i-1].kind == tokPunct && toks[i-1].text == "]" {
			return fmt.Errorf("a cast to %s of a subscript is refused", typ)
		}
		return nil
	}
	depth := 0
	for k := i - 1; k >= 0; k-- {
		switch {
		case isPunct(toks, k, ")"):
			depth++
		case isPunct(toks, k, "("):
			depth--
			if depth == 0 {
				return checkTemporalOperand(toks[k+1:i-1], typ)
			}
		}
	}
	return nil
}

func checkTemporalOperand(inner []token, typ string) error {
	if len(inner) == 1 && inner[0].kind == tokLiteral {
		return nil
	}
	for _, t := range inner {
		if t.kind == tokLiteral {
			return fmt.Errorf("a string expression is cast to %s: a built string could name the clock; cast a single literal or a column", typ)
		}
	}
	return nil
}
