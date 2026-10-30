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
)

// fragFunctions are the functions a fragment may call. Each is pure: it reads its arguments only.
var fragFunctions = wordSet(
	"coalesce", "nullif", "greatest", "least",
	"count", "min", "max", "sum",
	"lower", "upper", "length", "abs", "cardinality",
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
	raw  string // a word as written, for messages
	slot report.SlotKind
}

// tokenize splits parts into words, numbers, string literals, single punctuation characters and
// slots. It refuses a character that is none of those, and a slot inside a string literal.
func tokenize(parts []report.Part) ([]token, error) {
	var out []token
	inLit := false
	for _, p := range parts {
		if p.Kind != report.SlotLiteral {
			if inLit {
				return nil, fmt.Errorf("a slot sits inside a string literal")
			}
			out = append(out, token{kind: tokSlot, slot: p.Kind})
			continue
		}
		s := p.Text
		for i := 0; i < len(s); {
			c := s[i]
			switch {
			case inLit:
				if c == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i += 2
						continue
					}
					inLit = false
					out = append(out, token{kind: tokLiteral})
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

// checkFragment applies the allowlist to a parsed fragment. tables holds the lower-cased table
// names, only to give the "names a table" message; the allowlist refuses those words anyway.
//
// The rules, in token terms:
//   - a word is a keyword, a function followed by "(", a type after "::", "as" or before a
//     literal, or a column name after "{t}." or "{rel.x}.";
//   - a "." is allowed only after {t} or {rel.x}, so no schema-qualified name exists;
//   - "from" is followed by {rel.x}, except in IS DISTINCT FROM and EXTRACT(… FROM …), so a
//     subselect reads only relations the compiler built and scoped.
func checkFragment(parts []report.Part, tables map[string]bool) error {
	toks, err := tokenize(parts)
	if err != nil {
		return err
	}
	var extractDepth []int // paren depths at which an EXTRACT( is open
	depth := 0
	prev := func(i int) *token {
		if i == 0 {
			return nil
		}
		return &toks[i-1]
	}
	next := func(i int) *token {
		if i+1 >= len(toks) {
			return nil
		}
		return &toks[i+1]
	}
	for i, t := range toks {
		p, n := prev(i), next(i)
		switch t.kind {
		case tokPunct:
			switch t.text {
			case "(":
				depth++
				if p != nil && p.kind == tokWord && p.text == "extract" {
					extractDepth = append(extractDepth, depth)
				}
			case ")":
				if k := len(extractDepth); k > 0 && extractDepth[k-1] == depth {
					extractDepth = extractDepth[:k-1]
				}
				depth--
			case ".":
				if p == nil || p.kind != tokSlot || (p.slot != report.SlotBase && p.slot != report.SlotRel) {
					return fmt.Errorf("a schema-qualified or dotted name is not allowed%s; reach a column as {t}.col or {rel.<id>}.col", nearWord(p, n))
				}
				if n == nil || n.kind != tokWord && !(n.kind == tokPunct && n.text == "*") {
					return fmt.Errorf("a %q must be followed by a column name", ".")
				}
			}
		case tokWord:
			w := t.text
			afterDot := p != nil && p.kind == tokPunct && p.text == "."
			if afterDot {
				if n != nil && n.kind == tokPunct && n.text == "(" {
					return fmt.Errorf("a fragment may not call %q as a method", t.raw)
				}
				continue // a column of {t} or of a relation
			}
			afterCast := p != nil && (p.kind == tokPunct && p.text == ":" || p.kind == tokWord && p.text == "as")
			if afterCast && fragTypes[w] {
				continue
			}
			if n != nil && n.kind == tokLiteral && fragTypes[w] {
				continue // interval '90 days'
			}
			if fragFunctions[w] {
				if n == nil || n.kind != tokPunct || n.text != "(" {
					return fmt.Errorf("%q is a function and must be called", t.raw)
				}
				continue
			}
			if fragKeywords[w] {
				if w == "from" {
					if err := checkFrom(p, n, len(extractDepth) > 0 && extractDepth[len(extractDepth)-1] == depth); err != nil {
						return err
					}
				}
				continue
			}
			if tables[w] {
				return fmt.Errorf("a fragment names no table (found %q); tables enter through {rel.<id>}", t.raw)
			}
			if n != nil && n.kind == tokPunct && n.text == "(" {
				return fmt.Errorf("a fragment may not call %q; its functions come from the allowlist (fragFunctions)", t.raw)
			}
			if n != nil && n.kind == tokPunct && n.text == "." {
				return fmt.Errorf("a schema-qualified name is not allowed (found %q.…)", t.raw)
			}
			return fmt.Errorf("a fragment may not use %q; its words come from the allowlist (fragKeywords, fragTypes)", t.raw)
		}
	}
	return nil
}

// checkFrom allows FROM only before a {rel.x} slot, inside EXTRACT(…), or after DISTINCT.
func checkFrom(p, n *token, inExtract bool) error {
	if p != nil && p.kind == tokWord && p.text == "distinct" {
		return nil
	}
	if inExtract {
		return nil
	}
	if n != nil && n.kind == tokSlot && n.slot == report.SlotRel {
		return nil
	}
	if n != nil && n.kind == tokWord {
		return fmt.Errorf("a fragment names no table: %q follows from, which must be followed by a {rel.<id>} slot", n.raw)
	}
	return fmt.Errorf(`"from" must be followed by a {rel.<id>} slot; a fragment names no table`)
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
