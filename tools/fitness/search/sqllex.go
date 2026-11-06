package main

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// A small PostgreSQL lexer: enough to tell code from string literals and comments, which is what a text
// grep cannot do (RAISE EXCEPTION '... %' and LIKE '%x%' are legitimate, a bare % is a trigram operator).
// It does not parse SQL. Dollar-quoted bodies are lexed as code and flattened into the stream between
// a tBegin and a tEnd token, so a statement that defines a function still contains the words of its body.

type tokKind byte

const (
	tWord   tokKind = 'w' // identifier or keyword, lower-cased; a quoted identifier is tQuoted
	tQuoted tokKind = 'q'
	tParam  tokKind = 'p' // $1
	tOp     tokKind = 'o' // an operator lexeme, maximal munch
	tPunct  tokKind = ',' // ( ) , ; . : [ ]
	tStr    tokKind = 's' // a string literal; text is its content
	tNum    tokKind = 'n'
	tBegin  tokKind = '{' // start of a dollar-quoted body
	tEnd    tokKind = '}'
)

type tok struct {
	kind tokKind
	text string
	line int // 1-based, relative to the start of the lexed text
}

func (t tok) is(kind tokKind, text string) bool { return t.kind == kind && t.text == text }
func (t tok) word(text string) bool             { return t.kind == tWord && t.text == text }

const opChars = "+-*/<>=~!@#%^&|`?"

func isWordStart(r rune) bool { return r == '_' || unicode.IsLetter(r) || r >= 0x80 }
func isWordPart(r rune) bool  { return isWordStart(r) || unicode.IsDigit(r) || r == '$' }

// lexSQL tokenises src. line0 is the line of src's first character.
func lexSQL(src string, line0 int) []tok {
	l := &lexer{src: src, line: line0}
	l.run()
	return l.out
}

type lexer struct {
	src  string
	pos  int
	line int
	out  []tok
}

func (l *lexer) emit(k tokKind, text string, line int) { l.out = append(l.out, tok{k, text, line}) }

func (l *lexer) adv(n int) {
	l.line += strings.Count(l.src[l.pos:l.pos+n], "\n")
	l.pos += n
}

func (l *lexer) run() {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v':
			l.adv(1)
		case c == '-' && strings.HasPrefix(l.src[l.pos:], "--"):
			end := strings.IndexByte(l.src[l.pos:], '\n')
			if end < 0 {
				end = len(l.src) - l.pos
			}
			l.adv(end)
		case c == '/' && strings.HasPrefix(l.src[l.pos:], "/*"):
			l.blockComment()
		case c == '\'':
			l.str(false)
		case c == '"':
			l.quoted()
		case c == '$':
			l.dollar()
		case c >= '0' && c <= '9':
			l.number()
		case strings.IndexByte(opChars, c) >= 0:
			l.operator()
		case strings.IndexByte("(),;.:[]", c) >= 0:
			l.emit(tPunct, string(c), l.line)
			l.adv(1)
		default:
			r, size := utf8.DecodeRuneInString(l.src[l.pos:])
			if isWordStart(r) {
				l.word()
			} else {
				l.adv(size)
			}
		}
	}
}

func (l *lexer) blockComment() {
	depth := 0
	i := l.pos
	for i < len(l.src) {
		switch {
		case strings.HasPrefix(l.src[i:], "/*"):
			depth++
			i += 2
		case strings.HasPrefix(l.src[i:], "*/"):
			depth--
			i += 2
			if depth == 0 {
				l.adv(i - l.pos)
				return
			}
		default:
			i++
		}
	}
	l.adv(len(l.src) - l.pos) // unterminated: the rest is comment
}

// str lexes a string literal at l.pos (which is on the opening quote). escapes is true for E'...'.
func (l *lexer) str(escapes bool) {
	line := l.line
	i := l.pos + 1
	var b strings.Builder
	for i < len(l.src) {
		c := l.src[i]
		switch {
		case c == '\'' && i+1 < len(l.src) && l.src[i+1] == '\'':
			b.WriteByte('\'')
			i += 2
		case c == '\'':
			l.adv(i + 1 - l.pos)
			l.emit(tStr, b.String(), line)
			return
		case c == '\\' && escapes && i+1 < len(l.src):
			b.WriteByte(l.src[i+1])
			i += 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	l.adv(len(l.src) - l.pos)
	l.emit(tStr, b.String(), line)
}

func (l *lexer) quoted() {
	line := l.line
	i := l.pos + 1
	var b strings.Builder
	for i < len(l.src) {
		c := l.src[i]
		if c == '"' {
			if i+1 < len(l.src) && l.src[i+1] == '"' {
				b.WriteByte('"')
				i += 2
				continue
			}
			l.adv(i + 1 - l.pos)
			l.emit(tQuoted, b.String(), line)
			return
		}
		b.WriteByte(c)
		i++
	}
	l.adv(len(l.src) - l.pos)
	l.emit(tQuoted, b.String(), line)
}

func (l *lexer) number() {
	i := l.pos
	for i < len(l.src) && (l.src[i] >= '0' && l.src[i] <= '9' || l.src[i] == '.' && i+1 < len(l.src) && l.src[i+1] >= '0' && l.src[i+1] <= '9') {
		i++
	}
	l.emit(tNum, l.src[l.pos:i], l.line)
	l.adv(i - l.pos)
}

func (l *lexer) word() {
	i := l.pos
	for i < len(l.src) {
		r, size := utf8.DecodeRuneInString(l.src[i:])
		if !isWordPart(r) {
			break
		}
		i += size
	}
	w := l.src[l.pos:i]
	// A prefix letter of a string literal: E'..' takes backslash escapes; B, X, N and U& do not.
	if i < len(l.src) && l.src[i] == '\'' && len(w) == 1 && strings.ContainsAny(w, "eEbBxXnN") {
		l.adv(i - l.pos)
		l.str(w == "e" || w == "E")
		return
	}
	l.emit(tWord, strings.ToLower(w), l.line)
	l.adv(i - l.pos)
}

// dollar lexes $1 (a parameter), $tag$ ... $tag$ (a quoted body, lexed as code), or a stray $.
func (l *lexer) dollar() {
	rest := l.src[l.pos+1:]
	if rest != "" && rest[0] >= '0' && rest[0] <= '9' {
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		l.emit(tParam, "$"+rest[:i], l.line)
		l.adv(1 + i)
		return
	}
	i := 0
	for i < len(rest) {
		r, size := utf8.DecodeRuneInString(rest[i:])
		if !(r == '_' || unicode.IsLetter(r) || (i > 0 && unicode.IsDigit(r))) {
			break
		}
		i += size
	}
	if i < len(rest) && rest[i] == '$' {
		tag := "$" + rest[:i] + "$"
		bodyStart := l.pos + len(tag)
		end := strings.Index(l.src[bodyStart:], tag)
		if end >= 0 {
			body := l.src[bodyStart : bodyStart+end]
			if n := len(l.out); n > 0 && (l.out[n-1].is(tPunct, "(") || l.out[n-1].is(tPunct, ",") || l.out[n-1].kind == tOp) {
				// An argument or an operand, as in format($p$CREATE POLICY %I ...$p$, ...): a string.
				line := l.line
				l.adv(len(tag) + end + len(tag))
				l.emit(tStr, body, line)
				return
			}
			l.emit(tBegin, tag, l.line)
			l.out = append(l.out, lexSQL(body, l.line+strings.Count(l.src[l.pos:bodyStart], "\n"))...)
			l.adv(len(tag) + end + len(tag))
			l.emit(tEnd, tag, l.line)
			return
		}
	}
	l.adv(1)
}

func (l *lexer) operator() {
	i := l.pos
	for i < len(l.src) && strings.IndexByte(opChars, l.src[i]) >= 0 {
		if i > l.pos && (strings.HasPrefix(l.src[i:], "--") || strings.HasPrefix(l.src[i:], "/*")) {
			break
		}
		i++
	}
	op := l.src[l.pos:i]
	// PostgreSQL: a multi-character operator does not end in + or - unless it also holds one of ~!@#%^&|`?
	if len(op) > 1 && strings.ContainsAny(op[len(op)-1:], "+-") && !strings.ContainsAny(op, "~!@#%^&|`?") {
		for len(op) > 1 && strings.ContainsAny(op[len(op)-1:], "+-") {
			op = op[:len(op)-1]
		}
	}
	l.emit(tOp, op, l.line)
	l.adv(len(op))
}

// splitStatements cuts the stream at top-level semicolons (outside dollar-quoted bodies).
func splitStatements(toks []tok) [][]tok {
	var out [][]tok
	depth, start := 0, 0
	for i, t := range toks {
		switch {
		case t.kind == tBegin:
			depth++
		case t.kind == tEnd:
			depth--
		case t.is(tPunct, ";") && depth == 0:
			if i > start {
				out = append(out, toks[start:i])
			}
			start = i + 1
		}
	}
	if start < len(toks) {
		out = append(out, toks[start:])
	}
	return out
}

// names reports whether the tokens mention a table: a bare or quoted identifier equal to name, with or
// without a schema, as a whole word. String literals do not count: a table named inside a string is not
// a reference (a CHECK message, an error text); the one place a string names a table is regclass, which
// the rules below look at separately.
func names(toks []tok, name string) (line int, ok bool) {
	for _, t := range toks {
		if (t.kind == tWord || t.kind == tQuoted) && t.text == name {
			return t.line, true
		}
	}
	return 0, false
}
