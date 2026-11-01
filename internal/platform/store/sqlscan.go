package store

import "strings"

// Statements splits sql into its ';'-separated statements for inspection (never for execution). Every
// comment ("--" to the next CR or LF, and nested "/* */") becomes a space, and the content of every
// quoted run (a '…' literal, an E'…' literal with backslash escapes, a "…" identifier and a
// $tag$…$tag$ body) is replaced by an empty ” so a ';', an apostrophe or a keyword inside quotes can
// neither split nor hide a statement. A literal followed by whitespace that holds a newline and then
// another literal is one literal in PostgreSQL (a continuation), and the second segment is lexed like
// the first, so an E'…' continuation keeps its backslash escapes. An unterminated comment or quote
// hides the rest of the text, as it does for PostgreSQL. Empty statements are dropped.
//
// This is the lexing for standard_conforming_strings = on, where a plain '…' literal has no backslash
// escape. A session can switch that off (SET, set_config, a role or database default) and the scanner
// cannot know, so a guard must look at Lexings, which fails closed by also lexing the other way.
// Statements and Lexings are the one scanner the transaction-control guard and the operationtest
// Contract share, so a hiding place found in one is closed in both.
func Statements(sql string) []string { return scan(sql, false) }

// Lexings returns the statements of sql under every lexing PostgreSQL might apply: plain literals
// without backslash escapes (standard_conforming_strings = on) and with them (= off). When both agree
// there is one list, otherwise two. A guard reports a finding if ANY returned list holds one.
func Lexings(sql string) [][]string {
	std, bs := scan(sql, false), scan(sql, true)
	if equalStrings(std, bs) {
		return [][]string{std}
	}
	return [][]string{std, bs}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// scan is the scanner; backslash makes a plain '…' literal honour backslash escapes.
func scan(sql string, backslash bool) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(sql); {
		c := sql[i]
		switch {
		case c == '\'':
			esc := i > 0 && (sql[i-1] == 'e' || sql[i-1] == 'E') && (i < 2 || !isIdentByte(sql[i-2]))
			esc = esc || backslash
			i = skipQuoted(sql, i, '\'', esc)
			for {
				next, ok := continuation(sql, i)
				if !ok {
					break
				}
				i = skipQuoted(sql, next, '\'', esc)
			}
			cur.WriteString("''")
		case c == '"':
			i = skipQuoted(sql, i, '"', false)
			cur.WriteString("''")
		case c == '$' && (i == 0 || !isIdentByte(sql[i-1])):
			tag, ok := dollarTag(sql[i:])
			if !ok {
				cur.WriteByte(c)
				i++
				continue
			}
			rest := sql[i+len(tag):]
			if j := strings.Index(rest, tag); j >= 0 {
				i += len(tag) + j + len(tag)
			} else {
				i = len(sql)
			}
			cur.WriteString("''")
		case strings.HasPrefix(sql[i:], "--"):
			j := strings.IndexAny(sql[i:], "\r\n")
			cur.WriteByte(' ')
			if j < 0 {
				i = len(sql)
			} else {
				i += j
			}
		case strings.HasPrefix(sql[i:], "/*"):
			depth := 1
			i += 2
			for i < len(sql) && depth > 0 {
				switch {
				case strings.HasPrefix(sql[i:], "/*"):
					depth++
					i += 2
				case strings.HasPrefix(sql[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
			}
			cur.WriteByte(' ')
		case c == ';':
			flush()
			i++
		default:
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return out
}

// skipQuoted returns the index after the quoted run that opens at s[i]. A doubled quote is an escaped
// quote; with esc a backslash also escapes the next byte.
func skipQuoted(s string, i int, q byte, esc bool) int {
	for j := i + 1; j < len(s); j++ {
		switch {
		case esc && s[j] == '\\':
			j++
		case s[j] == q:
			if j+1 < len(s) && s[j+1] == q {
				j++
				continue
			}
			return j + 1
		}
	}
	return len(s)
}

// continuation reports whether the literal that ended at i is continued: PostgreSQL joins 'a' and 'b'
// when only horizontal space, a newline (CR or LF) and further whitespace or "--" comments, each ending
// at a newline, lie between them. It returns the index of the second literal's opening quote.
func continuation(s string, i int) (int, bool) {
	j := i
	for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\f') {
		j++
	}
	if j >= len(s) || (s[j] != '\n' && s[j] != '\r') {
		return 0, false
	}
	for j < len(s) {
		switch {
		case s[j] == ' ' || s[j] == '\t' || s[j] == '\f' || s[j] == '\n' || s[j] == '\r':
			j++
		case strings.HasPrefix(s[j:], "--"):
			k := strings.IndexAny(s[j:], "\r\n")
			if k < 0 {
				return 0, false
			}
			j += k + 1
		default:
			if s[j] == '\'' {
				return j, true
			}
			return 0, false
		}
	}
	return 0, false
}

// dollarTag returns the opening tag ("$$" or "$name$") at the start of s. A parameter such as $1 is not one.
func dollarTag(s string) (string, bool) {
	for j := 1; j < len(s); j++ {
		switch {
		case s[j] == '$':
			return s[:j+1], true
		case isIdentByte(s[j]) && s[j] != '$' && !(j == 1 && s[j] >= '0' && s[j] <= '9'):
		default:
			return "", false
		}
	}
	return "", false
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '$' || b >= 0x80 || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// IsTxControl reports whether sql contains a statement that starts or ends a transaction or a
// savepoint. It looks at the first word of every statement under every lexing (see Lexings).
func IsTxControl(sql string) bool {
	for _, lexing := range Lexings(sql) {
		for _, stmt := range lexing {
			if isTxControlStmt(strings.Fields(stmt)) {
				return true
			}
		}
	}
	return false
}

// IsTxControlStatement reports whether one statement from Statements is transaction control.
func IsTxControlStatement(stmt string) bool { return isTxControlStmt(strings.Fields(stmt)) }

func isTxControlStmt(f []string) bool {
	if len(f) == 0 {
		return false
	}
	switch strings.ToUpper(f[0]) {
	case "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "BEGIN", "START", "END", "ABORT":
		return true
	case "PREPARE":
		return len(f) > 1 && strings.EqualFold(f[1], "TRANSACTION")
	}
	return false
}
