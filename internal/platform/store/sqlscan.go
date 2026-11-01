package store

import "strings"

// Statements splits sql into its ';'-separated statements for inspection (never for execution). Every
// comment ("--" and nested "/* */") becomes a space, and the content of every quoted run (a '…' literal,
// an E'…' literal with backslash escapes, a "…" identifier and a $tag$…$tag$ body) is replaced by an
// empty ” so a ';', an apostrophe or a keyword inside quotes can neither split nor hide a statement.
// An unterminated comment or quote hides the rest of the text, as it does for PostgreSQL. Empty
// statements are dropped. It is the one scanner the transaction-control guard and the operationtest
// Contract share, so a hiding place found in one is closed in both.
func Statements(sql string) []string {
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
			i = skipQuoted(sql, i, '\'', esc)
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
			j := strings.IndexByte(sql[i:], '\n')
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
// savepoint. It looks at the first word of every statement (see Statements).
func IsTxControl(sql string) bool {
	for _, stmt := range Statements(sql) {
		if isTxControlStmt(strings.Fields(stmt)) {
			return true
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
