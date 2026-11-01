// Package searchkey is the one place that normalises search text (ADR-0011 rule 7). The sync writer
// builds the stored keys with it and the search path normalises and classifies the query with it, so the
// two cannot drift apart. It is a leaf: standard library and golang.org/x/text only.
package searchkey

import (
	"errors"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// Version is stored with every key. Any change to a normalisation rule bumps it; the backfill then
// rewrites the keys that carry an older number (ADR-0011 rule 5).
const Version = 1

// The refusals of rule 7, in the order they are checked. None carries the text.
var (
	ErrInvalidUTF8      = errors.New("searchkey: text is not valid UTF-8")
	ErrNUL              = errors.New("searchkey: text holds a NUL")
	ErrTooLong          = errors.New("searchkey: text is longer than 4 KiB")
	ErrTooManyRunes     = errors.New("searchkey: text is longer than 256 characters")
	ErrRecoveryPassword = errors.New("searchkey: text has the shape of a recovery password")
	ErrEmpty            = errors.New("searchkey: text is empty")
)

// Limits of rule 7.
const (
	MaxBytes = 4096
	MaxRunes = 256
	// recoveryDigits is the run of decimal digits that makes a BitLocker recovery password (48).
	recoveryDigits = 48
)

// Prepare applies the refusals of rule 7 in order and returns the NFKC form, which every later check
// and step sees. Raw bytes first (invalid UTF-8, NUL, > 4 KiB, which bounds the work NFKC can be asked
// to do), then NFKC, then on the NFKC form the rune cap and the recovery-password shape.
func Prepare(raw string) (string, error) {
	if len(raw) > MaxBytes {
		return "", ErrTooLong
	}
	if !utf8.ValidString(raw) {
		return "", ErrInvalidUTF8
	}
	if strings.IndexByte(raw, 0) >= 0 {
		return "", ErrNUL
	}
	s := norm.NFKC.String(raw)
	if utf8.RuneCountInString(s) > MaxRunes {
		return "", ErrTooManyRunes
	}
	if recoveryShape(s) {
		return "", ErrRecoveryPassword
	}
	return s, nil
}

// recoveryShape: after removing whitespace and every dash (unicode.Pd), the text holds a run of 48 or
// more decimal digits (unicode.Nd, so other scripts' digits count; NFKC has already made full-width
// digits ASCII).
func recoveryShape(s string) bool {
	run := 0
	for _, r := range s {
		switch {
		case unicode.IsSpace(r) || unicode.Is(unicode.Pd, r):
			continue
		case unicode.Is(unicode.Nd, r):
			run++
			if run >= recoveryDigits {
				return true
			}
		default:
			run = 0
		}
	}
	return false
}

var foldPool = sync.Pool{New: func() any { c := cases.Fold(); return &c }}

func fold(s string) string {
	c := foldPool.Get().(*cases.Caser)
	c.Reset()
	out := c.String(s)
	foldPool.Put(c)
	// Full folding maps some scripts (Cherokee) to their upper-case form, so "Ꮀ" and "ꮀ" would key
	// differently; a final lower-case map makes every spelling reach one key.
	return strings.ToLower(out)
}

// letters that do not decompose, all lower case (case folding comes first, so the table needs no upper
// case); U+00B7 (middle dot) is deleted.
var letterTable = map[rune]string{
	'ł': "l", 'đ': "d", 'ø': "o", 'ħ': "h", 'ı': "i", 'æ': "ae", 'œ': "oe", 'þ': "th", '·': "",
}

// NormName is the key and query form of a name (rule 7): NFKC, full case folding, NFD, combining marks
// removed, the letter table, NFC, then , . - ' _ ( ) become a space, runs of white space collapse and the
// result is trimmed. It does not refuse anything; run Prepare on a query first.
func NormName(s string) string {
	s = fold(norm.NFKC.String(s))
	s = norm.NFD.String(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		if rep, ok := letterTable[r]; ok {
			b.WriteString(rep)
			continue
		}
		b.WriteRune(r)
	}
	s = norm.NFC.String(b.String())
	return collapse(strings.Map(func(r rune) rune {
		switch r {
		case ',', '.', '-', '\'', '_', '(', ')':
			return ' '
		}
		return r
	}, s))
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// NormIdent is the key and query form of an identifier: NFKC, full case folding, trimmed. Its
// punctuation is kept.
func NormIdent(s string) string {
	return strings.TrimSpace(fold(norm.NFKC.String(s)))
}

// NormDN is NormIdent with the white space after an RDN separator removed, so "CN=a, DC=b" and
// "CN=a,DC=b" are one key.
func NormDN(s string) string {
	s = NormIdent(s)
	var b strings.Builder
	esc := false
	sep := false
	for _, r := range s {
		if sep && unicode.IsSpace(r) {
			continue
		}
		sep = false
		b.WriteRune(r)
		switch {
		case esc:
			esc = false
		case r == '\\':
			esc = true
		case r == ',' || r == ';':
			sep = true
		}
	}
	return b.String()
}

// Words are the distinct words of a normalised name, at least two characters each, at most maxWords.
// A one-word name has none: its name key already is the word.
func Words(name string) []string {
	const maxWords = 16
	fs := strings.Fields(name)
	if len(fs) < 2 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, w := range fs {
		if utf8.RuneCountInString(w) < 2 || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, w)
		if len(out) == maxWords {
			break
		}
	}
	return out
}

// PrefixUpper returns the exclusive upper bound of the keys that start with prefix, under byte (code
// point) order: the prefix with its last code point incremented. U+D7FF goes to U+E000 (the surrogates
// are not valid in UTF-8), U+10FFFF cannot be incremented so it is dropped and the one before it is,
// and a prefix of nothing but U+10FFFF has no upper bound (bounded false).
func PrefixUpper(prefix string) (hi string, bounded bool) {
	rs := []rune(prefix)
	for len(rs) > 0 {
		last := rs[len(rs)-1]
		switch {
		case last == 0x10FFFF:
			rs = rs[:len(rs)-1]
			continue
		case last == 0xD7FF:
			rs[len(rs)-1] = 0xE000
		default:
			rs[len(rs)-1] = last + 1
		}
		return string(rs), true
	}
	return "", false
}
