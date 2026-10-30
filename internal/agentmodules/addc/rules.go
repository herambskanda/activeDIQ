package addc

import (
	"strings"
	"unicode"
	"unicode/utf16"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
)

// Verdict is the whole output of the rule engine. It carries no text, so nothing about the candidate
// password can leak through it.
type Verdict uint8

// Verdicts. VerdictAccept is the zero value only by design of the callers; always compare explicitly.
const (
	VerdictAccept Verdict = iota
	VerdictTooShort
	VerdictTooLong
	VerdictTooFewClasses
	VerdictMissingClass
	VerdictBannedTerm
	VerdictContainsAccountName
	VerdictContainsDisplayNamePart
	VerdictMalformed // not valid UTF-16, or empty rules compiled from nothing
)

// Account is what the engine may compare the password with. Both are optional.
type Account struct {
	SAMAccountName string
	DisplayName    string
}

// Engine is a compiled password policy. It is immutable and safe for concurrent use.
type Engine struct {
	min, max   int
	required   []agentpolicy.Class
	minClasses int
	banned     []string // normalised, folded, non-empty
	sam, disp  bool
}

var fold = cases.Fold()

// normalise is NFKC then Unicode case folding, so the comparison does not depend on how a character
// was composed or cased.
func normalise(s string) string { return fold.String(norm.NFKC.String(s)) }

// Compile builds an Engine from a verified policy. Banned terms are literal substrings: no pattern
// language exists, so there is nothing to backtrack on (ReDoS next to LSASS).
func Compile(r agentpolicy.PasswordRules) *Engine {
	e := &Engine{min: int(r.MinLength), max: int(r.MaxLength), required: append([]agentpolicy.Class(nil), r.ClassesRequired...),
		minClasses: int(r.MinClasses), sam: r.RejectSAMInPassword, disp: r.RejectDisplayNameParts}
	for _, t := range r.BannedTerms {
		if n := normalise(t); n != "" {
			e.banned = append(e.banned, n)
		}
	}
	return e
}

func classOf(r rune) agentpolicy.Class {
	switch {
	case unicode.IsLower(r):
		return agentpolicy.ClassLower
	case unicode.IsUpper(r):
		return agentpolicy.ClassUpper
	case unicode.IsDigit(r):
		return agentpolicy.ClassDigit
	}
	return agentpolicy.ClassSymbol
}

// Evaluate checks a candidate password given as UTF-16 code units, the form LSA hands a password
// filter. It does not retain, copy out or log the password: the decoded runes live in a local buffer
// that is zeroed before return. Go strings are immutable and cannot be wiped, so the folded string
// needed for substring matching is built only when a term or name check is configured, and is dropped
// at once. This is residual exposure inside the filter process and is recorded in the threat model.
func (e *Engine) Evaluate(pw []uint16, acct Account) Verdict {
	runes := utf16.Decode(pw)
	defer clear(runes)
	for _, r := range runes {
		if r == unicode.ReplacementChar { // unpaired surrogate decodes to U+FFFD
			return VerdictMalformed
		}
	}
	if len(runes) < e.min {
		return VerdictTooShort
	}
	if len(runes) > e.max {
		return VerdictTooLong
	}
	var have [5]bool
	n := 0
	for _, r := range runes {
		c := classOf(r)
		if !have[c] {
			have[c] = true
			n++
		}
	}
	for _, c := range e.required {
		if int(c) < len(have) && !have[c] {
			return VerdictMissingClass
		}
	}
	if n < e.minClasses {
		return VerdictTooFewClasses
	}
	if len(e.banned) == 0 && !e.sam && !e.disp {
		return VerdictAccept
	}
	folded := normalise(string(runes))
	for _, b := range e.banned {
		if strings.Contains(folded, b) {
			return VerdictBannedTerm
		}
	}
	if e.sam {
		if s := normalise(acct.SAMAccountName); len(s) >= 3 && strings.Contains(folded, s) {
			return VerdictContainsAccountName
		}
	}
	if e.disp {
		for _, part := range strings.FieldsFunc(acct.DisplayName, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
			if p := normalise(part); len([]rune(p)) >= 3 && strings.Contains(folded, p) {
				return VerdictContainsDisplayNamePart
			}
		}
	}
	return VerdictAccept
}
