// Package cellsafe is the one formula-lead classifier (safe-primitives §12.2, O4). The CSV writer,
// the XLSX writer and the CSV reader's inverse all ask it; nothing else in the product decides
// whether a cell could be read as a formula, and FF-SP3 bans ad-hoc HasPrefix checks elsewhere.
package cellsafe

import (
	"unicode"
	"unicode/utf8"
)

// Class is the verdict of Classify.
type Class uint8

const (
	// Plain: no spreadsheet reads this as a formula.
	Plain Class = iota
	// FormulaLead: a spreadsheet might read this as a formula and it must be neutralised.
	FormulaLead
)

// Classify returns FormulaLead when the first scalar is TAB, CR or LF, or when, after skipping
// leading scalars that are Unicode White_Space, Cc or Cf, the first remaining scalar is in
// FormulaLeadTable. No value is ever normalised (R4). Invalid UTF-8 bytes classify as the
// replacement character, which is Plain.
func Classify(s string) Class {
	if s == "" {
		return Plain
	}
	if s[0] == '\t' || s[0] == '\r' || s[0] == '\n' {
		return FormulaLead
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if isLead(r) {
			return FormulaLead
		}
		return Plain
	}
	return Plain
}

// StartsWithTab reports whether s begins with the CSV neutraliser (U+0009). Exposed so the CSV
// reader's inverse needs no HasPrefix check of its own.
func StartsWithTab(s string) bool { return s != "" && s[0] == '\t' }

func isLead(r rune) bool {
	if r == utf8.RuneError {
		return false
	}
	lo, hi := 0, len(FormulaLeadTable)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		switch {
		case FormulaLeadTable[m] == r:
			return true
		case FormulaLeadTable[m] < r:
			lo = m + 1
		default:
			hi = m
		}
	}
	return false
}
