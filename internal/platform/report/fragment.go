package report

import (
	"strings"
)

// Fragment is constant SQL with slots, the only free-form SQL a dataset may carry (contract §3.3).
// Build it only with SQL and a compile-time constant: the FF-SP2 sqlconst analyzer (RP1) fails a
// call whose argument is not constant. A Fragment is never built from a request.
//
// Slots, filled by reportsql: {t} the base alias, {now} the run's bound now, {rel.<id>} a declared
// relation, {in_scope.<anchor>} a MaskAnchor's scope flag. A fragment names no table.
type Fragment struct{ text string }

// SQL builds a Fragment. text must be a compile-time constant.
func SQL(text string) Fragment { return Fragment{text: text} }

// IsZero reports whether f is the empty fragment.
func (f Fragment) IsZero() bool { return f.text == "" }

// String returns the fragment text with its slots unexpanded. It is for diagnostics and for the
// registry that expands it; it is not SQL.
func (f Fragment) String() string { return f.text }

// SlotKind says what a fragment slot is.
type SlotKind uint8

const (
	SlotLiteral SlotKind = iota // constant SQL text
	SlotBase                    // {t}
	SlotNow                     // {now}
	SlotRel                     // {rel.<id>}
	SlotInScope                 // {in_scope.<anchor>}
)

// Part is one piece of a parsed fragment: literal SQL, or a slot with its anchor/relation ID.
type Part struct {
	Kind SlotKind
	Text string   // SlotLiteral only
	ID   AnchorID // SlotRel and SlotInScope
}

// Parts splits the fragment into literal text and slots. It returns an error for anything §3.3
// forbids: a semicolon, a comment opener, a dollar sign (bind parameters are the compiler's), an
// unknown or malformed slot, unbalanced parentheses or quotes.
func (f Fragment) Parts() ([]Part, error) {
	s := f.text
	if strings.TrimSpace(s) == "" {
		return nil, verr(CodeInvalidDataset, "fragment")
	}
	for _, bad := range []string{";", "--", "/*", "*/", "$", "\x00", "\\"} {
		if strings.Contains(s, bad) {
			return nil, verrf(CodeInvalidDataset, "fragment", "contains %q", bad)
		}
	}
	if strings.Count(s, "'")%2 != 0 || strings.ContainsAny(s, "\"`") {
		return nil, verrf(CodeInvalidDataset, "fragment", "unbalanced or quoted identifier; quote nothing, slots do that")
	}
	var parts []Part
	depth := 0
	lit := strings.Builder{}
	flush := func() {
		if lit.Len() > 0 {
			parts = append(parts, Part{Kind: SlotLiteral, Text: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '(':
			depth++
			lit.WriteByte(c)
		case ')':
			depth--
			if depth < 0 {
				return nil, verrf(CodeInvalidDataset, "fragment", "unbalanced parentheses")
			}
			lit.WriteByte(c)
		case '}':
			return nil, verrf(CodeInvalidDataset, "fragment", "stray }")
		case '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return nil, verrf(CodeInvalidDataset, "fragment", "unterminated slot")
			}
			name := s[i+1 : i+end]
			p, err := parseSlot(name)
			if err != nil {
				return nil, err
			}
			flush()
			parts = append(parts, p)
			i += end
		default:
			lit.WriteByte(c)
		}
	}
	if depth != 0 {
		return nil, verrf(CodeInvalidDataset, "fragment", "unbalanced parentheses")
	}
	flush()
	return parts, nil
}

func parseSlot(name string) (Part, error) {
	switch name {
	case "t":
		return Part{Kind: SlotBase}, nil
	case "now":
		return Part{Kind: SlotNow}, nil
	}
	if id, ok := strings.CutPrefix(name, "rel."); ok && AnchorID(id).Valid() {
		return Part{Kind: SlotRel, ID: AnchorID(id)}, nil
	}
	if id, ok := strings.CutPrefix(name, "in_scope."); ok && AnchorID(id).Valid() {
		return Part{Kind: SlotInScope, ID: AnchorID(id)}, nil
	}
	return Part{}, verrf(CodeInvalidDataset, "fragment", "unknown slot {%s}", name)
}
