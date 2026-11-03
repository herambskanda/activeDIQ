package search

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
)

// typeName is the contract's name of a group.
func typeName(t reportsql.SearchType) string {
	switch t {
	case reportsql.TypeUser:
		return "users"
	case reportsql.TypeGroup:
		return "groups"
	case reportsql.TypeComputer:
		return "computers"
	case reportsql.TypeContact:
		return "contacts"
	}
	return ""
}

// ParseType maps the contract's type facet to a group; ok is false for an unknown name.
func ParseType(s string) (reportsql.SearchType, bool) {
	for _, t := range reportsql.AllSearchTypes {
		if typeName(t) == s {
			return t, true
		}
	}
	return 0, false
}

// TypeName is the contract's name of a group ("users", "groups", "computers", "contacts").
func TypeName(t reportsql.SearchType) string { return typeName(t) }

// Highlight is a matched stretch of one field, in code points (contract DirectorySearchHighlight).
type Highlight struct {
	Field         string
	Start, Length int
}

// Highlight fields.
const (
	FieldDisplayName = "displayName"
	FieldSAM         = "samAccountName"
	FieldUPN         = "userPrincipalName"
	FieldMail        = "mail"
)

const maxHighlights = 16

// highlights finds where the typed text occurs, ignoring case, in the fields a row shows. It marks only
// what is literally there: a fuzzy or accent-folded match with no literal occurrence gets none, which the
// contract allows ("a hit that matched on a key the row does not show has no highlight"). The whole text is
// looked for first, then each word of two or more characters.
func highlights(text string, fields [][2]string) []Highlight {
	text = strings.TrimSpace(text)
	needles := []string{text}
	if strings.ContainsAny(text, " \t") {
		for _, w := range strings.Fields(text) {
			if utf8.RuneCountInString(w) >= 2 {
				needles = append(needles, w)
			}
		}
	}
	out := []Highlight{}
	for _, f := range fields {
		hay := lowerRunes(f[1])
		if len(hay) == 0 {
			continue
		}
		used := make([]bool, len(hay))
		for _, n := range needles {
			nr := lowerRunes(n)
			if len(nr) == 0 {
				continue
			}
			for i := 0; i+len(nr) <= len(hay); i++ {
				if !equalRunes(hay[i:i+len(nr)], nr) || anyUsed(used[i:i+len(nr)]) {
					continue
				}
				for k := i; k < i+len(nr); k++ {
					used[k] = true
				}
				if i <= 1024 && len(nr) <= 1024 && len(out) < maxHighlights {
					out = append(out, Highlight{Field: f[0], Start: i, Length: len(nr)})
				}
				i += len(nr) - 1
			}
		}
	}
	return out
}

func lowerRunes(s string) []rune {
	r := []rune(s)
	for i, c := range r {
		r[i] = unicode.ToLower(c)
	}
	return r
}

func equalRunes(a, b []rune) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func anyUsed(u []bool) bool {
	for _, b := range u {
		if b {
			return true
		}
	}
	return false
}

// domainOf is the DNS name of the domain a DN lives in: its trailing run of DC components, dotted. A DN that
// does not parse, or holds none, has no domain, and says so with "" rather than a guess.
func domainOf(dnText string) string {
	d, err := dn.Parse(dnText, dn.Strict)
	if err != nil {
		return ""
	}
	rdns := d.RDNs()
	var parts []string
	for i := len(rdns) - 1; i >= 0; i-- {
		if rdns[i].Type() != dn.DC {
			break
		}
		parts = append([]string{strings.ToLower(rdns[i].Value())}, parts...)
	}
	return strings.Join(parts, ".")
}
