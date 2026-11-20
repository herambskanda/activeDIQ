package search

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
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

// ChipKind is the contract's DirectorySearchChipKind.
type ChipKind string

// The chip kinds of the contract.
const (
	ChipLocked                ChipKind = "locked"
	ChipDisabled              ChipKind = "disabled"
	ChipPasswordExpired       ChipKind = "passwordExpired"
	ChipPasswordExpiresInDays ChipKind = "passwordExpiresInDays"
	ChipAccountExpires        ChipKind = "accountExpires"
	ChipDeleted               ChipKind = "deleted"
	ChipTier0                 ChipKind = "tier0"
	ChipCloudOnly             ChipKind = "cloudOnly"
)

// PasswordExpiryWarnDays is the window in which "password expires in N days" is worth a chip: the days Windows
// itself warns before expiry on a domain-joined machine. A password further from expiry has no chip, so a row
// that shows nothing means nothing needs attention. [PROPOSED] product may change it.
const PasswordExpiryWarnDays = 14

// Chip is one status chip. At is set for locked, accountExpires and deleted when the time is known; Days for
// passwordExpiresInDays.
type Chip struct {
	Kind ChipKind
	At   time.Time
	Days *int64
}

// chips builds the chips of a hit from stored facts only. The order is the contract's "most urgent first".
// The locked, password and account-expiry facts come from the inventory.users derivation (inventory
// .SearchStatus); this function only decides which of them are worth a chip, and holds no policy rule.
func chips(h reportsql.SearchHit, st inventory.SearchStatus, now time.Time) []Chip {
	out := []Chip{}
	switch h.State {
	case "deleted", "recycled", "purged", "soft_deleted":
		out = append(out, Chip{Kind: ChipDeleted})
	}
	if st.Tier0 {
		out = append(out, Chip{Kind: ChipTier0})
	}
	if st.Locked {
		out = append(out, Chip{Kind: ChipLocked, At: st.LockedAt})
	}
	if h.Enabled != nil && !*h.Enabled {
		out = append(out, Chip{Kind: ChipDisabled})
	}
	if st.PasswordExpired {
		out = append(out, Chip{Kind: ChipPasswordExpired})
	}
	if !st.AccountExpires.IsZero() {
		out = append(out, Chip{Kind: ChipAccountExpires, At: st.AccountExpires})
	}
	if d := st.PasswordExpiresInDays; d != nil && *d >= 0 && *d <= PasswordExpiryWarnDays {
		out = append(out, Chip{Kind: ChipPasswordExpiresInDays, Days: d})
	}
	if st.CloudOnly {
		out = append(out, Chip{Kind: ChipCloudOnly})
	}
	return out
}

// present builds the row of a permitted hit. Everything on it is a stored fact of that object: no field is
// read from another object (a manager, a group), so a scope that hides one cannot show through.
func present(h reportsql.SearchHit, m inventory.SearchMeta, text string, now time.Time) Hit {
	out := Hit{Type: h.Group, Object: h.Object, DisplayName: h.DisplayName, Class: h.Class,
		SAMAccountName: m.SAMAccountName, UserPrincipalName: m.UserPrincipalName, Mail: m.Mail, DN: m.DN, Domain: domainOf(m.DN),
		Title: m.Title, Office: m.Office, Department: m.Department, Status: chips(h, m.Status, now)}
	out.Highlights = highlights(text, [][2]string{{FieldDisplayName, h.DisplayName}, {FieldSAM, m.SAMAccountName}, {FieldUPN, m.UserPrincipalName}, {FieldMail, m.Mail}})
	return out
}

// hideSingleDomain clears Domain on every hit unless the answer spans more than one domain: the domain is
// there to tell two objects with one name apart, and a caller who sees one domain does not need it. It looks
// only at permitted hits, so it reveals nothing the scope hides.
func hideSingleDomain(groups []Group) {
	seen := map[string]bool{}
	for _, g := range groups {
		for _, h := range g.Items {
			if h.Domain != "" {
				seen[h.Domain] = true
			}
		}
	}
	if len(seen) > 1 {
		return
	}
	for gi := range groups {
		for hi := range groups[gi].Items {
			groups[gi].Items[hi].Domain = ""
		}
	}
}
