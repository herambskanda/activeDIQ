package ldapfilter

import (
	"slices"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
)

// Syntax is the value family an attribute takes. Value kind must match it (§3.3 rule 3): a dashed
// GUID string against objectGUID would silently match nothing.
type Syntax int

const (
	SynString  Syntax = iota + 1 // Unicode, Directory, IA5 and Printable strings
	SynOctet                     // opaque octet string
	SynGUID                      // objectGUID and friends: Value.GUID only
	SynSID                       // objectSid, sIDHistory: Value.SID only
	SynDN                        // distinguished-name syntax: Value.DN only, no substrings
	SynInt32                     // Integer (also the bit-mask attributes)
	SynInt64                     // Large Integer / Integer8, FILETIME and intervals
	SynGenTime                   // Generalized Time
	SynBool                      // Boolean
)

// AttrInfo is what the builder needs to know about one schema attribute.
type AttrInfo struct {
	Name        string // ldapDisplayName; must not be OID-shaped (such entries are dropped)
	OID         string // attributeID (numericoid), optional; an alias for the same entry, never a second one
	Syntax      Syntax
	Constructed bool // systemFlags & FLAG_ATTR_IS_CONSTRUCTED (0x4): cannot be filtered (gotcha 12)
	Secret      bool // in SecretAttrs (§3.7): never filtered by this package
}

// Schema is the allowlist read at connect (gotcha 15). Lookup is case-insensitive, as LDAP attribute
// names are.
type Schema struct {
	byName map[string]AttrInfo
	byOID  map[string]string // numericoid -> lower-case ldapDisplayName
}

// NewSchema builds a schema. Attributes on the static secret list are marked Secret whatever the
// caller says; the schema-flagged half of SecretAttrs is the caller's to set.
func NewSchema(attrs ...AttrInfo) *Schema {
	s := &Schema{byName: make(map[string]AttrInfo, len(attrs)), byOID: map[string]string{}}
	static := secretattr.Static()
	groups := map[string][]string{} // numericoid -> every lower-case name claiming it
	for _, a := range attrs {
		// An OID-shaped Name would be a second, unclassified entry for an attribute AD resolves by
		// OID; fail closed by not admitting it. Register the OID in AttrInfo.OID instead.
		if c := a.Name; c == "" || c[0] >= '0' && c[0] <= '9' {
			continue
		}
		if slices.ContainsFunc(static, func(n string) bool { return strings.EqualFold(n, a.Name) }) {
			a.Secret = true
		}
		key := strings.ToLower(a.Name)
		if prev, dup := s.byName[key]; dup {
			// Same ldapDisplayName in another case: merge, never replace. Fail closed, so a later
			// unflagged duplicate cannot downgrade a Secret or Constructed entry (T-0121).
			a.Secret = a.Secret || prev.Secret
			a.Constructed = a.Constructed || prev.Constructed
			if a.OID == "" {
				a.OID = prev.OID
			}
			a.Name = prev.Name
			a.Syntax = prev.Syntax // first claim wins; only the flags merge upward
		}
		s.byName[key] = a
		if a.OID != "" {
			if o, err := parseAttrGrammar(a.OID); err == nil && a.OID[0] >= '0' && a.OID[0] <= '9' {
				if _, dup := s.byOID[o.name]; !dup {
					s.byOID[o.name] = key
				}
				if !slices.Contains(groups[o.name], key) {
					groups[o.name] = append(groups[o.name], key)
				}
			}
		}
	}
	// Every name sharing an OID inherits the OR of their Secret/Constructed. A name can sit in two
	// groups (a case-variant duplicate that brought a different OID), so one pass in map order is
	// not enough: repeat to the fixpoint. Flags only ever turn on, so the fixpoint is unique and
	// the result is deterministic whatever the order. The first claimant keeps the alias.
	for changed := true; changed; {
		changed = false
		for _, keys := range groups {
			var sec, con bool
			for _, k := range keys {
				sec, con = sec || s.byName[k].Secret, con || s.byName[k].Constructed
			}
			for _, k := range keys {
				e := s.byName[k]
				if e.Secret != sec || e.Constructed != con {
					e.Secret, e.Constructed = sec, con
					s.byName[k] = e
					changed = true
				}
			}
		}
	}
	return s
}

func (s *Schema) lookup(name string) (AttrInfo, bool) {
	if s == nil {
		return AttrInfo{}, false
	}
	a, ok := s.byName[strings.ToLower(name)]
	return a, ok
}

// AttrName is a validated attribute name: an RFC 4512 descr or numericoid with no options. The zero
// value is invalid. Obtain one from ParseAttrName.
type AttrName struct{ name string }

// String returns the name as parsed.
func (a AttrName) String() string { return a.name }

// ParseAttrName accepts RFC 4512 descr (ALPHA *(ALPHA / DIGIT / "-")) or numericoid, refuses options
// (";binary"), and requires the attribute to be in the schema. LF-19, LF-20.
func ParseAttrName(s string, sc *Schema) (AttrName, error) {
	n, err := parseAttrGrammar(s)
	if err != nil {
		return AttrName{}, err
	}
	if sc != nil {
		if key, isOID := sc.byOID[n.name]; isOID {
			// Resolve to the one schema entry so Secret/Constructed apply and the
			// ldapDisplayName is what gets rendered.
			n.name = sc.byName[key].Name
		}
	}
	if _, ok := sc.lookup(n.name); !ok {
		return AttrName{}, fail(UnknownAttribute)
	}
	return n, nil
}

func parseAttrGrammar(s string) (AttrName, error) {
	if strings.Contains(s, ";") {
		return AttrName{}, fail(AttributeOptionsNotAllowed)
	}
	if s == "" || len(s) > 128 {
		return AttrName{}, fail(InvalidAttributeName)
	}
	if c := s[0]; c >= '0' && c <= '9' { // numericoid: digits and single dots, no leading zero in an arc
		prevDot := true
		for i := 0; i < len(s); i++ {
			switch c := s[i]; {
			case c == '.':
				if prevDot {
					return AttrName{}, fail(InvalidAttributeName)
				}
				prevDot = true
			case c >= '0' && c <= '9':
				if prevDot && c == '0' && i+1 < len(s) && s[i+1] != '.' {
					return AttrName{}, fail(InvalidAttributeName)
				}
				prevDot = false
			default:
				return AttrName{}, fail(InvalidAttributeName)
			}
		}
		if prevDot {
			return AttrName{}, fail(InvalidAttributeName)
		}
		return AttrName{s}, nil
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !alpha && (i == 0 || !(c >= '0' && c <= '9' || c == '-')) {
			return AttrName{}, fail(InvalidAttributeName)
		}
	}
	return AttrName{s}, nil
}
