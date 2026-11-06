package objects

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// NamePurpose is which name a NamingFormat derives (DM-51).
type NamePurpose string

// The five purposes.
const (
	PurposeSAMAccountName NamePurpose = "sAMAccountName"
	PurposeUPNPrefix      NamePurpose = "upnPrefix"
	PurposeCN             NamePurpose = "cn"
	PurposeDisplayName    NamePurpose = "displayName"
	PurposeMailAlias      NamePurpose = "mailAlias"
)

// Purposes lists every purpose, in the order a form shows them.
func Purposes() []NamePurpose {
	return []NamePurpose{PurposeSAMAccountName, PurposeUPNPrefix, PurposeCN, PurposeDisplayName, PurposeMailAlias}
}

// Valid reports whether p is one of the five.
func (p NamePurpose) Valid() bool {
	switch p {
	case PurposeSAMAccountName, PurposeUPNPrefix, PurposeCN, PurposeDisplayName, PurposeMailAlias:
		return true
	}
	return false
}

// TokenKind is the kind of one token of an alternative.
type TokenKind string

// Token kinds. There is no script or expression kind (DM-51.I3).
const (
	TokenAttr    TokenKind = "attr"    // a part of an input attribute
	TokenLiteral TokenKind = "literal" // fixed text
	TokenDigits  TokenKind = "digits"  // only the decimal digits of an input attribute
)

// Case is how a token's text is cased.
type Case string

// Cases. The zero value keeps the text as given.
const (
	CaseKeep  Case = ""
	CaseLower Case = "lower"
	CaseUpper Case = "upper"
	CaseTitle Case = "title"
)

// Token is one piece of a derived name. Take is how many characters to keep (0 keeps all), counted from
// the start, or from the end when Last is set.
type Token struct {
	Kind    TokenKind `json:"kind"`
	Attr    string    `json:"attr,omitempty"`
	Literal string    `json:"literal,omitempty"`
	Take    int       `json:"take,omitempty"`
	Last    bool      `json:"last,omitempty"`
	Case    Case      `json:"case,omitempty"`
}

// Op is a condition operator. The zero value always holds.
type Op string

// Condition operators.
const (
	OpAlways    Op = ""
	OpEmpty     Op = "empty"
	OpNotEmpty  Op = "notEmpty"
	OpEquals    Op = "equals"
	OpNotEquals Op = "notEquals"
)

// Condition chooses an alternative from the input attributes. Equality is case-insensitive.
type Condition struct {
	Op    Op     `json:"op,omitempty"`
	Attr  string `json:"attr,omitempty"`
	Value string `json:"value,omitempty"`
}

// Alternative is a condition and the tokens that build the name when it holds.
type Alternative struct {
	When   Condition `json:"when"`
	Tokens []Token   `json:"tokens"`
}

// Collision is how a candidate name is varied after the DC reports the name taken.
type Collision string

// Collision styles.
const (
	CollisionNone    Collision = ""        // no variation: a taken name fails the item
	CollisionNumeric Collision = "numeric" // jsmith, jsmith2, jsmith3, ...
)

// NamingFormat is the data of a DM-51 format. Its identity and version live in the store.
type NamingFormat struct {
	Name            string        `json:"name"`
	Purpose         NamePurpose   `json:"purpose"`
	Alternatives    []Alternative `json:"alternatives"`
	CollisionSuffix Collision     `json:"collisionSuffix,omitempty"`
}

// ViolationError is a check failure that names the field it is about, so a Plan can block an item with
// a reason an administrator can act on.
type ViolationError struct {
	Field  string
	Reason string
}

func (e *ViolationError) Error() string { return e.Field + ": " + e.Reason }

func violation(field, format string, a ...any) error {
	return &ViolationError{Field: field, Reason: fmt.Sprintf(format, a...)}
}

// Validate reports why the format is malformed. It runs at save and publish, so Render never meets one.
func (f NamingFormat) Validate() error {
	if n := strings.TrimSpace(f.Name); n == "" || utf8.RuneCountInString(n) > 120 || hasControl(n) {
		return violation("name", "needs 1 to 120 printable characters")
	}
	if !f.Purpose.Valid() {
		return violation("purpose", "%q is not a naming purpose", f.Purpose)
	}
	if f.CollisionSuffix != CollisionNone && f.CollisionSuffix != CollisionNumeric {
		return violation("collisionSuffix", "%q is not a collision style", f.CollisionSuffix)
	}
	if len(f.Alternatives) == 0 || len(f.Alternatives) > 16 {
		return violation("alternatives", "needs between 1 and 16 alternatives")
	}
	for i, a := range f.Alternatives {
		fld := fmt.Sprintf("alternatives[%d]", i)
		if err := a.When.validate(fld + ".when"); err != nil {
			return err
		}
		if a.When.Op != OpAlways && i == len(f.Alternatives)-1 {
			return violation(fld+".when", "the last alternative must always apply, so a name can always be chosen")
		}
		if len(a.Tokens) == 0 || len(a.Tokens) > 16 {
			return violation(fld+".tokens", "needs between 1 and 16 tokens")
		}
		for j, t := range a.Tokens {
			if err := t.validate(fmt.Sprintf("%s.tokens[%d]", fld, j)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c Condition) validate(field string) error {
	switch c.Op {
	case OpAlways:
		if c.Attr != "" || c.Value != "" {
			return violation(field, "an always-true condition takes no attribute or value")
		}
	case OpEmpty, OpNotEmpty:
		if !validAttr(c.Attr) {
			return violation(field, "attribute %q is not a valid attribute name", c.Attr)
		}
	case OpEquals, OpNotEquals:
		if !validAttr(c.Attr) || c.Value == "" {
			return violation(field, "needs an attribute and a value")
		}
	default:
		return violation(field, "operator %q is unknown", c.Op)
	}
	return nil
}

func (t Token) validate(field string) error {
	if t.Take < 0 || t.Take > 64 {
		return violation(field, "take must be between 0 and 64")
	}
	switch t.Case {
	case CaseKeep, CaseLower, CaseUpper, CaseTitle:
	default:
		return violation(field, "case %q is unknown", t.Case)
	}
	switch t.Kind {
	case TokenAttr, TokenDigits:
		if !validAttr(t.Attr) || t.Literal != "" {
			return violation(field, "needs an attribute name and no literal")
		}
	case TokenLiteral:
		if t.Literal == "" || utf8.RuneCountInString(t.Literal) > 64 || t.Attr != "" || t.Take != 0 || hasControl(t.Literal) {
			return violation(field, "needs 1 to 64 printable characters and no attribute")
		}
	default:
		return violation(field, "kind %q is unknown", t.Kind)
	}
	return nil
}

// validAttr accepts an LDAP attribute description in its plain form: letters, digits and hyphens.
func validAttr(a string) bool {
	if a == "" || len(a) > 64 || !isLetter(a[0]) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if !isLetter(a[i]) && (a[i] < '0' || a[i] > '9') && a[i] != '-' {
			return false
		}
	}
	return true
}

func isLetter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

func hasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == utf8.RuneError }) >= 0
}

// Input is the attribute values a name is derived from. Keys are attribute names, matched without regard
// to case; only the first value counts.
type Input map[string]string

func (in Input) get(attr string) string {
	if v, ok := in[attr]; ok {
		return strings.TrimSpace(v)
	}
	for k, v := range in {
		if strings.EqualFold(k, attr) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (c Condition) holds(in Input) bool {
	v := in.get(c.Attr)
	switch c.Op {
	case OpEmpty:
		return v == ""
	case OpNotEmpty:
		return v != ""
	case OpEquals:
		return strings.EqualFold(v, c.Value)
	case OpNotEquals:
		return !strings.EqualFold(v, c.Value)
	}
	return true
}

// Limits are the per-call bounds Render checks against. SAMMax is the longest sAMAccountName the object
// class allows (20 for a user); the caller sets it from the class, this package does not guess it.
type Limits struct{ SAMMax int }

// DefaultLimits is the user-account limit.
var DefaultLimits = Limits{SAMMax: 20}

// ErrNoAlternative is returned when no alternative applies; a validated format cannot produce it.
var ErrNoAlternative = errors.New("objects: no naming alternative applies")

// Render derives the name from in. The first alternative whose condition holds is used; an attribute
// token whose attribute is empty blocks the item and names the attribute. The result is checked against
// DM-51.I1 for the format's purpose. The format is assumed validated.
func (f NamingFormat) Render(in Input, lim Limits) (string, error) {
	name, err := f.render(in)
	if err != nil {
		return "", err
	}
	if err := checkName(f.Purpose, name, lim); err != nil {
		return "", err
	}
	return name, nil
}

func (f NamingFormat) render(in Input) (string, error) {
	for _, a := range f.Alternatives {
		if !a.When.holds(in) {
			continue
		}
		var b strings.Builder
		for _, t := range a.Tokens {
			s, err := t.text(in)
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		}
		return b.String(), nil
	}
	return "", ErrNoAlternative
}

func (t Token) text(in Input) (string, error) {
	var s string
	switch t.Kind {
	case TokenLiteral:
		s = t.Literal
	case TokenAttr, TokenDigits:
		s = in.get(t.Attr)
		if t.Kind == TokenDigits {
			s = strings.Map(func(r rune) rune {
				if r >= '0' && r <= '9' {
					return r
				}
				return -1
			}, s)
		}
		if s == "" {
			return "", violation(t.Attr, "has no value to build the name from")
		}
	}
	if t.Take > 0 {
		rs := []rune(s)
		if len(rs) > t.Take {
			if t.Last {
				rs = rs[len(rs)-t.Take:]
			} else {
				rs = rs[:t.Take]
			}
		}
		s = string(rs)
	}
	switch t.Case {
	case CaseLower:
		s = strings.ToLower(s)
	case CaseUpper:
		s = strings.ToUpper(s)
	case CaseTitle:
		rs := []rune(strings.ToLower(s))
		if len(rs) > 0 {
			rs[0] = unicode.ToUpper(rs[0])
		}
		s = string(rs)
	}
	return s, nil
}

// samIllegal are the characters sAMAccountName may not contain (MS-ADTS 3.1.1.5.1.3 lists the set).
const samIllegal = "\"/\\[]:;|=,+*?<>@"

// upnIllegal adds the space and the parentheses a UPN prefix may not carry.
const upnIllegal = samIllegal + " ()"

// checkName is DM-51.I1: length and character rules per purpose, at Plan time. Escaping of an RDN value
// is the DN primitive's job at apply (P2), so CN only has to be non-empty, short enough and printable.
func checkName(p NamePurpose, name string, lim Limits) error {
	field := string(p)
	n := utf8.RuneCountInString(name)
	max := map[NamePurpose]int{PurposeUPNPrefix: 64, PurposeCN: 64, PurposeDisplayName: 256, PurposeMailAlias: 64}[p]
	if p == PurposeSAMAccountName {
		if lim.SAMMax <= 0 {
			lim = DefaultLimits
		}
		max = lim.SAMMax
	}
	switch {
	case n == 0:
		return violation(field, "the derived name is empty")
	case n > max:
		return violation(field, "%q is %d characters; the limit is %d", name, n, max)
	case hasControl(name):
		return violation(field, "contains a control or invalid character")
	case name != strings.TrimSpace(name):
		return violation(field, "starts or ends with a space")
	}
	switch p {
	case PurposeSAMAccountName:
		if i := strings.IndexAny(name, samIllegal); i >= 0 {
			return violation(field, "contains %q, which sAMAccountName does not allow", name[i:i+1])
		}
		if strings.HasSuffix(name, ".") {
			return violation(field, "must not end with a period")
		}
	case PurposeUPNPrefix:
		if i := strings.IndexAny(name, upnIllegal); i >= 0 {
			return violation(field, "contains %q, which a UPN prefix does not allow", name[i:i+1])
		}
	case PurposeCN:
		if strings.HasPrefix(name, "#") {
			return violation(field, "must not start with #")
		}
	case PurposeMailAlias:
		for _, r := range name {
			if !(r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-", r))) {
				return violation(field, "contains %q; a mail alias allows ASCII letters, digits, dot, underscore and hyphen", string(r))
			}
		}
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
			return violation(field, "must not start or end with a dot or contain two in a row")
		}
	}
	return nil
}

// Candidate returns the attempt-th name to try for base: attempt 0 is base itself, attempt n is base
// with the suffix n+1 for a numeric style (jsmith, jsmith2, jsmith3). The base is shortened so the
// whole name fits the purpose's limit, and the result is checked like a rendered one. A format with no
// collision style has only attempt 0. It never asks the directory whether the name is free: the DC's
// atomic create answers that (DM-51.I2).
func (f NamingFormat) Candidate(base string, attempt int, lim Limits) (string, error) {
	if attempt < 0 || (attempt > 0 && f.CollisionSuffix != CollisionNumeric) {
		return "", violation(string(f.Purpose), "the format has no collision suffix")
	}
	name := base
	if attempt > 0 {
		suffix := strconv.Itoa(attempt + 1)
		max := 64
		switch f.Purpose {
		case PurposeSAMAccountName:
			if lim.SAMMax <= 0 {
				lim = DefaultLimits
			}
			max = lim.SAMMax
		case PurposeDisplayName:
			max = 256
		}
		rs := []rune(base)
		if keep := max - len(suffix); len(rs) > keep {
			if keep < 1 {
				return "", violation(string(f.Purpose), "no room for the collision suffix")
			}
			rs = rs[:keep]
		}
		name = strings.TrimRight(string(rs), " .") + suffix
	}
	if err := checkName(f.Purpose, name, lim); err != nil {
		return "", err
	}
	return name, nil
}
