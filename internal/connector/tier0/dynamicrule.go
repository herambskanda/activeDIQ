package tier0

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ReasonDesignatedDynamicRule is the refusal reason for a property write that could change who a
// customer-designated dynamic group contains (TM-D25 rule 7).
const ReasonDesignatedDynamicRule = "designated_dynamic_rule"

// maxRuleLen bounds the lexer's input. Entra limits a rule to 3,072 characters
// (https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership); a longer
// one is not a rule Entra produced, so it is untokenisable.
const maxRuleLen = 8192

// TokenKind is a lexical class of the dynamic membership rule grammar
// (https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership).
type TokenKind int

const (
	TokPunct    TokenKind = iota + 1 // ( ) [ ] { } ,
	TokOperator                      // -eq, -and, -any, … (a leading '-' and a word)
	TokString                        // "…" with backtick escapes
	TokNumber                        // digits, optionally one '.' fraction
	TokProperty                      // user.x or device.x: a property of the object the rule matches
	TokIdent                         // any other dotted identifier (lambda variables, True, $null)
)

// Token is one lexeme. Text is the source text; for TokProperty it is "user.name" as written.
type Token struct {
	Kind TokenKind
	Text string
}

// Lex splits a membership rule into tokens. It does not evaluate and does not check the grammar
// beyond what tokenising needs: an unknown character, an unterminated string or a rule over the
// length bound is an error, and the caller then treats the rule as untokenisable (refuse every user
// property write).
func Lex(rule string) ([]Token, error) {
	if len(rule) > maxRuleLen {
		return nil, errors.New("membership rule exceeds the length bound")
	}
	var out []Token
	rs := []rune(rule)
	for i := 0; i < len(rs); {
		c := rs[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case strings.ContainsRune("()[]{},", c):
			out = append(out, Token{TokPunct, string(c)})
			i++
		case c == '"':
			j := i + 1
			for {
				if j >= len(rs) {
					return nil, errors.New("unterminated string in membership rule")
				}
				if rs[j] == '`' { // Entra escapes a double quote with a backtick
					if j+1 >= len(rs) {
						return nil, errors.New("unterminated string in membership rule")
					}
					j += 2
					continue
				}
				if rs[j] == '"' {
					break
				}
				j++
			}
			out = append(out, Token{TokString, string(rs[i : j+1])})
			i = j + 1
		case c == '-' && i+1 < len(rs) && isLetter(rs[i+1]):
			j := i + 1
			for j < len(rs) && isLetter(rs[j]) {
				j++
			}
			out = append(out, Token{TokOperator, string(rs[i:j])})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(rs) && (rs[j] >= '0' && rs[j] <= '9' || rs[j] == '.') {
				j++
			}
			out = append(out, Token{TokNumber, string(rs[i:j])})
			i = j
		case isLetter(c) || c == '_' || c == '$':
			j := i + 1
			for j < len(rs) && (isLetter(rs[j]) || rs[j] >= '0' && rs[j] <= '9' || rs[j] == '_' || rs[j] == '.') {
				j++
			}
			word := string(rs[i:j])
			if strings.HasSuffix(word, ".") || strings.Contains(word, "..") {
				return nil, fmt.Errorf("malformed identifier in membership rule")
			}
			head, _, dotted := strings.Cut(word, ".")
			if dotted && (strings.EqualFold(head, "user") || strings.EqualFold(head, "device")) {
				out = append(out, Token{TokProperty, word})
			} else {
				out = append(out, Token{TokIdent, word})
			}
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q in membership rule", c)
		}
	}
	return out, nil
}

func isLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

// RuleScope is what a closure dynamic group's rule says about property writes.
type RuleScope struct {
	// Properties are the lower-case "user.x" / "device.x" references of the rule.
	Properties map[string]bool
	// RefuseAll: the rule could not be fully tokenised, names a property absent from ruleprops v1,
	// is no recognised whole-rule form, or refers to group membership, so any property of any user
	// or device could change who is in the group (rule 7b).
	RefuseAll bool
	// MemberOf: the rule refers to group membership; group membership writes count too.
	MemberOf bool
	// User and Device: the kinds of object the rule can match (both when RefuseAll).
	User, Device bool
}

// ScopeOfRule extracts the properties a rule depends on. Nothing is evaluated.
func ScopeOfRule(rule string) RuleScope {
	sc := RuleScope{Properties: map[string]bool{}}
	toks, err := Lex(rule)
	if err != nil || len(toks) == 0 {
		// An empty rule on a dynamic group is also unreadable: refuse.
		sc.RefuseAll, sc.User, sc.Device = true, true, true
		return sc
	}
	known := false
	for i, t := range toks {
		// Whole-rule form 'Direct Reports for "{managerId}"' depends on user.manager (rule 7c).
		if t.Kind == TokIdent && strings.EqualFold(t.Text, "direct") && i+3 < len(toks) &&
			toks[i+1].Kind == TokIdent && strings.EqualFold(toks[i+1].Text, "reports") &&
			toks[i+2].Kind == TokIdent && strings.EqualFold(toks[i+2].Text, "for") && toks[i+3].Kind == TokString {
			sc.Properties["user.manager"] = true
			sc.User = true
			known = true
		}
		switch t.Kind {
		case TokProperty:
			lp := strings.ToLower(t.Text)
			sc.Properties[lp] = true
			if strings.HasPrefix(lp, "device.") {
				sc.Device = true
			} else {
				sc.User = true
			}
			if !knownRuleProperty(lp) {
				sc.RefuseAll = true // an unknown property cannot be proved harmless
			}
			if strings.Contains(lp, "memberof") {
				sc.RefuseAll, sc.MemberOf = true, true
			}
		case TokOperator, TokIdent:
			// "-memberOf" operator, or a bare memberOf word: membership of other groups drives this one.
			if strings.Contains(strings.ToLower(t.Text), "memberof") {
				sc.RefuseAll, sc.MemberOf = true, true
			}
		}
	}
	// A rule that tokenises but names no property and is no known whole-rule form is a shape we do
	// not understand: fail closed.
	if len(sc.Properties) == 0 && !known {
		sc.RefuseAll = true
	}
	if sc.RefuseAll {
		sc.User, sc.Device = true, true
	}
	return sc
}

// merge adds other into s.
func (s *RuleScope) merge(o RuleScope) {
	if s.Properties == nil {
		s.Properties = map[string]bool{}
	}
	for p := range o.Properties {
		s.Properties[p] = true
	}
	s.RefuseAll = s.RefuseAll || o.RefuseAll
	s.MemberOf = s.MemberOf || o.MemberOf
	s.User = s.User || o.User
	s.Device = s.Device || o.Device
}

// DynamicClosure is one dynamic group found in a designated closure (rule 7a), as carried in the
// guard input: the group, the kinds of object its rule matches and a hash of the rule seen.
type DynamicClosure struct {
	GroupID      string
	User, Device bool
	RuleHash     string
	scope        RuleScope
}

func ruleHash(rule string) string {
	h := sha256.Sum256([]byte(rule))
	return hex.EncodeToString(h[:])
}

// DynamicClosure lists the closure's dynamic groups as of the snapshot.
func (s *Set) DynamicClosure() []DynamicClosure {
	if s == nil {
		return nil
	}
	return append([]DynamicClosure(nil), s.dyn...)
}

// Plane is the directory a property write lands on.
type Plane int

const (
	PlaneEntra Plane = iota + 1 // keys are Graph PATCH keys
	PlaneAD                     // keys are LDAP attribute names
)

// WriteKind is the kind of directory object a property write targets.
type WriteKind int

const (
	WriteUser WriteKind = iota + 1
	WriteDevice
	WriteGroup
)

// Op is the operation of a property write (connector contract §8.9).
type Op int

const (
	OpUpdate Op = iota + 1
	OpCreate
	OpInvite
	OpAssignLicense
	OpSetManager
	OpClearManager
	OpMoveOrRename
	OpGroupMembership
	OpDelete // AD only (contract §8.9, T-1621): removes the object; Keys are empty and ignored
)

func (o Op) String() string {
	names := [...]string{"", "UPDATE", "CREATE", "INVITE", "ASSIGN_LICENSE", "SET_MANAGER", "CLEAR_MANAGER", "MOVE_OR_RENAME", "GROUP_MEMBERSHIP", "DELETE"}
	if o < 1 || int(o) >= len(names) {
		return "UNKNOWN"
	}
	return names[o]
}

// PropertyWrite is what a write kind declares it does (contract §8.9). Keys are Graph PATCH keys
// on the Entra plane and LDAP attribute names on the AD plane; never rule-side names, never values.
type PropertyWrite struct {
	Plane Plane
	Kind  WriteKind
	Op    Op
	Keys  []string
}

// Stage says which check refused.
type Stage int

const (
	StageConnectorSet Stage = iota + 1 // the closure as computed by the guard's own evidence
	StageLiveReread                    // the per-write re-read of the closure's rules
)

// DynamicRuleRefusal is the verdict of CheckPropertyWrite. Op and Keys echo the refused write
// (names only; values never reach this package).
type DynamicRuleRefusal struct {
	Refused bool
	Reason  string // ReasonDesignatedDynamicRule when Refused
	Stage   Stage
	Op      Op
	Keys    []string
}

// CheckPropertyWrite is the write path's check (TM-D25 rule 7, contract §8.9). It re-reads the rule
// of every dynamic group in the closure (a rule edited since the snapshot is seen; a read failure
// refuses and returns the error), then decides w against the merged live scope. There is no
// override. A set with no closure dynamic group refuses only a malformed write.
func (s *Set) CheckPropertyWrite(ctx context.Context, w PropertyWrite) (DynamicRuleRefusal, error) {
	refuse := func(st Stage, keys []string) DynamicRuleRefusal {
		return DynamicRuleRefusal{Refused: true, Reason: ReasonDesignatedDynamicRule, Stage: st, Op: w.Op, Keys: keys}
	}
	if s == nil || !validWrite(w) {
		return refuse(StageConnectorSet, nil), nil
	}
	if len(s.dyn) == 0 {
		return DynamicRuleRefusal{}, nil
	}
	if s.r == nil {
		return refuse(StageLiveReread, nil), errors.New("tier0: no reader to re-read the closure's membership rules")
	}
	var live RuleScope
	for _, d := range s.dyn {
		gid, err := objectID(d.GroupID)
		if err != nil {
			return refuse(StageLiveReread, nil), fmt.Errorf("tier0: dynamic group in the closure: %w", err)
		}
		g, err := s.r.GroupByID(ctx, gid)
		if err != nil {
			return refuse(StageLiveReread, nil), fmt.Errorf("tier0: re-read of dynamic group %s: %w", d.GroupID, err)
		}
		if g.MembershipRule == "" && !hasDynamic(g.GroupTypes) {
			// It stopped being dynamic since the snapshot. The snapshot still names it as a
			// closure member; keep its snapshot-time scope rather than trust a one-sided edit.
			live.merge(d.scope)
			continue
		}
		live.merge(ScopeOfRule(g.MembershipRule))
	}
	if keys := decide(w, live, s.extMap); keys != nil {
		return refuse(StageLiveReread, keys), nil
	}
	return DynamicRuleRefusal{}, nil
}

func validWrite(w PropertyWrite) bool {
	if w.Plane != PlaneEntra && w.Plane != PlaneAD {
		return false
	}
	switch w.Kind {
	case WriteUser, WriteDevice, WriteGroup:
	default:
		return false
	}
	for _, k := range w.Keys {
		if !canonicalKey(w.Plane, k) {
			return false
		}
	}
	switch w.Op {
	case OpUpdate, OpCreate, OpGroupMembership:
		return w.Op != OpGroupMembership || w.Kind == WriteGroup
	case OpInvite, OpAssignLicense:
		return w.Plane == PlaneEntra && (w.Kind == WriteUser || w.Op == OpAssignLicense && w.Kind == WriteGroup)
	case OpSetManager, OpClearManager:
		return w.Kind == WriteUser
	case OpMoveOrRename, OpDelete:
		return w.Plane == PlaneAD
	}
	return false
}

// canonicalKey accepts only plain attribute names: AD an ASCII letter then letters, digits or '-'
// (no ";binary" options, no numeric OIDs, no spaces); Entra an ASCII letter then letters, digits or
// '_', with at most one '.'-separated sub-key of the same form. Anything else could name a
// property the table does not (RFC 4512 §2.5), so it is refused.
func canonicalKey(plane Plane, k string) bool {
	if plane == PlaneAD {
		return identOK(k, '-')
	}
	head, sub, dotted := strings.Cut(k, ".")
	return identOK(head, '_') && (!dotted || identOK(sub, '_'))
}

func identOK(s string, extra byte) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !(letter || i > 0 && (c >= '0' && c <= '9' || c == extra)) {
			return false
		}
	}
	return s != ""
}

// decide applies the contract §8.9 decision table. It returns the keys to report (a non-nil empty
// slice when the refusal has no key) or nil when the write is allowed.
func decide(w PropertyWrite, sc RuleScope, ext map[string]string) []string {
	none := []string{}
	prefix := "user."
	if w.Kind == WriteDevice {
		prefix = "device."
	}
	switch w.Op {
	case OpUpdate:
		if len(w.Keys) == 0 {
			return nil
		}
		if sc.RefuseAll {
			return append([]string{}, w.Keys...)
		}
		if w.Kind == WriteGroup {
			return nil
		}
		var hit []string
		for _, k := range w.Keys {
			for _, rp := range reaches(w.Plane, prefix, k, ext) {
				if sc.Properties[rp] {
					hit = append(hit, k)
					break
				}
			}
		}
		if w.Plane == PlaneAD && prefix == "user." && unmappedExtension(sc, ext) {
			return append([]string{}, w.Keys...)
		}
		if len(hit) > 0 {
			return hit
		}
	case OpCreate, OpInvite:
		if w.Kind == WriteUser && sc.User || w.Kind == WriteDevice && sc.Device {
			return none
		}
	case OpAssignLicense:
		if sc.RefuseAll || sc.Properties["user.assignedplans"] || sc.Properties["user.mail"] || sc.Properties["user.proxyaddresses"] {
			return none
		}
	case OpSetManager, OpClearManager:
		if sc.RefuseAll || sc.Properties["user.manager"] {
			return none
		}
	case OpMoveOrRename:
		if sc.RefuseAll || sc.Properties[prefix+"onpremisesdistinguishedname"] || w.Kind == WriteDevice && sc.Properties["device.organizationalunit"] {
			return none
		}
	case OpDelete:
		// Deleting a group removes it from every member's memberOf, so a rule that reads membership
		// (a 'not memberOf' form) can start to match those members by absence (T-1621 R1). Any other
		// object only leaves a rule's scope; no other object's properties change. A memberOf rule is
		// RefuseAll, so the MemberOf and property tests are belt and braces.
		if w.Kind == WriteGroup && (sc.RefuseAll || sc.MemberOf || sc.Properties["user.memberof"]) {
			return none
		}
	case OpGroupMembership:
		// Group-based licensing: joining a licensed group assigns plans and can recalculate
		// mail/proxyAddresses, so those rule properties are reachable through membership.
		if sc.MemberOf || sc.RefuseAll || sc.Properties["user.assignedplans"] || sc.Properties["user.mail"] || sc.Properties["user.proxyaddresses"] {
			return none
		}
	}
	return nil
}

// unmappedExtension: a rule uses extension_<appId>_<name> and the connector was not told which AD
// attribute feeds it, so no AD write can be proved harmless (rule 7g, safe direction).
func unmappedExtension(sc RuleScope, ext map[string]string) bool {
	mapped := map[string]bool{}
	for _, p := range ext {
		mapped[strings.ToLower(p)] = true
	}
	for p := range sc.Properties {
		if rest, ok := strings.CutPrefix(p, "user."); ok && isDirectoryExtension(rest) && !mapped[p] {
			return true
		}
	}
	return false
}
