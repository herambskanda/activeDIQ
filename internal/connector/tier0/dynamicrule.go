package tier0

import (
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
	TokString                        // "…" with backslash escapes
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
				if rs[j] == '\\' {
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

// RuleScope is what a designated dynamic group's rule says about property writes.
type RuleScope struct {
	// Properties are the lower-case "user.x" / "device.x" references of the rule.
	Properties map[string]bool
	// RefuseAll: the rule could not be fully tokenised, or refers to group membership, so any
	// property of any user or device could change who is in the group.
	RefuseAll bool
}

// ScopeOfRule extracts the properties a rule depends on. Nothing is evaluated.
func ScopeOfRule(rule string) RuleScope {
	sc := RuleScope{Properties: map[string]bool{}}
	toks, err := Lex(rule)
	if err != nil || len(toks) == 0 {
		// An empty rule on a dynamic group is also unreadable: refuse.
		sc.RefuseAll = true
		return sc
	}
	for _, t := range toks {
		switch t.Kind {
		case TokProperty:
			sc.Properties[strings.ToLower(t.Text)] = true
			if strings.Contains(strings.ToLower(t.Text), "memberof") {
				sc.RefuseAll = true
			}
		case TokOperator, TokIdent:
			// "-memberOf" operator, or a bare memberOf word: membership of other groups drives this one.
			if strings.Contains(strings.ToLower(t.Text), "memberof") {
				sc.RefuseAll = true
			}
		}
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
}

// WriteKind is the kind of directory object a property write targets.
type WriteKind int

const (
	WriteUser WriteKind = iota + 1
	WriteDevice
)

// DynamicRuleRefusal is the verdict of CheckPropertyWrite.
type DynamicRuleRefusal struct {
	Refused bool
	Reason  string // ReasonDesignatedDynamicRule when Refused
}

// CheckPropertyWrite is the write path's check (TM-D25 rule 7): a write that sets any of props
// (Graph property names, such as "department" or "extensionAttribute1") on a user or device is
// refused when a designated dynamic group's rule refers to one of them, and every user and device
// property write is refused when a rule is untokenisable or refers to group membership. An unknown
// kind is refused. A snapshot with no designated dynamic group refuses nothing here.
func (s *Set) CheckPropertyWrite(kind WriteKind, props []string) DynamicRuleRefusal {
	refuse := DynamicRuleRefusal{Refused: true, Reason: ReasonDesignatedDynamicRule}
	if kind != WriteUser && kind != WriteDevice {
		return refuse
	}
	if s == nil {
		return refuse
	}
	if s.dynamic.RefuseAll && len(props) > 0 {
		return refuse
	}
	prefix := "user."
	if kind == WriteDevice {
		prefix = "device."
	}
	for _, p := range props {
		if s.dynamic.Properties[prefix+strings.ToLower(p)] {
			return refuse
		}
	}
	return DynamicRuleRefusal{}
}
