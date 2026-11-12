package objects

import (
	"errors"
	"strings"
	"testing"
)

func alt(op Op, attr string, toks ...Token) Alternative {
	return Alternative{When: Condition{Op: op, Attr: attr}, Tokens: toks}
}

func attr(a string, take int, c Case) Token {
	return Token{Kind: TokenAttr, Attr: a, Take: take, Case: c}
}

// first initial + surname when there is a first name, surname alone when there is not.
var sam = NamingFormat{
	Name: "initial.surname", Purpose: PurposeSAMAccountName, CollisionSuffix: CollisionNumeric,
	Alternatives: []Alternative{
		alt(OpNotEmpty, "givenName", attr("givenName", 1, CaseLower), attr("sn", 0, CaseLower)),
		alt(OpAlways, "", attr("sn", 0, CaseLower)),
	},
}

func TestRenderTable(t *testing.T) {
	long := strings.Repeat("x", 30)
	cases := []struct {
		name  string
		f     NamingFormat
		in    Input
		lim   Limits
		want  string
		field string // non-empty: the violation must name this field
	}{
		{"first alternative", sam, Input{"givenName": "Jane", "sn": "Smith"}, Limits{}, "jsmith", ""},
		{"fallback on empty first name", sam, Input{"givenName": "  ", "sn": "Smith"}, Limits{}, "smith", ""},
		{"fallback when attribute absent, keys case-insensitive", sam, Input{"SN": "Smith"}, Limits{}, "smith", ""},
		{"too long for sAMAccountName", sam, Input{"sn": long}, Limits{}, "", "sAMAccountName"},
		{"long fits a larger class limit", sam, Input{"sn": long}, Limits{SAMMax: 64}, long, ""},
		{"fallback still blocked when its attribute is empty", sam, Input{}, Limits{}, "", "sn"},
		{"illegal character", sam, Input{"givenName": "J", "sn": "O[Brien"}, Limits{}, "", "sAMAccountName"},
		{"trailing period", sam, Input{"givenName": "J", "sn": "Smith."}, Limits{}, "", "sAMAccountName"},
		{"title case and last take", NamingFormat{Name: "n", Purpose: PurposeDisplayName, Alternatives: []Alternative{
			alt(OpAlways, "", attr("sn", 0, CaseTitle), Token{Kind: TokenLiteral, Literal: ", "}, attr("givenName", 0, CaseTitle))}},
			Input{"sn": "sMITH", "givenName": "jane"}, Limits{}, "Smith, Jane", ""},
		{"digits token", NamingFormat{Name: "n", Purpose: PurposeUPNPrefix, Alternatives: []Alternative{
			alt(OpAlways, "", Token{Kind: TokenLiteral, Literal: "e"}, Token{Kind: TokenDigits, Attr: "employeeID", Take: 4, Last: true})}},
			Input{"employeeID": "EMP-00123"}, Limits{}, "e0123", ""},
		{"UPN prefix may not carry a space", NamingFormat{Name: "n", Purpose: PurposeUPNPrefix, Alternatives: []Alternative{
			alt(OpAlways, "", attr("cn", 0, CaseKeep))}}, Input{"cn": "Jane Smith"}, Limits{}, "", "upnPrefix"},
		{"CN may carry a space (escaping is the DN primitive's)", NamingFormat{Name: "n", Purpose: PurposeCN, Alternatives: []Alternative{
			alt(OpAlways, "", attr("cn", 0, CaseKeep))}}, Input{"cn": "Smith, Jane"}, Limits{}, "Smith, Jane", ""},
		{"CN over 64", NamingFormat{Name: "n", Purpose: PurposeCN, Alternatives: []Alternative{
			alt(OpAlways, "", attr("cn", 0, CaseKeep))}}, Input{"cn": strings.Repeat("a", 65)}, Limits{}, "", "cn"},
		{"mail alias", NamingFormat{Name: "n", Purpose: PurposeMailAlias, Alternatives: []Alternative{
			alt(OpAlways, "", attr("givenName", 0, CaseLower), Token{Kind: TokenLiteral, Literal: "."}, attr("sn", 0, CaseLower))}},
			Input{"givenName": "Jane", "sn": "Smith"}, Limits{}, "jane.smith", ""},
		{"mail alias refuses non-ASCII", NamingFormat{Name: "n", Purpose: PurposeMailAlias, Alternatives: []Alternative{
			alt(OpAlways, "", attr("sn", 0, CaseLower))}}, Input{"sn": "Müller"}, Limits{}, "", "mailAlias"},
		{"equals condition", NamingFormat{Name: "n", Purpose: PurposeCN, Alternatives: []Alternative{
			{When: Condition{Op: OpEquals, Attr: "department", Value: "IT"}, Tokens: []Token{{Kind: TokenLiteral, Literal: "it-"}, attr("sn", 0, CaseKeep)}},
			alt(OpAlways, "", attr("sn", 0, CaseKeep))}}, Input{"department": "it", "sn": "Lee"}, Limits{}, "it-Lee", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.f.Validate(); err != nil {
				t.Fatalf("format invalid: %v", err)
			}
			got, err := c.f.Render(c.in, c.lim)
			if c.field != "" {
				var ve *ViolationError
				if !errors.As(err, &ve) || ve.Field != c.field {
					t.Fatalf("want a violation naming %q, got %q, %v", c.field, got, err)
				}
				if got != "" {
					t.Fatalf("blocked render returned a name %q", got)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

func TestCandidate(t *testing.T) {
	for _, c := range []struct {
		base    string
		attempt int
		want    string
	}{{"jsmith", 0, "jsmith"}, {"jsmith", 1, "jsmith2"}, {"jsmith", 9, "jsmith10"},
		{"abcdefghijklmnopqrst", 1, "abcdefghijklmnopqrs2"}, // 20 chars: the base gives way to the suffix
	} {
		got, err := sam.Candidate(c.base, c.attempt, Limits{})
		if err != nil || got != c.want {
			t.Errorf("Candidate(%q,%d) = %q, %v; want %q", c.base, c.attempt, got, err, c.want)
		}
	}
	none := sam
	none.CollisionSuffix = CollisionNone
	if _, err := none.Candidate("jsmith", 1, Limits{}); err == nil {
		t.Error("a format without a collision style produced a suffixed name")
	}
}

func TestNamingValidate(t *testing.T) {
	bad := map[string]NamingFormat{
		"no name":             {Purpose: PurposeCN, Alternatives: sam.Alternatives[1:]},
		"bad purpose":         {Name: "n", Purpose: "samaccount", Alternatives: sam.Alternatives[1:]},
		"no alts":             {Name: "n", Purpose: PurposeCN},
		"last is conditional": {Name: "n", Purpose: PurposeCN, Alternatives: sam.Alternatives[:1]},
		"unknown kind":        {Name: "n", Purpose: PurposeCN, Alternatives: []Alternative{alt(OpAlways, "", Token{Kind: "script", Literal: "x"})}},
		"bad attr":            {Name: "n", Purpose: PurposeCN, Alternatives: []Alternative{alt(OpAlways, "", attr("sn)(uid=*", 0, CaseKeep))}},
		"no tokens":           {Name: "n", Purpose: PurposeCN, Alternatives: []Alternative{alt(OpAlways, "")}},
		"bad op":              {Name: "n", Purpose: PurposeCN, Alternatives: []Alternative{{When: Condition{Op: "regex", Attr: "sn"}, Tokens: []Token{{Kind: TokenLiteral, Literal: "x"}}}, alt(OpAlways, "", attr("sn", 0, CaseKeep))}},
	}
	for n, f := range bad {
		if err := f.Validate(); err == nil {
			t.Errorf("%s: accepted", n)
		}
	}
}
